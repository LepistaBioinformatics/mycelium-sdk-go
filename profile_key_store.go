package mycelium

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// profileKeyStore caches the gateway public keys of a downstream verifier.
//
//   - Fetched lazily on the first request (default), or before serving
//     when the service opts in with Prefetch. Until a set is downloaded,
//     requests fail closed and a failed attempt is retried after
//     ProfileJWKSEmptyRetry (at most the cooldown).
//   - Refreshed when max-age expires; a failed refresh keeps the last valid
//     set and is logged, so a short gateway outage never drops trusted keys.
//     The set stops being trusted ProfileJWKSMaxStale after it expired, so a
//     retired key cannot verify forever while refreshes fail.
//   - A request never waits for a refresh another request already started
//     while keys are cached: it verifies with the cached set.
//   - Refetched when a signature names an unknown kid, at most once per
//     cooldown (measured from the last attempt, prefetch included), and
//     single-flight: concurrent requests share one fetch, and waiters that
//     find a newer generation retry without fetching again.
//
// Safe for concurrent use.
type profileKeyStore struct {
	url      string
	fetch    ProfileJWKSFetcher
	cooldown time.Duration
	now      func() time.Time

	mu          sync.RWMutex
	keys        *TrustedProfileKeys
	generation  uint64
	freshUntil  time.Time
	fetched     bool
	lastAttempt time.Time
	attempted   bool

	refreshMu sync.Mutex
}

func newProfileKeyStore(url string, fetch ProfileJWKSFetcher, cooldown time.Duration) *profileKeyStore {
	return &profileKeyStore{
		url:      url,
		fetch:    fetch,
		cooldown: cooldown,
		now:      time.Now,
		keys:     emptyTrustedProfileKeys(),
	}
}

// current returns the trusted keys now and the generation they belong to.
// The keys are an empty set once they outlived the maximum staleness.
func (s *profileKeyStore) current() (*TrustedProfileKeys, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.fetched && !s.now().Before(s.freshUntil.Add(ProfileJWKSMaxStale)) {
		return emptyTrustedProfileKeys(), s.generation
	}
	return s.keys, s.generation
}

// prefetch fetches the set now; any failure is returned.
func (s *profileKeyStore) prefetch(ctx context.Context) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	return s.fetchAndStore(ctx)
}

// refreshIfStale refreshes when the cached set expired or was never fetched.
// While a set is cached it never waits for a refresh already in flight.
func (s *profileKeyStore) refreshIfStale(ctx context.Context) {
	s.mu.RLock()
	generation := s.generation
	stale := !s.fetched || !s.now().Before(s.freshUntil)
	s.mu.RUnlock()

	if !stale {
		return
	}
	if generation == 0 {
		s.refreshFrom(ctx, generation)
		return
	}
	if !s.refreshMu.TryLock() {
		return
	}
	defer s.refreshMu.Unlock()
	s.refreshHolding(ctx, generation)
}

// refreshAfterUnknownKey refetches after an unknown kid; it reports whether
// newer keys are available than the generation the caller verified with.
func (s *profileKeyStore) refreshAfterUnknownKey(ctx context.Context, seenGeneration uint64) bool {
	return s.refreshFrom(ctx, seenGeneration)
}

func (s *profileKeyStore) refreshFrom(ctx context.Context, seenGeneration uint64) bool {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	return s.refreshHolding(ctx, seenGeneration)
}

// refreshHolding runs the single-flight refresh; refreshMu must be held.
func (s *profileKeyStore) refreshHolding(ctx context.Context, seenGeneration uint64) bool {
	s.mu.RLock()
	generation, attempted, lastAttempt := s.generation, s.attempted, s.lastAttempt
	s.mu.RUnlock()

	if generation != seenGeneration {
		return true
	}
	if attempted && s.now().Sub(lastAttempt) < s.retryInterval(generation) {
		return false
	}

	if err := s.fetchAndStore(ctx); err != nil {
		slog.Warn("keeping the last valid profile JWKS",
			"event", "profile_signature.jwks", "outcome", "refresh_failed", "reason", err.Error())
		return false
	}
	return true
}

// retryInterval is the cooldown, shortened while no key set was ever stored,
// so a service started before the gateway recovers within seconds.
func (s *profileKeyStore) retryInterval(generation uint64) time.Duration {
	if generation > 0 {
		return s.cooldown
	}
	return min(s.cooldown, ProfileJWKSEmptyRetry)
}

// fetchAndStore runs one fetch, detached from the caller's cancellation so
// an abandoned request does not burn the cooldown with a cancelled fetch.
// The cooldown counts from the end of the fetch, so a fetch that hangs until
// its timeout does not let every queued request run its own.
func (s *profileKeyStore) fetchAndStore(ctx context.Context) error {
	fetched, err := s.fetch(context.WithoutCancel(ctx), s.url)

	s.mu.Lock()
	s.attempted, s.lastAttempt = true, s.now()
	s.mu.Unlock()

	if err != nil {
		return err
	}
	if fetched.Keys == nil {
		return errors.New("profile_jwks_fetch_failed: no key set")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = fetched.Keys
	s.generation++
	s.freshUntil = s.now().Add(fetched.MaxAge)
	s.fetched = true
	return nil
}

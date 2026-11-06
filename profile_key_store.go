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
//     set and is logged, so a gateway outage never drops trusted keys.
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
		keys:     emptyTrustedProfileKeys(),
	}
}

// current returns the trusted keys now and the generation they belong to.
func (s *profileKeyStore) current() (*TrustedProfileKeys, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keys, s.generation
}

// prefetch fetches the set now; any failure is returned.
func (s *profileKeyStore) prefetch(ctx context.Context) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	return s.fetchAndStore(ctx)
}

// refreshIfStale refreshes when the cached set expired or was never fetched.
func (s *profileKeyStore) refreshIfStale(ctx context.Context) {
	s.mu.RLock()
	generation := s.generation
	stale := !s.fetched || !time.Now().Before(s.freshUntil)
	s.mu.RUnlock()

	if stale {
		s.refreshFrom(ctx, generation)
	}
}

// refreshAfterUnknownKey refetches after an unknown kid; it reports whether
// newer keys are available than the generation the caller verified with.
func (s *profileKeyStore) refreshAfterUnknownKey(ctx context.Context, seenGeneration uint64) bool {
	return s.refreshFrom(ctx, seenGeneration)
}

func (s *profileKeyStore) refreshFrom(ctx context.Context, seenGeneration uint64) bool {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	s.mu.RLock()
	generation, attempted, lastAttempt := s.generation, s.attempted, s.lastAttempt
	s.mu.RUnlock()

	if generation != seenGeneration {
		return true
	}
	if attempted && time.Since(lastAttempt) < s.retryInterval(generation) {
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
func (s *profileKeyStore) fetchAndStore(ctx context.Context) error {
	s.mu.Lock()
	s.attempted, s.lastAttempt = true, time.Now()
	s.mu.Unlock()

	fetched, err := s.fetch(context.WithoutCancel(ctx), s.url)
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
	s.freshUntil = time.Now().Add(fetched.MaxAge)
	s.fetched = true
	return nil
}

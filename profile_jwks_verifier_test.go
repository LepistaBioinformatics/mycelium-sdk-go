package mycelium

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Behavior of the JWKS-backed verifier: key rotation without touching the
// downstream, refetch limits, keeping the last valid set, and the real HTTP
// fetch (bounded, no redirects). Mirrors the gateway's Rust
// tests/profile_jwks_verifier.rs.

func verifyWith(t *testing.T, verifier *ProfileSignatureVerifier, version uint32) error {
	t.Helper()
	profileHeader, signature := signedPair(t, version)
	_, err := verifier.VerifyAndDecodeProfile(context.Background(), profileHeader, signature)
	return err
}

func isRejection(err error, reason string) bool {
	var rejection *ProfileSignatureError
	return errors.As(err, &rejection) && rejection.Reason == reason
}

func TestJWKSRotationIsPickedUpWithoutTouchingTheDownstream(t *testing.T) {
	gateway := newFakeGateway(t, 10*time.Minute, 1)
	verifier := gateway.verifier(t, 0)
	if err := verifier.Prefetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := verifyWith(t, verifier, 1); err != nil {
		t.Fatalf("key 1: %v", err)
	}

	gateway.publish(1, 2)

	if err := verifyWith(t, verifier, 2); err != nil {
		t.Fatalf("key 2 after rotation: %v", err)
	}
	if got := gateway.fetches.Load(); got != 2 {
		t.Errorf("fetches = %d, want 2", got)
	}
}

func TestJWKSUnknownKidRefetchesAtMostOncePerCooldown(t *testing.T) {
	gateway := newFakeGateway(t, 10*time.Minute, 1)
	verifier := gateway.verifier(t, 30*time.Second)
	if err := verifier.Prefetch(context.Background()); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		if err := verifyWith(t, verifier, 2); !isRejection(err, ReasonUnknownKey) {
			t.Fatalf("err = %v, want unknown_key", err)
		}
	}
	if got := gateway.fetches.Load(); got != 1 {
		t.Errorf("fetches = %d, want 1 (cooldown since the prefetch)", got)
	}
}

func TestJWKSConcurrentUnknownKidsShareOneFetch(t *testing.T) {
	gateway := newFakeGateway(t, 10*time.Minute, 1)
	verifier := gateway.verifier(t, 0)
	if err := verifier.Prefetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	gateway.publish(1, 2)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- verifyWith(t, verifier, 2)
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("verify: %v", err)
		}
	}
	if got := gateway.fetches.Load(); got != 2 {
		t.Errorf("fetches = %d, want 2", got)
	}
}

func TestJWKSFailedRefreshKeepsTheLastValidSet(t *testing.T) {
	gateway := newFakeGateway(t, 0, 1)
	verifier := gateway.verifier(t, 0)
	if err := verifier.Prefetch(context.Background()); err != nil {
		t.Fatal(err)
	}

	gateway.goDown()

	if err := verifyWith(t, verifier, 1); err != nil {
		t.Fatalf("verify with the kept set: %v", err)
	}
	if got := gateway.fetches.Load(); got < 2 {
		t.Errorf("fetches = %d, want the stale set refreshed", got)
	}
}

func TestJWKSPrefetchFailsWhenTheGatewayIsUnreachable(t *testing.T) {
	gateway := newFakeGateway(t, 10*time.Minute, 1)
	gateway.goDown()

	if err := gateway.verifier(t, 0).Prefetch(context.Background()); err == nil {
		t.Fatal("prefetch must fail")
	}
}

func TestJWKSLazyVerifierFetchesOnFirstUse(t *testing.T) {
	gateway := newFakeGateway(t, 10*time.Minute, 1)
	verifier := gateway.verifier(t, 30*time.Second)

	if err := verifyWith(t, verifier, 1); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := gateway.fetches.Load(); got != 1 {
		t.Errorf("fetches = %d, want 1", got)
	}
}

// A service started before the gateway: requests fail closed, then the keys
// are picked up after the short first-download retry, not the cooldown.
func TestJWKSServiceStartedBeforeTheGatewayRecoversWithinSeconds(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the first-download retry interval")
	}
	gateway := newFakeGateway(t, 10*time.Minute, 1)
	gateway.goDown()
	verifier := gateway.verifier(t, 30*time.Second)
	if err := verifyWith(t, verifier, 1); err == nil {
		t.Fatal("must fail closed while the gateway is down")
	}

	gateway.publish(1)
	if err := verifyWith(t, verifier, 1); err == nil {
		t.Fatal("the retry must be bounded")
	}
	if got := gateway.fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}

	time.Sleep(ProfileJWKSEmptyRetry + 100*time.Millisecond)
	if err := verifyWith(t, verifier, 1); err != nil {
		t.Fatalf("verify after the retry interval: %v", err)
	}
	if got := gateway.fetches.Load(); got != 2 {
		t.Errorf("fetches = %d, want 2", got)
	}
}

func TestJWKSNonCanonicalKidNeverTriggersAFetch(t *testing.T) {
	gateway := newFakeGateway(t, 10*time.Minute, 1)
	verifier := gateway.verifier(t, 0)
	if err := verifier.Prefetch(context.Background()); err != nil {
		t.Fatal(err)
	}

	// {"alg":"EdDSA","kid":"01"}
	signature := "eyJhbGciOiJFZERTQSIsImtpZCI6IjAxIn0.e30.c2ln"
	err := verifier.VerifyProfileSignature(context.Background(), "profile", signature)

	if !isRejection(err, ReasonUnknownKey) {
		t.Fatalf("err = %v, want unknown_key", err)
	}
	if got := gateway.fetches.Load(); got != 1 {
		t.Errorf("fetches = %d, want 1", got)
	}
}

// ? ---------------------------------------------------------------------------
// ? Real HTTP fetch
// ? ---------------------------------------------------------------------------

func serveJWKS(t *testing.T) *httptest.Server {
	t.Helper()
	document := testJWKS(t, 1, 2)
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(document)
	})
	mux.HandleFunc("/huge.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat(" ", 70*1024)))
	})
	mux.HandleFunc("/redirect.json", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/jwks.json", http.StatusFound)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestFetchProfileJWKSReadsTheSetAndItsCacheLifetime(t *testing.T) {
	server := serveJWKS(t)

	fetched, err := FetchProfileJWKS(context.Background(), server.URL+"/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	if fetched.Keys.Len() != 2 || fetched.MaxAge != 10*time.Minute {
		t.Errorf("keys = %d, max-age = %v", fetched.Keys.Len(), fetched.MaxAge)
	}
}

func TestFetchProfileJWKSRefusesErrorsOversizedBodiesAndRedirects(t *testing.T) {
	server := serveJWKS(t)

	for _, path := range []string{"/missing.json", "/huge.json", "/redirect.json"} {
		if _, err := FetchProfileJWKS(context.Background(), server.URL+path); err == nil {
			t.Errorf("%s: want an error", path)
		}
	}
}

func TestConfiguredVerifierDownloadsOverHTTPOnFirstUseOrPrefetch(t *testing.T) {
	ResetProfileSignatureConfiguration()
	t.Cleanup(ResetProfileSignatureConfiguration)
	server := serveJWKS(t)
	t.Setenv(ProfileJWKSURLEnv, server.URL+"/jwks.json")
	t.Setenv(ProfileJWKSAllowInsecureHTTPEnv, "true")
	t.Setenv(ProfileSignatureAudienceEnv, testAudience)

	verifier, err := ConfigureProfileSignature(context.Background())
	if err != nil || verifier == nil {
		t.Fatalf("configure: %v", err)
	}
	if verifier.TrustsKey("1") {
		t.Error("configure must not download the keys")
	}
	if err := verifyWith(t, verifier, 2); err != nil {
		t.Errorf("verify (first use): %v", err)
	}

	ResetProfileSignatureConfiguration()
	prefetched, err := ConfigureProfileSignature(context.Background())
	if err != nil || prefetched == nil {
		t.Fatalf("configure: %v", err)
	}
	if err := prefetched.Prefetch(context.Background()); err != nil {
		t.Fatalf("prefetch: %v", err)
	}
	if !prefetched.TrustsKey("1") || !prefetched.TrustsKey("2") {
		t.Error("prefetch did not download the keys")
	}
}

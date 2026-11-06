package mycelium

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

func signedHeader(profileHeader, signature string) http.Header {
	header := http.Header{}
	header.Set(DefaultProfileKey, profileHeader)
	header.Set(DefaultProfileSignatureKey, signature)
	return header
}

func enforcementVerifier(t *testing.T) *ProfileSignatureVerifier {
	t.Helper()
	return newFakeGateway(t, 10*time.Minute, 1).verifier(t, 0)
}

func TestEnforcementAcceptsTheGatewaySignature(t *testing.T) {
	outcome := EnforceProfileSignature(context.Background(), signedHeader(signedPair(t, 1)), enforcementVerifier(t))

	if !outcome.Enabled || outcome.Profile == nil || outcome.Reason != "" {
		t.Fatalf("outcome = %+v, want accepted", outcome)
	}
}

func TestEnforcementRefusesWithGenericDetails(t *testing.T) {
	profileHeader, signature := signedPair(t, 1)

	cases := map[string]http.Header{}

	unsigned := http.Header{}
	unsigned.Set(DefaultProfileKey, profileHeader)
	cases[ReasonMissingSignature] = unsigned

	signatureOnly := http.Header{}
	signatureOnly.Set(DefaultProfileSignatureKey, signature)
	cases[ReasonMissingProfile] = signatureOnly

	duplicated := signedHeader(profileHeader, signature)
	duplicated.Add(DefaultProfileKey, profileHeader)
	cases[ReasonDuplicateHeader] = duplicated

	folded := signedHeader(profileHeader, signature)
	folded.Set(DefaultProfileSignatureKey, signature+", "+signature)
	cases[ReasonDuplicateHeader+"_folded"] = folded

	tampered := signedHeader(profileHeader+"A", signature)
	cases[ReasonProfileHashMismatch] = tampered

	for name, header := range cases {
		outcome := EnforceProfileSignature(context.Background(), header, enforcementVerifier(t))
		if outcome.Status != http.StatusForbidden || outcome.Detail != SignatureRejectionDetail || outcome.Profile != nil {
			t.Errorf("%s: outcome = %+v", name, outcome)
		}
	}
}

func TestEnforcementRefusesAnotherAudience(t *testing.T) {
	gateway := newFakeGateway(t, 10*time.Minute, 1)
	verifier, err := LoadProfileSignatureVerifierFromEnv(map[string]string{
		ProfileJWKSURLEnv:           "https://gateway.test/jwks.json",
		ProfileSignatureAudienceEnv: "another-service",
	}, WithJWKSFetcher(gateway.fetcher()))
	if err != nil {
		t.Fatal(err)
	}

	outcome := EnforceProfileSignature(context.Background(), signedHeader(signedPair(t, 1)), verifier)
	if outcome.Status != http.StatusForbidden || outcome.Reason != ReasonAudienceMismatch {
		t.Fatalf("outcome = %+v, want audience_mismatch", outcome)
	}
}

func TestEnforcementDisabledWithoutConfiguration(t *testing.T) {
	ResetProfileSignatureConfiguration()
	t.Cleanup(ResetProfileSignatureConfiguration)

	if outcome := EnforceProfileSignature(context.Background(), http.Header{}, nil); outcome.Enabled {
		t.Fatalf("outcome = %+v, want disabled", outcome)
	}
}

func TestEnforcementWarnsOnceWhenASignatureIsIgnored(t *testing.T) {
	ResetProfileSignatureConfiguration()
	t.Cleanup(ResetProfileSignatureConfiguration)
	unverifiedSignatureWarned.Store(false)

	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	header := signedHeader(signedPair(t, 1))
	for range 3 {
		if outcome := EnforceProfileSignature(context.Background(), header, nil); outcome.Enabled {
			t.Fatalf("outcome = %+v, want disabled", outcome)
		}
	}

	if got := strings.Count(logs.String(), ProfileJWKSURLEnv+" is not set"); got != 1 {
		t.Errorf("warnings = %d, want 1:\n%s", got, logs.String())
	}
}

func TestEnforcementInvalidConfigurationFailsClosed(t *testing.T) {
	ResetProfileSignatureConfiguration()
	t.Cleanup(ResetProfileSignatureConfiguration)
	t.Setenv(ProfileJWKSURLEnv, testHTTPSURL)

	outcome := EnforceProfileSignature(context.Background(), http.Header{}, nil)
	if outcome.Status != http.StatusInternalServerError || outcome.Reason != ReasonConfigurationInvalid {
		t.Fatalf("outcome = %+v, want 500", outcome)
	}
}

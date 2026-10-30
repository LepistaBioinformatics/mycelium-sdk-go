package mycelium

import (
	"errors"
	"testing"
)

// TEST ONLY: RFC 8032 section 7.1 test vector 1 (public material).
const (
	testPublicPEM  = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n"
	testPrivatePEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n"
)

func TestConfigDisabledWithoutPublicKeys(t *testing.T) {
	verifier, err := LoadProfileSignatureVerifierFromEnv(map[string]string{"PATH": "x"})
	if err != nil || verifier != nil {
		t.Fatalf("got (%v, %v), want disabled", verifier, err)
	}
}

func TestConfigReadsKeysToleranceAndAudience(t *testing.T) {
	verifier, err := LoadProfileSignatureVerifierFromEnv(map[string]string{
		"MYC_PROFILE_PUBLIC_KEY_1":                testPublicPEM,
		"MYC_PROFILE_SIGNATURE_TOLERANCE_SECONDS": " 30 ",
		"MYC_PROFILE_SIGNATURE_AUDIENCE":          "billing-api",
	})
	if err != nil || verifier == nil {
		t.Fatalf("load: %v", err)
	}
	if verifier.ToleranceSeconds() != 30 {
		t.Errorf("tolerance = %d, want 30", verifier.ToleranceSeconds())
	}
	if audience, ok := verifier.ExpectedAudience(); !ok || audience != "billing-api" {
		t.Errorf("audience = %q (%v)", audience, ok)
	}
	if !verifier.TrustsKey("1") || verifier.TrustsKey("2") {
		t.Error("unexpected trusted key set")
	}
}

func TestConfigInvalidEntriesAreErrors(t *testing.T) {
	invalid := []map[string]string{
		{"MYC_PROFILE_PUBLIC_KEY_0": testPublicPEM},
		{"MYC_PROFILE_PUBLIC_KEY_01": testPublicPEM},
		{"MYC_PROFILE_PUBLIC_KEY_v1": testPublicPEM},
		{"MYC_PROFILE_PUBLIC_KEY_4294967296": testPublicPEM},
		{"MYC_PROFILE_PUBLIC_KEY_1": testPrivatePEM},
		{"MYC_PROFILE_PUBLIC_KEY_1": ""},
		{"MYC_PROFILE_PUBLIC_KEY_1": "-----BEGIN PUBLIC KEY-----\nAA=="},
		{"MYC_PROFILE_SIGNATURE_TOLERANCE_SECONDS": "0"},
		{"MYC_PROFILE_SIGNATURE_TOLERANCE_SECONDS": "060"},
		{"MYC_PROFILE_SIGNATURE_TOLERANCE_SECONDS": "9007199254740992"},
		{"MYC_PROFILE_SIGNATURE_AUDIENCE": "   "},
	}

	for _, environ := range invalid {
		_, err := LoadProfileSignatureVerifierFromEnv(environ)
		var configErr *ProfileSignatureConfigurationError
		if !errors.As(err, &configErr) || configErr.Code != ProfileSignatureConfigInvalidCode {
			t.Errorf("%v: err = %v, want configuration error", environ, err)
		}
	}
}

func TestConfigProcessVerifierIsCachedUntilReset(t *testing.T) {
	ResetProfileSignatureConfiguration()
	t.Cleanup(ResetProfileSignatureConfiguration)

	t.Setenv("MYC_PROFILE_PUBLIC_KEY_1", testPublicPEM)
	first, err := GetProfileSignatureVerifier()
	if err != nil || first == nil {
		t.Fatalf("load: %v", err)
	}

	t.Setenv("MYC_PROFILE_PUBLIC_KEY_1", "not a key")
	if cached, err := GetProfileSignatureVerifier(); err != nil || cached != first {
		t.Fatalf("cache not reused: %v", err)
	}

	if _, err := ConfigureProfileSignature(); err == nil {
		t.Fatal("ConfigureProfileSignature must reload and report the error")
	}
	if _, err := GetProfileSignatureVerifier(); err == nil {
		t.Fatal("configuration error must stay cached (fail closed)")
	}
}

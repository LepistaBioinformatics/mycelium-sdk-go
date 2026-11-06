package mycelium

import (
	"context"
	"testing"
)

const (
	testHTTPSURL = "https://gateway.test/.well-known/mycelium-profile-jwks.json"
	testHTTPURL  = "http://localhost:8080/.well-known/mycelium-profile-jwks.json"
)

func loadSettings(environ map[string]string) (*ProfileSignatureVerifier, error) {
	return LoadProfileSignatureVerifierFromEnv(environ, WithJWKSFetcher(newFakeGateway(nil, 0).fetcher()))
}

func TestConfigEnabledByTheJWKSURLOnly(t *testing.T) {
	for _, environ := range []map[string]string{
		{"PATH": "x"},
		{ProfileSignatureAudienceEnv: testAudience},
	} {
		if verifier, err := loadSettings(environ); err != nil || verifier != nil {
			t.Errorf("%v: got (%v, %v), want disabled", environ, verifier, err)
		}
	}

	verifier, err := loadSettings(map[string]string{
		ProfileJWKSURLEnv:            "  " + testHTTPSURL + " ",
		ProfileSignatureAudienceEnv:  "billing-api",
		ProfileSignatureToleranceEnv: " 30 ",
	})
	if err != nil || verifier == nil {
		t.Fatalf("load: %v", err)
	}
	if verifier.ToleranceSeconds() != 30 || verifier.ExpectedAudience() != "billing-api" || verifier.JWKSURL() != testHTTPSURL {
		t.Errorf("unexpected verifier settings")
	}
}

func TestConfigAudienceIsMandatoryWhenEnabled(t *testing.T) {
	_, err := loadSettings(map[string]string{ProfileJWKSURLEnv: testHTTPSURL})
	if !isConfigurationError(err) {
		t.Fatalf("err = %v, want configuration error", err)
	}
}

func TestConfigPlainHTTPNeedsTheDevelopmentSwitch(t *testing.T) {
	cases := map[string]bool{"": false, "false": false, "true": true, " true ": true, "yes": false, "TRUE": false}
	for value, accepted := range cases {
		environ := map[string]string{ProfileJWKSURLEnv: testHTTPURL, ProfileSignatureAudienceEnv: testAudience}
		if value != "" {
			environ[ProfileJWKSAllowInsecureHTTPEnv] = value
		}
		verifier, err := loadSettings(environ)
		if accepted != (err == nil && verifier != nil) {
			t.Errorf("%q: got (%v, %v)", value, verifier, err)
		}
	}
}

func TestConfigRejectsOtherSchemesRelativeURLsAndCredentials(t *testing.T) {
	for _, raw := range []string{
		"",
		"/.well-known/mycelium-profile-jwks.json",
		"ftp://gateway/jwks.json",
		"file:///etc/jwks.json",
		"https://user:pass@gateway/jwks.json",
		"https:gateway/jwks.json",
	} {
		_, err := loadSettings(map[string]string{
			ProfileJWKSURLEnv: raw, ProfileSignatureAudienceEnv: testAudience,
			ProfileJWKSAllowInsecureHTTPEnv: "true",
		})
		if !isConfigurationError(err) {
			t.Errorf("%q: err = %v, want configuration error", raw, err)
		}
	}
}

func TestConfigInvalidSettingsFailEvenWhenDisabled(t *testing.T) {
	for _, environ := range []map[string]string{
		{ProfileSignatureToleranceEnv: "0"},
		{ProfileSignatureToleranceEnv: "060"},
		{ProfileSignatureToleranceEnv: "9007199254740992"},
		{ProfileSignatureAudienceEnv: "   "},
		{ProfileJWKSAllowInsecureHTTPEnv: "maybe"},
	} {
		if _, err := loadSettings(environ); !isConfigurationError(err) {
			t.Errorf("%v: err = %v, want configuration error", environ, err)
		}
	}
}

func TestConfigProcessVerifierIsCachedUntilReset(t *testing.T) {
	ResetProfileSignatureConfiguration()
	t.Cleanup(ResetProfileSignatureConfiguration)

	t.Setenv(ProfileJWKSURLEnv, testHTTPSURL)
	t.Setenv(ProfileSignatureAudienceEnv, testAudience)
	first, err := GetProfileSignatureVerifier()
	if err != nil || first == nil {
		t.Fatalf("load: %v", err)
	}

	t.Setenv(ProfileJWKSURLEnv, "ftp://not-allowed")
	if cached, err := GetProfileSignatureVerifier(); err != nil || cached != first {
		t.Fatalf("cache not reused: %v", err)
	}

	if _, err := ConfigureProfileSignature(context.Background()); !isConfigurationError(err) {
		t.Fatalf("ConfigureProfileSignature must reload and report the error, got %v", err)
	}
	if _, err := GetProfileSignatureVerifier(); err == nil {
		t.Fatal("configuration error must stay cached (fail closed)")
	}
}

// The service never depends on the gateway to start: configuration does not
// download the keys, and only the opt-in Prefetch fails when it cannot.
func TestConfigStartupDoesNotNeedTheGateway(t *testing.T) {
	ResetProfileSignatureConfiguration()
	t.Cleanup(ResetProfileSignatureConfiguration)
	t.Setenv(ProfileJWKSURLEnv, "http://127.0.0.1:1/jwks.json")
	t.Setenv(ProfileJWKSAllowInsecureHTTPEnv, "true")
	t.Setenv(ProfileSignatureAudienceEnv, testAudience)

	verifier, err := ConfigureProfileSignature(context.Background())
	if err != nil || verifier == nil {
		t.Fatalf("startup must not need the gateway: %v", err)
	}
	if err := verifier.Prefetch(context.Background()); err == nil {
		t.Fatal("opt-in prefetch must fail when the JWKS is unreachable")
	}
}

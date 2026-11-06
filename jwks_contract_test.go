package mycelium

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// testdata/profile-signature/jwks-vectors.json is a byte-for-byte copy of the
// gateway contract (mycelium-api-gateway/lib/http_tools/test/mock/
// profile-signature/jwks-vectors.json), produced by the gateway's real JWKS
// publisher. The Python, JavaScript and Rust verifiers run the same corpus.

const (
	jwksVectorsPath        = "testdata/profile-signature/jwks-vectors.json"
	gatewayJWKSVectorsPath = "../mycelium-api-gateway/lib/http_tools/test/mock/profile-signature/jwks-vectors.json"
)

type jwksCorpus struct {
	Contract struct {
		Path                   string `json:"path"`
		URLVariable            string `json:"urlVariable"`
		InsecureHTTPVariable   string `json:"insecureHttpVariable"`
		AudienceVariable       string `json:"audienceVariable"`
		FetchTimeoutSeconds    int64  `json:"fetchTimeoutSeconds"`
		MaxBytes               int64  `json:"maxBytes"`
		RefetchCooldownSeconds int64  `json:"refetchCooldownSeconds"`
		EmptyRetrySeconds      int64  `json:"emptyRetrySeconds"`
		DefaultMaxAgeSeconds   int64  `json:"defaultMaxAgeSeconds"`
		MinMaxAgeSeconds       int64  `json:"minMaxAgeSeconds"`
		MaxMaxAgeSeconds       int64  `json:"maxMaxAgeSeconds"`
	} `json:"contract"`
	Published string `json:"published"`
	Vectors   []struct {
		Name         string   `json:"name"`
		Document     string   `json:"document"`
		Expected     string   `json:"expected"`
		ExpectedKids []string `json:"expectedKids"`
	} `json:"vectors"`
	CacheControl []struct {
		CacheControl    *string `json:"cacheControl"`
		ExpectedSeconds int64   `json:"expectedSeconds"`
	} `json:"cacheControl"`
}

func readJWKSCorpus(t *testing.T) jwksCorpus {
	t.Helper()
	raw, err := os.ReadFile(jwksVectorsPath)
	if err != nil {
		t.Fatalf("read jwks vectors: %v", err)
	}
	var corpus jwksCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("parse jwks vectors: %v", err)
	}
	return corpus
}

func trustedKids(keys *TrustedProfileKeys) []string {
	kids := []string{}
	for _, kid := range []string{"1", "2", "3"} {
		if keys.Has(kid) {
			kids = append(kids, kid)
		}
	}
	return kids
}

func TestJWKSContractEveryDocumentHasTheExpectedOutcome(t *testing.T) {
	corpus := readJWKSCorpus(t)
	if len(corpus.Vectors) == 0 {
		t.Fatal("no jwks vectors")
	}

	for _, vector := range corpus.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			keys, err := ParseTrustedProfileKeys([]byte(vector.Document))
			if vector.Expected == "invalid_jwks" {
				if !isConfigurationError(err) {
					t.Fatalf("err = %v, want configuration error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want valid", err)
			}
			if got := trustedKids(keys); !equalStrings(got, vector.ExpectedKids) {
				t.Errorf("kids = %v, want %v", got, vector.ExpectedKids)
			}
		})
	}
}

func TestJWKSContractPublishedDocumentTrustsKeysOneAndTwo(t *testing.T) {
	keys, err := ParseTrustedProfileKeys([]byte(readJWKSCorpus(t).Published))
	if err != nil {
		t.Fatalf("published: %v", err)
	}
	if got := trustedKids(keys); !equalStrings(got, []string{"1", "2"}) {
		t.Errorf("kids = %v", got)
	}
}

func TestJWKSContractSettingsMatchTheGateway(t *testing.T) {
	contract := readJWKSCorpus(t).Contract
	seconds := func(value int64) time.Duration { return time.Duration(value) * time.Second }
	checks := []struct {
		name      string
		got, want any
	}{
		{"path", ProfileJWKSPath, contract.Path},
		{"urlVariable", ProfileJWKSURLEnv, contract.URLVariable},
		{"insecureHttpVariable", ProfileJWKSAllowInsecureHTTPEnv, contract.InsecureHTTPVariable},
		{"audienceVariable", ProfileSignatureAudienceEnv, contract.AudienceVariable},
		{"fetchTimeoutSeconds", ProfileJWKSFetchTimeout, seconds(contract.FetchTimeoutSeconds)},
		{"maxBytes", int64(ProfileJWKSMaxBytes), contract.MaxBytes},
		{"refetchCooldownSeconds", ProfileJWKSRefetchCooldown, seconds(contract.RefetchCooldownSeconds)},
		{"emptyRetrySeconds", ProfileJWKSEmptyRetry, seconds(contract.EmptyRetrySeconds)},
		{"defaultMaxAgeSeconds", DefaultProfileJWKSMaxAge, seconds(contract.DefaultMaxAgeSeconds)},
		{"minMaxAgeSeconds", MinProfileJWKSMaxAge, seconds(contract.MinMaxAgeSeconds)},
		{"maxMaxAgeSeconds", MaxProfileJWKSMaxAge, seconds(contract.MaxMaxAgeSeconds)},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %v, gateway contract says %v", check.name, check.got, check.want)
		}
	}
}

func TestJWKSContractCacheLifetimes(t *testing.T) {
	for _, vector := range readJWKSCorpus(t).CacheControl {
		value := ""
		if vector.CacheControl != nil {
			value = *vector.CacheControl
		}
		want := time.Duration(vector.ExpectedSeconds) * time.Second
		if got := ReadJWKSCacheMaxAge(value); got != want {
			t.Errorf("%q: max-age = %v, want %v", value, got, want)
		}
	}
}

func TestJWKSContractFixtureCopyMatchesGatewayOutput(t *testing.T) {
	gateway, err := os.ReadFile(gatewayJWKSVectorsPath)
	if err != nil {
		t.Skip("gateway checkout not available")
	}
	local, err := os.ReadFile(jwksVectorsPath)
	if err != nil {
		t.Fatalf("read jwks vectors: %v", err)
	}

	normalize := func(raw []byte) [32]byte {
		return sha256.Sum256(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")))
	}
	if normalize(local) != normalize(gateway) {
		t.Error("testdata jwks vectors differ from the gateway fixture; copy it byte for byte")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

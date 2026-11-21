package myceliumgin

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	mycelium "github.com/LepistaBioinformatics/mycelium-sdk-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func init() { gin.SetMode(gin.TestMode) }

func encodedProfile(t *testing.T) string {
	t.Helper()
	p := mycelium.Profile{AccID: uuid.New(), IsStaff: true}
	enc, err := mycelium.CompressAndEncodeProfileToBase64(&p)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func newEngine(env string, captured **mycelium.Profile) *gin.Engine {
	r := gin.New()
	r.Use(Middleware(WithEnvironment(env)))
	r.GET("/", func(c *gin.Context) {
		if p, ok := FromContext(c); ok {
			*captured = p
		}
		c.Status(http.StatusOK)
	})
	return r
}

func TestGinMiddlewarePopulatesContext(t *testing.T) {
	var captured *mycelium.Profile
	r := newEngine("production", &captured)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(mycelium.DefaultProfileKey, encodedProfile(t))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if captured == nil || !captured.IsStaff {
		t.Errorf("profile not populated: %+v", captured)
	}
}

func TestGinMissingHeaderProduction403(t *testing.T) {
	var captured *mycelium.Profile
	r := newEngine("production", &captured)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestGinBadHeaderProduction401(t *testing.T) {
	var captured *mycelium.Profile
	r := newEngine("production", &captured)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(mycelium.DefaultProfileKey, "!!!bad!!!")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestGinDevelopmentTolerant(t *testing.T) {
	var captured *mycelium.Profile
	r := newEngine("development", &captured)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || captured != nil {
		t.Errorf("dev tolerant failed: code=%d captured=%+v", rec.Code, captured)
	}
}

// ? ---------------------------------------------------------------------------
// ? Signature verification (contract vectors shared with the gateway)
// ? ---------------------------------------------------------------------------

type signatureCorpus struct {
	PublicKeys map[string]string `json:"publicKeys"`
	Vectors    []struct {
		ProfileHeader string `json:"profileHeader"`
	} `json:"vectors"`
}

// TEST ONLY: RFC 8032 section 7.1 test vector 1 (PKCS#8), key 1 of the
// shared fixture.
const testPrivatePEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n"

// signNow signs profileHeader with key 1 at the current time, like the
// gateway does (the tolerance is at most 5 minutes, so the fixed-clock
// signature of the vector cannot be verified at the real time).
func signNow(t *testing.T, profileHeader string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(testPrivatePEM))
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(value any) string {
		raw, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signed := encode(map[string]string{"typ": "JWT", "alg": "EdDSA", "kid": "1"}) + "." + encode(map[string]any{
		"iat": time.Now().Unix(), "ph": mycelium.ProfileHeaderHash(profileHeader), "aud": "billing-api",
	})
	signature := ed25519.Sign(key.(ed25519.PrivateKey), []byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// signedFixture returns the profile of the first (valid) contract vector,
// signed now, and a verifier whose JWKS is the document the gateway
// publishes (keys 1 and 2).
func signedFixture(t *testing.T) (string, string, *mycelium.ProfileSignatureVerifier) {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/profile-signature/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus signatureCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	verifier, err := mycelium.LoadProfileSignatureVerifierFromEnv(map[string]string{
		mycelium.ProfileJWKSURLEnv:           "https://gateway.test",
		mycelium.ProfileSignatureAudienceEnv: "billing-api",
	}, mycelium.WithJWKSFetcher(publishedJWKS(t)))
	if err != nil {
		t.Fatal(err)
	}
	profileHeader := corpus.Vectors[0].ProfileHeader
	return profileHeader, signNow(t, profileHeader), verifier
}

// publishedJWKS serves the gateway-published JWKS of the shared fixture.
func publishedJWKS(t *testing.T) mycelium.ProfileJWKSFetcher {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/profile-signature/jwks-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Published string `json:"published"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return func(context.Context, string) (mycelium.FetchedProfileJWKS, error) {
		keys, err := mycelium.ParseTrustedProfileKeys([]byte(fixture.Published))
		return mycelium.FetchedProfileJWKS{Keys: keys, MaxAge: time.Hour}, err
	}
}

func serveSigned(opts []Option, header http.Header) (*httptest.ResponseRecorder, *mycelium.Profile) {
	var captured *mycelium.Profile
	r := gin.New()
	r.Use(Middleware(opts...))
	r.GET("/", func(c *gin.Context) {
		captured, _ = FromContext(c)
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header = header
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec, captured
}

func TestSignedProfileIsAccepted(t *testing.T) {
	profile, signature, verifier := signedFixture(t)
	header := http.Header{}
	header.Set(mycelium.DefaultProfileKey, profile)
	header.Set(mycelium.DefaultProfileSignatureKey, signature)

	rec, captured := serveSigned([]Option{WithProfileSignatureVerifier(verifier)}, header)

	if rec.Code != http.StatusOK || captured == nil || !captured.IsStaff {
		t.Fatalf("status = %d, profile = %+v", rec.Code, captured)
	}
}

func TestUnsignedProfileIsRefusedEvenInDevelopment(t *testing.T) {
	profile, _, verifier := signedFixture(t)
	header := http.Header{}
	header.Set(mycelium.DefaultProfileKey, profile)
	var reasons []string

	rec, captured := serveSigned([]Option{
		WithEnvironment("development"),
		WithProfileSignatureVerifier(verifier),
		WithSignatureRejectionListener(func(reason string) { reasons = append(reasons, reason) }),
	}, header)

	if rec.Code != http.StatusForbidden || captured != nil {
		t.Fatalf("status = %d, want 403 without handler profile", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), mycelium.SignatureRejectionDetail) {
		t.Errorf("body = %s, want generic detail", rec.Body.String())
	}
	if len(reasons) != 1 || reasons[0] != mycelium.ReasonMissingSignature {
		t.Errorf("reasons = %v", reasons)
	}
}

func TestTamperedProfileIsRefused(t *testing.T) {
	profile, signature, verifier := signedFixture(t)
	header := http.Header{}
	header.Set(mycelium.DefaultProfileKey, profile+"A")
	header.Set(mycelium.DefaultProfileSignatureKey, signature)

	rec, _ := serveSigned([]Option{WithProfileSignatureVerifier(verifier)}, header)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestInvalidSignatureConfigurationFailsClosed(t *testing.T) {
	mycelium.ResetProfileSignatureConfiguration()
	t.Cleanup(mycelium.ResetProfileSignatureConfiguration)
	// Verification requested without the mandatory audience.
	t.Setenv(mycelium.ProfileJWKSURLEnv, "https://gateway.test")

	rec, _ := serveSigned([]Option{WithEnvironment("development")}, http.Header{})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

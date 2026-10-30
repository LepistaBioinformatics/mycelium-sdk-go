package myceliumgin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

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
		Signature     string `json:"signature"`
	} `json:"vectors"`
}

// signedFixture returns the first (valid) contract vector and a verifier
// trusting key 1 with a tolerance wide enough for its fixed clock.
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
		mycelium.ProfilePublicKeyEnvPrefix + "1": corpus.PublicKeys["1"],
		mycelium.ProfileSignatureToleranceEnv:    strconv.FormatUint(mycelium.MaxSafeTimestampSeconds, 10),
	})
	if err != nil {
		t.Fatal(err)
	}
	return corpus.Vectors[0].ProfileHeader, corpus.Vectors[0].Signature, verifier
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
	t.Setenv("MYC_PROFILE_PUBLIC_KEY_1", "not a key")

	rec, _ := serveSigned([]Option{WithEnvironment("development")}, http.Header{})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

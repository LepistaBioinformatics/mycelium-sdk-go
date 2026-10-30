package myceliumecho

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	mycelium "github.com/LepistaBioinformatics/mycelium-sdk-go"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func encodedProfile(t *testing.T) string {
	t.Helper()
	p := mycelium.Profile{AccID: uuid.New(), IsStaff: true}
	enc, err := mycelium.CompressAndEncodeProfileToBase64(&p)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func newEcho(env string, captured **mycelium.Profile) *echo.Echo {
	e := echo.New()
	e.Use(Middleware(WithEnvironment(env)))
	e.GET("/", func(c echo.Context) error {
		if p, ok := FromContext(c); ok {
			*captured = p
		}
		return c.NoContent(http.StatusOK)
	})
	return e
}

func TestEchoMiddlewarePopulatesContext(t *testing.T) {
	var captured *mycelium.Profile
	e := newEcho("production", &captured)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(mycelium.DefaultProfileKey, encodedProfile(t))
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if captured == nil || !captured.IsStaff {
		t.Errorf("profile not populated: %+v", captured)
	}
}

func TestEchoMissingHeaderProduction403(t *testing.T) {
	var captured *mycelium.Profile
	e := newEcho("production", &captured)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestEchoBadHeaderProduction401(t *testing.T) {
	var captured *mycelium.Profile
	e := newEcho("production", &captured)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(mycelium.DefaultProfileKey, "!!!bad!!!")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestEchoDevelopmentTolerant(t *testing.T) {
	var captured *mycelium.Profile
	e := newEcho("development", &captured)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
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
	e := echo.New()
	e.Use(Middleware(opts...))
	e.GET("/", func(c echo.Context) error {
		captured, _ = FromContext(c)
		return c.NoContent(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header = header
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
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

package myceliumgin

import (
	"net/http"
	"net/http/httptest"
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

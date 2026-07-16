package myceliumecho

import (
	"net/http"
	"net/http/httptest"
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

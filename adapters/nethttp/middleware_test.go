package nethttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mycelium "github.com/LepistaBioinformatics/mycelium-sdk-go"
	"github.com/google/uuid"
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

func TestMiddlewarePopulatesContext(t *testing.T) {
	var captured *mycelium.Profile
	handler := Middleware(WithEnvironment("production"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := FromContext(r.Context())
		if ok {
			captured = p
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(mycelium.DefaultProfileKey, encodedProfile(t))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if captured == nil || !captured.IsStaff {
		t.Errorf("profile not populated: %+v", captured)
	}
}

func TestMiddlewareMissingHeaderProduction403(t *testing.T) {
	handler := Middleware(WithEnvironment("production"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestMiddlewareBadHeaderProduction401(t *testing.T) {
	handler := Middleware(WithEnvironment("production"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(mycelium.DefaultProfileKey, "!!!not valid!!!")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestMiddlewareDevelopmentTolerant(t *testing.T) {
	called := false
	handler := Middleware(WithEnvironment("development"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := FromContext(r.Context()); ok {
			t.Error("expected no profile in tolerant dev mode")
		}
		w.WriteHeader(http.StatusOK)
	}))
	// Missing header
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called || rec.Code != http.StatusOK {
		t.Errorf("dev missing header: called=%v code=%d", called, rec.Code)
	}
	// Bad header
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(mycelium.DefaultProfileKey, "garbage")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Errorf("dev bad header code = %d, want 200", rec2.Code)
	}
}

func TestFromContextEmpty(t *testing.T) {
	if _, ok := FromContext(httptest.NewRequest(http.MethodGet, "/", nil).Context()); ok {
		t.Error("expected no profile in bare context")
	}
}

func TestDefaultEnvironmentIsDevelopment(t *testing.T) {
	c := &config{}
	if c.resolvedEnvironment() != "development" {
		t.Errorf("default env = %q, want development", c.resolvedEnvironment())
	}
}

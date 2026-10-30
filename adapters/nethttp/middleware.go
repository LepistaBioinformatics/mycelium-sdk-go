// Package nethttp provides net/http middleware that extracts the Mycelium
// profile from the x-mycelium-profile header into the request context.
package nethttp

import (
	"context"
	"net/http"
	"os"

	mycelium "github.com/LepistaBioinformatics/mycelium-sdk-go"
)

type contextKey struct{}

var profileContextKey = contextKey{}

type config struct {
	environment string
	verifier    *mycelium.ProfileSignatureVerifier
	onRejected  func(reason string)
}

// Option configures the middleware.
type Option func(*config)

// WithEnvironment sets the runtime environment explicitly. When unset, the
// ENVIRONMENT variable is used, defaulting to "development".
func WithEnvironment(env string) Option {
	return func(c *config) { c.environment = env }
}

func (c *config) resolvedEnvironment() string {
	if c.environment != "" {
		return c.environment
	}
	if env := os.Getenv("ENVIRONMENT"); env != "" {
		return env
	}
	return "development"
}

// WithProfileSignatureVerifier sets the signature verifier explicitly (for
// example the one returned by mycelium.ConfigureProfileSignature at startup).
// When unset, the verifier is loaded once from the MYC_PROFILE_PUBLIC_KEY_*
// environment; with no public key configured, verification is disabled.
func WithProfileSignatureVerifier(verifier *mycelium.ProfileSignatureVerifier) Option {
	return func(c *config) { c.verifier = verifier }
}

// WithSignatureRejectionListener receives the log-safe reason of every
// refused signature (never the token). Clients only see a generic detail.
func WithSignatureRejectionListener(listener func(reason string)) Option {
	return func(c *config) { c.onRejected = listener }
}

func (c *config) enforceSignature(header http.Header) mycelium.SignatureEnforcement {
	outcome := mycelium.EnforceProfileSignature(header, c.verifier)
	if outcome.Reason != "" && c.onRejected != nil {
		c.onRejected(outcome.Reason)
	}
	return outcome
}

// Middleware returns a net/http middleware that decodes the profile header and
// stores the resulting *mycelium.Profile in the request context.
//
// In development a missing or undecodable header is tolerated (the profile is
// simply absent). In any other environment a missing header yields 403 and an
// undecodable header yields 401.
//
// When signature verification is enabled (any MYC_PROFILE_PUBLIC_KEY_* or an
// explicit verifier), the profile is authenticated first in every
// environment: a rejected signature answers 403 and a configuration or
// internal error 500, both with generic details.
func Middleware(opts ...Option) func(http.Handler) http.Handler {
	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}
	env := cfg.resolvedEnvironment()
	development := env == "development"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if outcome := cfg.enforceSignature(r.Header); outcome.Enabled {
				if outcome.Profile == nil {
					writeJSONError(w, outcome.Status, outcome.Detail)
					return
				}
				ctx := context.WithValue(r.Context(), profileContextKey, outcome.Profile)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			raw := r.Header.Get(mycelium.DefaultProfileKey)

			if raw == "" {
				if development {
					next.ServeHTTP(w, r)
					return
				}
				writeJSONError(w, http.StatusForbidden,
					"Required header '"+mycelium.DefaultProfileKey+"' missing in production environment.")
				return
			}

			profile, err := mycelium.DecodeAndDecompressProfileFromBase64(raw)
			if err != nil {
				if development {
					next.ServeHTTP(w, r)
					return
				}
				writeJSONError(w, http.StatusUnauthorized,
					"Unable to check user identity. Please contact administrators")
				return
			}

			ctx := context.WithValue(r.Context(), profileContextKey, profile)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FromContext returns the profile stored by Middleware, if present.
func FromContext(ctx context.Context) (*mycelium.Profile, bool) {
	p, ok := ctx.Value(profileContextKey).(*mycelium.Profile)
	return p, ok
}

func writeJSONError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"detail":"` + detail + `"}`))
}

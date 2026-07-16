// Package myceliumecho provides Echo middleware that extracts the Mycelium
// profile from the x-mycelium-profile header into the Echo context.
package myceliumecho

import (
	"net/http"
	"os"

	mycelium "github.com/LepistaBioinformatics/mycelium-sdk-go"
	"github.com/labstack/echo/v4"
)

// ContextKey is the key under which the *mycelium.Profile is stored in the Echo
// context.
const ContextKey = "mycelium_profile"

type config struct {
	environment string
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

// Middleware returns Echo middleware that decodes the profile header and stores
// the resulting *mycelium.Profile in the context.
//
// In development a missing or undecodable header is tolerated. In any other
// environment a missing header responds 403 and an undecodable header 401.
func Middleware(opts ...Option) echo.MiddlewareFunc {
	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}
	development := cfg.resolvedEnvironment() == "development"

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			raw := c.Request().Header.Get(mycelium.DefaultProfileKey)

			if raw == "" {
				if development {
					return next(c)
				}
				return c.JSON(http.StatusForbidden, map[string]string{
					"detail": "Required header '" + mycelium.DefaultProfileKey + "' missing in production environment.",
				})
			}

			profile, err := mycelium.DecodeAndDecompressProfileFromBase64(raw)
			if err != nil {
				if development {
					return next(c)
				}
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"detail": "Unable to check user identity. Please contact administrators",
				})
			}

			c.Set(ContextKey, profile)
			return next(c)
		}
	}
}

// FromContext returns the profile stored by Middleware, if present.
func FromContext(c echo.Context) (*mycelium.Profile, bool) {
	p, ok := c.Get(ContextKey).(*mycelium.Profile)
	return p, ok
}

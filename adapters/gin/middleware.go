// Package myceliumgin provides Gin middleware that extracts the Mycelium
// profile from the x-mycelium-profile header into the Gin context.
package myceliumgin

import (
	"net/http"
	"os"

	mycelium "github.com/LepistaBioinformatics/mycelium-sdk-go"
	"github.com/gin-gonic/gin"
)

// ContextKey is the key under which the *mycelium.Profile is stored in the Gin
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

// Middleware returns Gin middleware that decodes the profile header and stores
// the resulting *mycelium.Profile in the context.
//
// In development a missing or undecodable header is tolerated. In any other
// environment a missing header aborts with 403 and an undecodable header with 401.
func Middleware(opts ...Option) gin.HandlerFunc {
	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}
	development := cfg.resolvedEnvironment() == "development"

	return func(c *gin.Context) {
		raw := c.GetHeader(mycelium.DefaultProfileKey)

		if raw == "" {
			if development {
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"detail": "Required header '" + mycelium.DefaultProfileKey + "' missing in production environment.",
			})
			return
		}

		profile, err := mycelium.DecodeAndDecompressProfileFromBase64(raw)
		if err != nil {
			if development {
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"detail": "Unable to check user identity. Please contact administrators",
			})
			return
		}

		c.Set(ContextKey, profile)
		c.Next()
	}
}

// FromContext returns the profile stored by Middleware, if present.
func FromContext(c *gin.Context) (*mycelium.Profile, bool) {
	v, ok := c.Get(ContextKey)
	if !ok {
		return nil, false
	}
	p, ok := v.(*mycelium.Profile)
	return p, ok
}

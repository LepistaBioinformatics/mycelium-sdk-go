package mycelium

import (
	"log/slog"
	"net/url"
	"strings"
)

// parseProfileJWKSURL validates where the gateway profile JWKS is fetched.
//
// The location comes only from the service configuration, never from a
// request: a verifier that followed a URL found in the message it verifies
// would let an attacker choose the keys. https:// is required; http:// only
// with the explicit development switch. Credentials in the URL are refused.
func parseProfileJWKSURL(raw string, allowInsecureHTTP bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Opaque != "" || parsed.Host == "" {
		return "", invalidJWKSURL("is not an absolute URL")
	}
	if parsed.User != nil {
		if _, hasPassword := parsed.User.Password(); parsed.User.Username() != "" || hasPassword {
			return "", invalidJWKSURL("must not carry credentials")
		}
	}

	switch {
	case parsed.Scheme == "https":
		return parsed.String(), nil
	case parsed.Scheme == "http" && allowInsecureHTTP:
		slog.Warn(ProfileJWKSURLEnv+" uses plain HTTP; development only",
			"event", "profile_signature.jwks")
		return parsed.String(), nil
	default:
		return "", invalidJWKSURL("must use https")
	}
}

func invalidJWKSURL(problem string) error {
	return NewProfileSignatureConfigurationError(ProfileJWKSURLEnv + " " + problem)
}

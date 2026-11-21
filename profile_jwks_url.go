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
//
// Two forms are accepted, so a service only needs to know where its gateway
// is: the complete endpoint, ending in ProfileJWKSPath, used as is; or the
// gateway base (mycelium.example.com, https://host/prefix), to which
// ProfileJWKSPath is appended. Without a scheme, https:// is assumed.
func parseProfileJWKSURL(raw string, allowInsecureHTTP bool) (string, error) {
	configured, err := withDefaultScheme(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(configured)
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
	case parsed.Scheme == "http" && allowInsecureHTTP:
		slog.Warn(ProfileJWKSURLEnv+" uses plain HTTP; development only",
			"event", "profile_signature.jwks")
	default:
		return "", invalidJWKSURL("must use https")
	}

	if strings.HasSuffix(parsed.EscapedPath(), ProfileJWKSPath) {
		return parsed.String(), nil
	}
	if strings.ContainsAny(configured, "?#") {
		return "", invalidJWKSURL("must not carry a query or fragment")
	}
	return strings.TrimRight(parsed.String(), "/") + ProfileJWKSPath, nil
}

// withDefaultScheme returns the configured value, with https:// when it
// names no scheme.
func withDefaultScheme(configured string) (string, error) {
	if strings.Contains(configured, "://") {
		return configured, nil
	}
	if configured == "" || strings.HasPrefix(configured, "/") {
		return "", invalidJWKSURL("is not an absolute URL")
	}
	return "https://" + configured, nil
}

func invalidJWKSURL(problem string) error {
	return NewProfileSignatureConfigurationError(ProfileJWKSURLEnv + " " + problem)
}

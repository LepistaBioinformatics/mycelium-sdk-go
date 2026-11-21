package mycelium

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// FetchedProfileJWKS is a key set read from the gateway and how long it may
// be cached.
type FetchedProfileJWKS struct {
	Keys   *TrustedProfileKeys
	MaxAge time.Duration
}

// ProfileJWKSFetcher downloads the profile JWKS (HTTP in production, fakes
// in tests). It must be safe for concurrent use.
type ProfileJWKSFetcher func(ctx context.Context, url string) (FetchedProfileJWKS, error)

// jwksHTTPClient never follows redirects: a redirect could move the trust
// anchor to another origin, so a 3xx is a failure.
var jwksHTTPClient = &http.Client{
	Timeout: ProfileJWKSFetchTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// FetchProfileJWKS downloads and parses the gateway profile JWKS over HTTP.
//
// Bounded: 5 s timeout, 64 KiB body, redirects never followed, non-2xx
// refused. The cache lifetime comes from Cache-Control max-age (see
// ReadJWKSCacheMaxAge). A refused key set is a
// *ProfileSignatureConfigurationError; transport failures are plain errors.
func FetchProfileJWKS(ctx context.Context, url string) (FetchedProfileJWKS, error) {
	ctx, cancel := context.WithTimeout(ctx, ProfileJWKSFetchTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return FetchedProfileJWKS{}, fetchFailure("request invalid: %v", err)
	}
	request.Header.Set("Accept", "application/json")

	response, err := jwksHTTPClient.Do(request)
	if err != nil {
		return FetchedProfileJWKS{}, fetchFailure("request failed: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return FetchedProfileJWKS{}, fetchFailure("status %d", response.StatusCode)
	}

	body, err := readBoundedBody(response.Body)
	if err != nil {
		return FetchedProfileJWKS{}, err
	}
	keys, err := ParseTrustedProfileKeys(body)
	if err != nil {
		return FetchedProfileJWKS{}, err
	}

	maxAge := ReadJWKSCacheMaxAge(response.Header.Get("Cache-Control"))
	return FetchedProfileJWKS{Keys: keys, MaxAge: maxAge}, nil
}

func readBoundedBody(body io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(body, ProfileJWKSMaxBytes+1))
	if err != nil {
		return nil, fetchFailure("body unreadable: %v", err)
	}
	if len(raw) > ProfileJWKSMaxBytes {
		return nil, fetchFailure("body larger than %d bytes", ProfileJWKSMaxBytes)
	}
	return raw, nil
}

func fetchFailure(format string, args ...any) error {
	return errors.New("profile_jwks_fetch_failed: " + fmt.Sprintf(format, args...))
}

// ReadJWKSCacheMaxAge returns how long a fetched profile JWKS may be cached:
// the max-age directive of a Cache-Control value (name case-insensitive),
// clamped to 1 minute..1 day; 12 hours when the value is empty or has no
// readable max-age.
func ReadJWKSCacheMaxAge(cacheControl string) time.Duration {
	announced := DefaultProfileJWKSMaxAge
	for _, directive := range strings.Split(cacheControl, ",") {
		if seconds, ok := maxAgeDirective(directive); ok {
			announced = time.Duration(seconds) * time.Second
			break
		}
	}
	return min(max(announced, MinProfileJWKSMaxAge), MaxProfileJWKSMaxAge)
}

func maxAgeDirective(directive string) (uint64, bool) {
	name, value, found := strings.Cut(strings.TrimSpace(directive), "=")
	if !found || !strings.EqualFold(strings.TrimSpace(name), "max-age") {
		return 0, false
	}
	// A single leading "+" is accepted, like the Rust reference parser.
	digits := strings.TrimPrefix(strings.TrimSpace(value), "+")
	seconds, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, false
	}
	return min(seconds, uint64(MaxProfileJWKSMaxAge/time.Second)), true
}

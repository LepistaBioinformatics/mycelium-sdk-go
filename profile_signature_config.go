package mycelium

import (
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var canonicalPositiveInteger = regexp.MustCompile(`^[1-9][0-9]*$`)

const maxKeyVersion = 4_294_967_295

// ProfileSignatureVerifier verifies the gateway profile signature with the
// public keys the gateway publishes as a JWKS.
//
// Verification is opt-in per service: it is enabled when MYCELIUM_JWKS_URL
// is set, and MYC_PROFILE_SIGNATURE_AUDIENCE is then required, so a signed
// pair issued for another service is always refused. The verification
// itself is local; only the keys are remote, cached and refreshed (see
// Prefetch and the refresh rules on profileKeyStore). An invalid setting is
// always an error, never "disabled". Safe for concurrent use.
type ProfileSignatureVerifier struct {
	store            *profileKeyStore
	toleranceSeconds uint64
	expectedAudience string
}

// VerifierOption customizes a verifier built from the environment.
type VerifierOption func(*verifierOptions)

type verifierOptions struct {
	fetcher  ProfileJWKSFetcher
	cooldown time.Duration
}

// WithJWKSFetcher replaces the HTTP fetcher (tests, custom transports).
func WithJWKSFetcher(fetcher ProfileJWKSFetcher) VerifierOption {
	return func(o *verifierOptions) { o.fetcher = fetcher }
}

// WithJWKSRefetchCooldown overrides the 30 s refetch cooldown (tests only).
func WithJWKSRefetchCooldown(cooldown time.Duration) VerifierOption {
	return func(o *verifierOptions) { o.cooldown = cooldown }
}

// ToleranceSeconds returns the symmetric, inclusive iat tolerance.
func (v *ProfileSignatureVerifier) ToleranceSeconds() uint64 { return v.toleranceSeconds }

// ExpectedAudience returns the audience every signature must carry.
func (v *ProfileSignatureVerifier) ExpectedAudience() string { return v.expectedAudience }

// JWKSURL returns the validated URL the keys are fetched from.
func (v *ProfileSignatureVerifier) JWKSURL() string { return v.store.url }

// TrustsKey reports whether kid selects a currently cached public key.
func (v *ProfileSignatureVerifier) TrustsKey(kid string) bool {
	keys, _ := v.store.current()
	_, ok := keys.keyFor(kid)
	return ok
}

// Prefetch downloads the key set now. Opt-in: call it after
// ConfigureProfileSignature to download at startup and fail when the gateway
// is unreachable. By default the keys are downloaded on the first signed
// request instead, so the service does not depend on the gateway to start
// (requests only reach it through the gateway).
func (v *ProfileSignatureVerifier) Prefetch(ctx context.Context) error {
	return v.store.prefetch(ctx)
}

// IsCanonicalKeyVersion reports whether raw is a canonical positive u32 (no
// sign, leading zeros or spaces), the only form accepted as a kid.
func IsCanonicalKeyVersion(raw string) bool {
	if len(raw) > 10 || !canonicalPositiveInteger.MatchString(raw) {
		return false
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	return err == nil && value <= maxKeyVersion
}

// LoadProfileSignatureVerifierFromEnv builds the verifier from an
// environment mapping without touching the network. It returns (nil, nil)
// when MYCELIUM_JWKS_URL is absent (verification disabled, legacy behavior)
// and a *ProfileSignatureConfigurationError for any invalid setting, even
// when verification stays disabled.
func LoadProfileSignatureVerifierFromEnv(environ map[string]string, opts ...VerifierOption) (*ProfileSignatureVerifier, error) {
	tolerance, err := parseTolerance(environ)
	if err != nil {
		return nil, err
	}
	audience, err := parseAudience(environ)
	if err != nil {
		return nil, err
	}
	allowInsecureHTTP, err := parseInsecureSwitch(environ)
	if err != nil {
		return nil, err
	}

	rawURL, enabled := environ[ProfileJWKSURLEnv]
	if !enabled {
		return nil, nil
	}
	jwksURL, err := parseProfileJWKSURL(rawURL, allowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	if audience == nil {
		return nil, NewProfileSignatureConfigurationError(
			ProfileSignatureAudienceEnv + " is required when " + ProfileJWKSURLEnv + " is set")
	}

	options := verifierOptions{fetcher: FetchProfileJWKS, cooldown: ProfileJWKSRefetchCooldown}
	for _, opt := range opts {
		opt(&options)
	}
	return &ProfileSignatureVerifier{
		store:            newProfileKeyStore(jwksURL, options.fetcher, options.cooldown),
		toleranceSeconds: tolerance,
		expectedAudience: *audience,
	}, nil
}

// LoadProfileSignatureVerifier builds the verifier from the process
// environment (see LoadProfileSignatureVerifierFromEnv).
func LoadProfileSignatureVerifier(opts ...VerifierOption) (*ProfileSignatureVerifier, error) {
	return LoadProfileSignatureVerifierFromEnv(processEnvironment(), opts...)
}

func processEnvironment() map[string]string {
	environ := map[string]string{}
	for _, entry := range os.Environ() {
		if name, value, ok := strings.Cut(entry, "="); ok {
			environ[name] = value
		}
	}
	return environ
}

func parseTolerance(environ map[string]string) (uint64, error) {
	raw, ok := environ[ProfileSignatureToleranceEnv]
	if !ok {
		return DefaultProfileSignatureToleranceSeconds, nil
	}

	trimmed := strings.TrimSpace(raw)
	invalid := NewProfileSignatureConfigurationError(
		ProfileSignatureToleranceEnv + " must be a positive integer")
	if len(trimmed) > 16 || !canonicalPositiveInteger.MatchString(trimmed) {
		return 0, invalid
	}
	value, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil || value > MaxSafeTimestampSeconds {
		return 0, invalid
	}
	return value, nil
}

func parseAudience(environ map[string]string) (*string, error) {
	raw, ok := environ[ProfileSignatureAudienceEnv]
	if !ok {
		return nil, nil
	}
	if strings.TrimSpace(raw) == "" {
		return nil, NewProfileSignatureConfigurationError(
			ProfileSignatureAudienceEnv + " must not be empty")
	}
	return &raw, nil
}

func parseInsecureSwitch(environ map[string]string) (bool, error) {
	raw, ok := environ[ProfileJWKSAllowInsecureHTTPEnv]
	if !ok {
		return false, nil
	}
	switch strings.TrimSpace(raw) {
	case "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, NewProfileSignatureConfigurationError(
			ProfileJWKSAllowInsecureHTTPEnv + " must be true or false")
	}
}

// Process-wide verifier, loaded once.

var (
	signatureStateMu sync.Mutex
	signatureLoaded  bool
	signatureState   *ProfileSignatureVerifier
	signatureErr     error
)

func storeSignatureState(environ map[string]string) {
	signatureState, signatureErr = LoadProfileSignatureVerifierFromEnv(environ)
	signatureLoaded = true
}

// ConfigureProfileSignature loads, validates and pins the process verifier
// from the environment. Call it at application startup and abort on error:
// a misconfigured service must not start. It does not access the network:
// the gateway JWKS is downloaded on the first signed request (requests fail
// closed until it is available), so the service never waits for the gateway
// to start. Call Prefetch on the result to download it at startup instead.
// A nil verifier with a nil error means verification is disabled. ctx is
// kept for API stability.
func ConfigureProfileSignature(ctx context.Context) (*ProfileSignatureVerifier, error) {
	signatureStateMu.Lock()
	defer signatureStateMu.Unlock()

	_ = ctx
	storeSignatureState(processEnvironment())
	return signatureState, signatureErr
}

// GetProfileSignatureVerifier returns the process verifier, loading it lazily
// once without network access (keys are fetched on the first verification).
// The cached configuration error is returned on every call, so requests fail
// closed; the environment is never re-read per request.
func GetProfileSignatureVerifier() (*ProfileSignatureVerifier, error) {
	signatureStateMu.Lock()
	defer signatureStateMu.Unlock()

	if !signatureLoaded {
		storeSignatureState(processEnvironment())
	}
	return signatureState, signatureErr
}

// ResetProfileSignatureConfiguration forgets the cached state (tests and
// controlled reconfiguration only).
func ResetProfileSignatureConfiguration() {
	signatureStateMu.Lock()
	defer signatureStateMu.Unlock()

	signatureLoaded, signatureState, signatureErr = false, nil, nil
}

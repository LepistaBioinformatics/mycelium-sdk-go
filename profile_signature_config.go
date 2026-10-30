package mycelium

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var canonicalPositiveInteger = regexp.MustCompile(`^[1-9][0-9]*$`)

const maxKeyVersion = 4_294_967_295

// ProfileSignatureVerifier holds the immutable verification settings: the
// trusted Ed25519 public keys by key version (the JWS kid), the iat tolerance
// and the optional expected audience.
//
// Verification is opt-in per service: it is enabled when at least one
// MYC_PROFILE_PUBLIC_KEY_<version> variable is present. An invalid setting is
// always an error, never "disabled".
type ProfileSignatureVerifier struct {
	publicKeys       map[string]ed25519.PublicKey
	toleranceSeconds uint64
	expectedAudience *string
}

// ToleranceSeconds returns the symmetric, inclusive iat tolerance.
func (v *ProfileSignatureVerifier) ToleranceSeconds() uint64 { return v.toleranceSeconds }

// ExpectedAudience returns the configured audience, if any.
func (v *ProfileSignatureVerifier) ExpectedAudience() (string, bool) {
	if v.expectedAudience == nil {
		return "", false
	}
	return *v.expectedAudience, true
}

// TrustsKey reports whether kid selects a trusted public key.
func (v *ProfileSignatureVerifier) TrustsKey(kid string) bool {
	_, ok := v.publicKeys[kid]
	return ok
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
// environment mapping. It returns (nil, nil) when no public key variable
// exists (verification disabled, legacy behavior) and a
// *ProfileSignatureConfigurationError for any invalid entry.
func LoadProfileSignatureVerifierFromEnv(environ map[string]string) (*ProfileSignatureVerifier, error) {
	tolerance, err := parseTolerance(environ)
	if err != nil {
		return nil, err
	}
	audience, err := parseAudience(environ)
	if err != nil {
		return nil, err
	}

	keys, err := loadPublicKeys(environ)
	if err != nil || len(keys) == 0 {
		return nil, err
	}

	return &ProfileSignatureVerifier{
		publicKeys:       keys,
		toleranceSeconds: tolerance,
		expectedAudience: audience,
	}, nil
}

// LoadProfileSignatureVerifier builds the verifier from the process
// environment (see LoadProfileSignatureVerifierFromEnv).
func LoadProfileSignatureVerifier() (*ProfileSignatureVerifier, error) {
	return LoadProfileSignatureVerifierFromEnv(processEnvironment())
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

func loadPublicKeys(environ map[string]string) (map[string]ed25519.PublicKey, error) {
	names := make([]string, 0)
	for name := range environ {
		if strings.HasPrefix(name, ProfilePublicKeyEnvPrefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	keys := map[string]ed25519.PublicKey{}
	for _, name := range names {
		version := strings.TrimPrefix(name, ProfilePublicKeyEnvPrefix)
		if !IsCanonicalKeyVersion(version) {
			return nil, NewProfileSignatureConfigurationError(name +
				": key version suffix must be a canonical positive integer (for example MYC_PROFILE_PUBLIC_KEY_1)")
		}
		key, err := parsePublicKey(name, environ[name])
		if err != nil {
			return nil, err
		}
		keys[version] = key
	}
	return keys, nil
}

func parsePublicKey(name, raw string) (ed25519.PublicKey, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, NewProfileSignatureConfigurationError(name + " is empty")
	}

	block, _ := pem.Decode([]byte(raw))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, NewProfileSignatureConfigurationError(name +
			" is not a PEM SubjectPublicKeyInfo public key (a private key or malformed PEM was provided)")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, NewProfileSignatureConfigurationError(name + " is not an Ed25519 public key")
	}
	return key, nil
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

// ConfigureProfileSignature loads and pins the process verifier from the
// environment. Call it at application startup: it returns the configuration
// error so a misconfigured service does not start. A nil verifier with a nil
// error means verification is disabled.
func ConfigureProfileSignature() (*ProfileSignatureVerifier, error) {
	signatureStateMu.Lock()
	defer signatureStateMu.Unlock()

	storeSignatureState(processEnvironment())
	return signatureState, signatureErr
}

// GetProfileSignatureVerifier returns the process verifier, loading it lazily
// once. The cached configuration error is returned on every call, so
// requests fail closed; the environment is never re-read per request.
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

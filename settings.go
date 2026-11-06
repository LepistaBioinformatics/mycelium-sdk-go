package mycelium

import "time"

// Header keys injected by the Mycelium API Gateway into downstream requests.
//
// These mirror the gateway constants in lib/http_tools/src/settings.rs and the
// sibling SDKs (mycelium-sdk-py, mycelium-sdk-js). Only DefaultProfileKey is
// consumed by the decode/middleware code; the rest are provided for consumers.
const (
	// DefaultProfileKey carries the Base64 + ZSTD compressed JSON Profile.
	DefaultProfileKey = "x-mycelium-profile"
	// DefaultEmailKey carries the authenticated user email.
	DefaultEmailKey = "x-mycelium-email"
	// DefaultScopeKey carries the request scope.
	DefaultScopeKey = "x-mycelium-scope"
	// DefaultMyceliumRoleKey carries the request role.
	DefaultMyceliumRoleKey = "x-mycelium-role"
	// DefaultRequestIDKey carries the request correlation id.
	DefaultRequestIDKey = "x-mycelium-request-id"
	// DefaultConnectionStringKey carries the service connection string.
	DefaultConnectionStringKey = "x-mycelium-connection-string"
	// DefaultTenantIDKey carries the resolved tenant id.
	DefaultTenantIDKey = "x-mycelium-tenant-id"
	// DefaultProfileSignatureKey carries the gateway's compact JWS (EdDSA)
	// over the exact DefaultProfileKey value.
	DefaultProfileSignatureKey = "x-mycelium-profile-signature"
)

// Profile signature verification settings, shared with the gateway and the
// Python, JavaScript and Rust verifiers.
const (
	// ProfileJWKSURLEnv names the URL of the gateway profile JWKS. Its
	// presence enables verification; it must be https:// unless
	// ProfileJWKSAllowInsecureHTTPEnv is "true" (development only).
	ProfileJWKSURLEnv = "MYCELIUM_JWKS_URL"
	// ProfileJWKSAllowInsecureHTTPEnv accepts an http:// JWKS URL when
	// "true" (development only). Absent or "false" refuses it.
	ProfileJWKSAllowInsecureHTTPEnv = "MYCELIUM_JWKS_ALLOW_INSECURE_HTTP"
	// ProfileSignatureToleranceEnv optionally overrides the iat tolerance.
	ProfileSignatureToleranceEnv = "MYC_PROFILE_SIGNATURE_TOLERANCE_SECONDS"
	// ProfileSignatureAudienceEnv sets the expected aud claim. Required
	// whenever ProfileJWKSURLEnv is set.
	ProfileSignatureAudienceEnv = "MYC_PROFILE_SIGNATURE_AUDIENCE"
	// DefaultProfileSignatureToleranceSeconds is the symmetric, inclusive
	// iat tolerance.
	DefaultProfileSignatureToleranceSeconds uint64 = 60
	// MaxProfileSignatureBytes bounds the accepted signature header.
	MaxProfileSignatureBytes = 4096
	// MaxSafeTimestampSeconds is the largest integer every SDK represents
	// exactly (2^53 - 1).
	MaxSafeTimestampSeconds uint64 = 9_007_199_254_740_991
)

// Profile JWKS retrieval limits, shared with every verifier (see
// testdata/profile-signature/jwks-vectors.json "contract").
const (
	// ProfileJWKSPath is where the gateway publishes the profile JWKS.
	ProfileJWKSPath = "/.well-known/mycelium-profile-jwks.json"
	// ProfileJWKSFetchTimeout bounds one JWKS request.
	ProfileJWKSFetchTimeout = 5 * time.Second
	// ProfileJWKSMaxBytes bounds the JWKS response body.
	ProfileJWKSMaxBytes = 64 * 1024
	// ProfileJWKSRefetchCooldown is the minimum interval between JWKS
	// requests not caused by expiry (unknown kid, failed refresh).
	ProfileJWKSRefetchCooldown = 30 * time.Second
	// ProfileJWKSEmptyRetry is the shorter retry interval while no key set
	// was ever downloaded, so a service started before the gateway picks
	// the keys up within seconds once the gateway is reachable.
	ProfileJWKSEmptyRetry = 5 * time.Second
	// DefaultProfileJWKSMaxAge is the cache lifetime when the response has
	// no usable max-age (12 hours).
	DefaultProfileJWKSMaxAge = 43_200 * time.Second
	// MinProfileJWKSMaxAge and MaxProfileJWKSMaxAge clamp the announced
	// max-age.
	MinProfileJWKSMaxAge = 60 * time.Second
	MaxProfileJWKSMaxAge = 86_400 * time.Second
)

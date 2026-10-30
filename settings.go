package mycelium

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
// Python and JavaScript SDKs.
const (
	// ProfilePublicKeyEnvPrefix names the trusted Ed25519 SPKI PEM public
	// keys: MYC_PROFILE_PUBLIC_KEY_<version>. Any such variable enables
	// verification.
	ProfilePublicKeyEnvPrefix = "MYC_PROFILE_PUBLIC_KEY_"
	// ProfileSignatureToleranceEnv optionally overrides the iat tolerance.
	ProfileSignatureToleranceEnv = "MYC_PROFILE_SIGNATURE_TOLERANCE_SECONDS"
	// ProfileSignatureAudienceEnv optionally sets the expected aud claim.
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

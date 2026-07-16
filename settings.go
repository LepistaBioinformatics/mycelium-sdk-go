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
)

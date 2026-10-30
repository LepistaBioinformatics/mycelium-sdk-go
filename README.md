# mycelium-sdk-go

Mycelium SDK for Go backends — decode the `x-mycelium-profile` header injected by the
Mycelium API Gateway and enforce tenant/account/role authorization with a fluent, typed API.

Part of the Mycelium SDK family, alongside
[`mycelium-sdk-py`](https://github.com/LepistaBioinformatics/mycelium-sdk-py) (Python) and
[`mycelium-sdk-js`](https://github.com/LepistaBioinformatics/mycelium-sdk-js) (Node/TypeScript).
All three have full parity against the gateway's Rust `core::Profile` — the same method
surface (`permitFlags`/`denyFlags`, tenant-wide and admin helpers) and the same wire
contract (`perm` serialized as `"read"`/`"write"`).

## Requirements

- Go **>= 1.23**
- ZSTD via [`github.com/klauspost/compress`](https://github.com/klauspost/compress) (pure
  Go, no cgo)

## Install

```bash
# Core (framework-agnostic, includes the net/http adapter)
go get github.com/LepistaBioinformatics/mycelium-sdk-go

# Gin adapter (separate module — pulled only if you import it)
go get github.com/LepistaBioinformatics/mycelium-sdk-go/adapters/gin

# Echo adapter (separate module)
go get github.com/LepistaBioinformatics/mycelium-sdk-go/adapters/echo
```

The `gin` and `echo` adapters live in their own modules, so a service that only uses the
core package or the `net/http` adapter never compiles Gin or Echo.

## Core usage

```go
import mycelium "github.com/LepistaBioinformatics/mycelium-sdk-go"

profile, err := mycelium.DecodeAndDecompressProfileFromBase64(headerValue)
if err != nil {
    // handle *mycelium.ProfileDecodingError
}

related, err := profile.
    WithReadAccess().
    OnTenant(tenantID).
    WithRoles([]string{"admin"}).
    OnAccount(accountID).
    GetRelatedAccountOrError()
```

Every filter method returns a copy — the original `Profile` is never mutated.

`DecodeAndDecompressProfileFromBase64` returns a `*ProfileDecodingError` on any failure
(empty input, invalid Base64, failed decompression, or invalid JSON). By default it is
strict; pass `WithStrict(false)` to fall back to treating the payload as uncompressed
(useful in development):

```go
profile, err := mycelium.DecodeAndDecompressProfileFromBase64(headerValue, mycelium.WithStrict(false))
```

To produce a header value (e.g. in tests or a gateway-like service), use the encode
counterpart:

```go
encoded, err := mycelium.CompressAndEncodeProfileToBase64(profile)
```

## net/http usage

```go
import (
    mycelium "github.com/LepistaBioinformatics/mycelium-sdk-go"
    myceliumhttp "github.com/LepistaBioinformatics/mycelium-sdk-go/adapters/nethttp"
)

mux := http.NewServeMux()
mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
    profile, ok := myceliumhttp.FromContext(r.Context())
    if !ok {
        http.Error(w, "no profile", http.StatusUnauthorized)
        return
    }
    fmt.Fprintf(w, "accId: %s", profile.AccID)
})

handler := myceliumhttp.Middleware()(mux)
http.ListenAndServe(":8080", handler)
```

In development a missing or invalid header is tolerated (the profile is simply absent from
the context). In any other environment a missing header responds `403` and an undecodable
header `401`. The environment is read from `ENVIRONMENT` (default `development`) or set
explicitly with `myceliumhttp.Middleware(myceliumhttp.WithEnvironment("production"))`.

## Gin usage

```go
import (
    myceliumgin "github.com/LepistaBioinformatics/mycelium-sdk-go/adapters/gin"
    "github.com/gin-gonic/gin"
)

r := gin.New()
r.Use(myceliumgin.Middleware())

r.GET("/whoami", func(c *gin.Context) {
    if profile, ok := myceliumgin.FromContext(c); ok {
        c.JSON(200, gin.H{"accId": profile.AccID})
        return
    }
    c.JSON(401, gin.H{"detail": "no profile"})
})
```

## Echo usage

```go
import (
    myceliumecho "github.com/LepistaBioinformatics/mycelium-sdk-go/adapters/echo"
    "github.com/labstack/echo/v4"
)

e := echo.New()
e.Use(myceliumecho.Middleware())

e.GET("/whoami", func(c echo.Context) error {
    if profile, ok := myceliumecho.FromContext(c); ok {
        return c.JSON(200, map[string]string{"accId": profile.AccID.String()})
    }
    return c.JSON(401, map[string]string{"detail": "no profile"})
})
```

All three adapters share the same environment-gated behavior (dev-tolerant; `403` on
missing and `401` on undecodable headers in production) and expose `FromContext`.

## Verifying the profile signature

If your service can be reached without going through the gateway, enable verification so
forged `x-mycelium-profile` headers are rejected. The gateway signs the exact profile header
with Ed25519 (`x-mycelium-profile-signature`, compact JWS); the SDK verifies it locally with
the gateway public key, using only the Go standard library.

Set the public key **after** the gateway is already signing:

```bash
export MYC_PROFILE_PUBLIC_KEY_1="$(cat profile-signing-v1.pub.pem)"
```

| Variable | Meaning |
|---|---|
| `MYC_PROFILE_PUBLIC_KEY_<version>` | Gateway public key (PEM SPKI) trusted for `kid = <version>`. Any such variable enables verification |
| `MYC_PROFILE_SIGNATURE_TOLERANCE_SECONDS` | Accepted clock difference, default `60` |
| `MYC_PROFILE_SIGNATURE_AUDIENCE` | Optional. When set, the `aud` claim must equal it |

Load the configuration at startup so an invalid value stops the service:

```go
verifier, err := mycelium.ConfigureProfileSignature()
if err != nil {
    log.Fatal(err) // *mycelium.ProfileSignatureConfigurationError
}

handler := myceliumhttp.Middleware(
    myceliumhttp.WithProfileSignatureVerifier(verifier), // optional: loaded once from the environment otherwise
    myceliumhttp.WithSignatureRejectionListener(func(reason string) {
        log.Printf("profile signature rejected: %s", reason) // log-safe reason, never the token
    }),
)(mux)
```

With verification enabled, every adapter (`nethttp`, `gin`, `echo`) verifies **before**
decoding, in every environment (the development leniency does not apply): a rejected
signature answers `403 Unable to verify Mycelium profile`, a configuration or internal error a
generic `500`. Without any public key, the adapters keep the behavior above.

To verify outside an HTTP adapter:

```go
profile, err := verifier.VerifyAndDecodeProfile(profileHeader, signatureHeader)
var rejected *mycelium.ProfileSignatureError
if errors.As(err, &rejected) {
    // rejected.Reason: missing_signature, unknown_key, invalid_signature,
    // timestamp_out_of_tolerance, profile_hash_mismatch, audience_mismatch, ...
}
```

The verifier is tested against the cross-language contract vectors produced by the gateway
(`testdata/profile-signature/vectors.json`, copied byte for byte), the same corpus used by
the Python, JavaScript and Rust verifiers.

## Error handling

All SDK errors embed `*MyceliumError` (`Message`, `Code`, `ExpTrue`) and support
`errors.As`:

| Error | Code | Returned by |
|---|---|---|
| `*ProfileDecodingError` | `MYC00020` | `DecodeAndDecompressProfileFromBase64` on any decode failure |
| `*InsufficientLicensesError` | `MYC00019` | `GetRelatedAccountOrError` when licensed resources are present but empty |
| `*InsufficientPrivilegesError` | `MYC00019` | Any method requiring a privilege the profile lacks (carries `FilteringState`) |
| `*ProfileSignatureError` | `MYC_PROFILE_SIGNATURE_INVALID` | Signature verification; carries a log-safe `Reason` |
| `*ProfileSignatureConfigurationError` | `MYC_PROFILE_SIGNATURE_CONFIG_INVALID` | `ConfigureProfileSignature` / `LoadProfileSignatureVerifier` on an invalid setting |

```go
var decErr *mycelium.ProfileDecodingError
if errors.As(err, &decErr) {
    // handle a decode failure specifically
}
```

## License

Apache-2.0

package mycelium

// Error codes mirror the sibling SDKs: authorization failures share MYC00019,
// profile decoding failures use MYC00020.
const (
	codeInsufficient = "MYC00019"
	codeDecoding     = "MYC00020"
)

// MyceliumError is the base error type for the SDK. It carries an optional
// machine-readable Code and the ExpTrue flag (true for authorization errors
// that are safe to surface to the caller).
type MyceliumError struct {
	Message string
	Code    string
	ExpTrue bool
}

func (e *MyceliumError) Error() string { return e.Message }

// InsufficientPrivilegesError is raised when a profile lacks the administrative
// or scoped privileges required by an operation. It records the filtering state
// accumulated by the fluent chain for diagnostics.
type InsufficientPrivilegesError struct {
	*MyceliumError
	FilteringState []string
}

// NewInsufficientPrivilegesError builds an InsufficientPrivilegesError with the
// shared MYC00019 code.
func NewInsufficientPrivilegesError(message string, filteringState []string) *InsufficientPrivilegesError {
	if filteringState == nil {
		filteringState = []string{}
	}
	return &InsufficientPrivilegesError{
		MyceliumError:  &MyceliumError{Message: message, Code: codeInsufficient, ExpTrue: true},
		FilteringState: filteringState,
	}
}

// Unwrap exposes the embedded base error so errors.As can target *MyceliumError.
func (e *InsufficientPrivilegesError) Unwrap() error { return e.MyceliumError }

// InsufficientLicensesError is raised when a profile has no licensed resources
// satisfying the requested access.
type InsufficientLicensesError struct {
	*MyceliumError
}

// NewInsufficientLicensesError builds an InsufficientLicensesError. An empty
// message falls back to the shared default used by the sibling SDKs.
func NewInsufficientLicensesError(message string) *InsufficientLicensesError {
	if message == "" {
		message = "Insufficient licenses to perform these action"
	}
	return &InsufficientLicensesError{
		MyceliumError: &MyceliumError{Message: message, Code: codeInsufficient, ExpTrue: true},
	}
}

// Unwrap exposes the embedded base error so errors.As can target *MyceliumError.
func (e *InsufficientLicensesError) Unwrap() error { return e.MyceliumError }

// ProfileDecodingError is raised when the x-mycelium-profile header cannot be
// decoded (invalid Base64, decompression, or JSON).
type ProfileDecodingError struct {
	*MyceliumError
}

// NewProfileDecodingError builds a ProfileDecodingError with the MYC00020 code.
func NewProfileDecodingError(message string) *ProfileDecodingError {
	return &ProfileDecodingError{
		MyceliumError: &MyceliumError{Message: message, Code: codeDecoding, ExpTrue: false},
	}
}

// Unwrap exposes the embedded base error so errors.As can target *MyceliumError.
func (e *ProfileDecodingError) Unwrap() error { return e.MyceliumError }

// Profile signature error codes, shared with the Python and JavaScript SDKs.
const (
	// ProfileSignatureInvalidCode marks a rejected profile signature.
	ProfileSignatureInvalidCode = "MYC_PROFILE_SIGNATURE_INVALID"
	// ProfileSignatureConfigInvalidCode marks an invalid verification setting.
	ProfileSignatureConfigInvalidCode = "MYC_PROFILE_SIGNATURE_CONFIG_INVALID"
)

// Stable, log-safe rejection reasons. Every verifier (gateway contract,
// Python, JavaScript, Rust, Go) reports the same reason for the same input.
const (
	ReasonMissingProfile          = "missing_profile"
	ReasonMissingSignature        = "missing_signature"
	ReasonDuplicateHeader         = "duplicate_header"
	ReasonMalformedSignature      = "malformed_signature"
	ReasonUnsupportedAlgorithm    = "unsupported_algorithm"
	ReasonUnknownKey              = "unknown_key"
	ReasonInvalidSignature        = "invalid_signature"
	ReasonInvalidClaims           = "invalid_claims"
	ReasonTimestampOutOfTolerance = "timestamp_out_of_tolerance"
	ReasonProfileHashMismatch     = "profile_hash_mismatch"
	ReasonAudienceMismatch        = "audience_mismatch"
	ReasonInvalidProfile          = "invalid_profile"
)

// ProfileSignatureError is raised when a profile signature fails
// verification. Reason is stable and log-safe; it must not be returned to
// clients: the HTTP adapters answer with a generic message.
type ProfileSignatureError struct {
	*MyceliumError
	Reason string
}

// NewProfileSignatureError builds a ProfileSignatureError for a reason.
func NewProfileSignatureError(reason string) *ProfileSignatureError {
	return &ProfileSignatureError{
		MyceliumError: &MyceliumError{
			Message: "Profile signature rejected: " + reason,
			Code:    ProfileSignatureInvalidCode,
			ExpTrue: true,
		},
		Reason: reason,
	}
}

// Unwrap exposes the embedded base error so errors.As can target *MyceliumError.
func (e *ProfileSignatureError) Unwrap() error { return e.MyceliumError }

// ProfileSignatureConfigurationError is raised when a verification setting is
// present but invalid. Any MYC_PROFILE_PUBLIC_KEY_* variable means
// "verification requested": a malformed one must stop the service instead of
// silently disabling verification. The message names variables, never values.
type ProfileSignatureConfigurationError struct {
	*MyceliumError
}

// NewProfileSignatureConfigurationError builds a configuration error.
func NewProfileSignatureConfigurationError(message string) *ProfileSignatureConfigurationError {
	return &ProfileSignatureConfigurationError{
		MyceliumError: &MyceliumError{
			Message: message,
			Code:    ProfileSignatureConfigInvalidCode,
			ExpTrue: false,
		},
	}
}

// Unwrap exposes the embedded base error so errors.As can target *MyceliumError.
func (e *ProfileSignatureConfigurationError) Unwrap() error { return e.MyceliumError }

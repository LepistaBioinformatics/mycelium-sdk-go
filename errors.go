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

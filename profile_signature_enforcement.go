package mycelium

import (
	"errors"
	"net/http"
	"strings"
)

// Generic client-facing details. The detailed reason is never returned to
// clients; adapters only hand it to an optional rejection listener.
const (
	// SignatureRejectionDetail answers every rejected signature (403).
	SignatureRejectionDetail = "Unable to verify Mycelium profile"
	// SignatureInternalDetail answers configuration or internal errors (500).
	SignatureInternalDetail = "Unable to check user identity. Please contact administrators"
)

// Log-safe reasons of a 500 outcome.
const (
	ReasonConfigurationInvalid = "configuration_invalid"
	ReasonInternalError        = "internal_error"
)

// SignatureEnforcement is the outcome of the signature check for a request.
//
// When Enabled is false, verification is not configured and the adapter keeps
// its legacy behavior. When Enabled is true, the handler may only run if
// Profile is set; otherwise the adapter answers Status (403 or 500) with
// Detail. Reason is the log-safe cause ("" when accepted).
type SignatureEnforcement struct {
	Enabled bool
	Profile *Profile
	Status  int
	Detail  string
	Reason  string
}

// EnforceProfileSignature authenticates and decodes the profile carried by
// header when verification is enabled, in every environment: the development
// leniency never applies to a failed signature.
//
// verifier, when non-nil, is used as is; otherwise the process verifier is
// loaded once from the environment (GetProfileSignatureVerifier) and an
// invalid configuration fails closed with 500.
func EnforceProfileSignature(header http.Header, verifier *ProfileSignatureVerifier) SignatureEnforcement {
	if verifier == nil {
		loaded, err := GetProfileSignatureVerifier()
		if err != nil {
			return refused(http.StatusInternalServerError, SignatureInternalDetail, ReasonConfigurationInvalid)
		}
		verifier = loaded
	}
	if verifier == nil {
		return SignatureEnforcement{}
	}

	profile, err := verifyRequestHeaders(header, verifier)
	var rejection *ProfileSignatureError
	if errors.As(err, &rejection) {
		return refused(http.StatusForbidden, SignatureRejectionDetail, rejection.Reason)
	}
	if err != nil {
		return refused(http.StatusInternalServerError, SignatureInternalDetail, ReasonInternalError)
	}
	return SignatureEnforcement{Enabled: true, Profile: profile}
}

func refused(status int, detail, reason string) SignatureEnforcement {
	return SignatureEnforcement{Enabled: true, Status: status, Detail: detail, Reason: reason}
}

func verifyRequestHeaders(header http.Header, verifier *ProfileSignatureVerifier) (*Profile, error) {
	profileHeader, err := singleHeaderValue(header, DefaultProfileKey, ReasonMissingProfile)
	if err != nil {
		return nil, err
	}
	signatureHeader, err := singleHeaderValue(header, DefaultProfileSignatureKey, ReasonMissingSignature)
	if err != nil {
		return nil, err
	}
	return verifier.VerifyAndDecodeProfile(profileHeader, signatureHeader)
}

// singleHeaderValue returns the one value of a header, refusing duplicates.
// Neither Base64 nor a compact JWS contains ",": a comma can only come from
// repeated headers folded by a proxy, so it counts as a duplicate too.
func singleHeaderValue(header http.Header, name, missingReason string) (string, error) {
	values := []string{}
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			values = append(values, strings.TrimSpace(part))
		}
	}

	if len(values) > 1 {
		return "", NewProfileSignatureError(ReasonDuplicateHeader)
	}
	if len(values) == 0 || values[0] == "" {
		return "", NewProfileSignatureError(missingReason)
	}
	return values[0], nil
}

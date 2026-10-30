package mycelium

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Strict, local verification of the downstream profile signature.
//
// Contract (shared with the gateway, the Python, JavaScript and Rust
// verifiers):
//
//   - x-mycelium-profile-signature is a compact JWS, alg EdDSA, with the key
//     version as kid in the protected header;
//   - claims {iat, ph, aud}: ph is the unpadded Base64URL SHA-256 of the exact
//     x-mycelium-profile value; iat is checked against a symmetric, inclusive
//     tolerance window; aud is compared only when an audience is configured.
//
// Checks run in a fixed precedence so every verifier reports the same reason.
// The profile is only decoded after the signature, claims, time window and
// hash are accepted. No network, file or environment access happens here.

var (
	forbiddenHeaderMembers = []string{"crit", "b64", "jku", "jwk", "x5u", "x5c"}
	canonicalUnsigned      = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	segmentEncoding        = base64.RawURLEncoding.Strict()
)

const encodedDigestLength = 43

// ProfileHeaderHash returns the unpadded Base64URL SHA-256 of the exact
// profile header value (the ph claim).
func ProfileHeaderHash(profileHeader string) string {
	digest := sha256.Sum256([]byte(profileHeader))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// VerifyProfileSignature verifies that signatureHeader authenticates
// profileHeader at the current time. It returns a *ProfileSignatureError
// with a stable Reason on rejection and does not decode the profile.
func (v *ProfileSignatureVerifier) VerifyProfileSignature(profileHeader, signatureHeader string) error {
	return v.VerifyProfileSignatureAt(profileHeader, signatureHeader, currentSeconds())
}

// VerifyProfileSignatureAt is VerifyProfileSignature with an explicit clock,
// in Unix seconds.
func (v *ProfileSignatureVerifier) VerifyProfileSignatureAt(profileHeader, signatureHeader string, nowSeconds uint64) error {
	if profileHeader == "" {
		return NewProfileSignatureError(ReasonMissingProfile)
	}

	parts, err := splitToken(signatureHeader)
	if err != nil {
		return err
	}
	key, err := v.selectKey(parts[0])
	if err != nil {
		return err
	}
	payload, err := verifySegments(parts, key)
	if err != nil {
		return err
	}
	claims, err := parseClaims(payload)
	if err != nil {
		return err
	}
	return v.checkClaims(claims, profileHeader, nowSeconds)
}

// VerifyAndDecodeProfile verifies the signature, then decodes the profile
// (invalid_profile when the authenticated header does not decode).
func (v *ProfileSignatureVerifier) VerifyAndDecodeProfile(profileHeader, signatureHeader string) (*Profile, error) {
	return v.VerifyAndDecodeProfileAt(profileHeader, signatureHeader, currentSeconds())
}

// VerifyAndDecodeProfileAt is VerifyAndDecodeProfile with an explicit clock.
func (v *ProfileSignatureVerifier) VerifyAndDecodeProfileAt(profileHeader, signatureHeader string, nowSeconds uint64) (*Profile, error) {
	if err := v.VerifyProfileSignatureAt(profileHeader, signatureHeader, nowSeconds); err != nil {
		return nil, err
	}

	profile, err := DecodeAndDecompressProfileFromBase64(profileHeader)
	if err != nil {
		return nil, NewProfileSignatureError(ReasonInvalidProfile)
	}
	return profile, nil
}

func currentSeconds() uint64 {
	return uint64(time.Now().Unix())
}

func splitToken(signatureHeader string) ([]string, error) {
	if signatureHeader == "" {
		return nil, NewProfileSignatureError(ReasonMissingSignature)
	}

	parts := strings.Split(signatureHeader, ".")
	if len(signatureHeader) > MaxProfileSignatureBytes || len(parts) != 3 {
		return nil, NewProfileSignatureError(ReasonMalformedSignature)
	}
	return parts, nil
}

// decodeSegment decodes strict, unpadded Base64URL. The standard decoder
// skips CR/LF, which a strict verifier must not tolerate.
func decodeSegment(segment string) ([]byte, error) {
	if strings.ContainsAny(segment, "\r\n") {
		return nil, errors.New("line break in segment")
	}
	return segmentEncoding.DecodeString(segment)
}

func decodeObject(segment string) (map[string]json.RawMessage, bool) {
	raw, err := decodeSegment(segment)
	if err != nil {
		return nil, false
	}

	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil || members == nil {
		return nil, false
	}
	return members, true
}

func stringMember(members map[string]json.RawMessage, name string) (string, bool) {
	raw, present := members[name]
	if !present {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func (v *ProfileSignatureVerifier) selectKey(headerSegment string) (ed25519.PublicKey, error) {
	header, ok := decodeObject(headerSegment)
	if !ok {
		return nil, NewProfileSignatureError(ReasonMalformedSignature)
	}

	if alg, ok := stringMember(header, "alg"); !ok || alg != "EdDSA" {
		return nil, NewProfileSignatureError(ReasonUnsupportedAlgorithm)
	}
	for _, member := range forbiddenHeaderMembers {
		if _, present := header[member]; present {
			return nil, NewProfileSignatureError(ReasonMalformedSignature)
		}
	}

	kid, ok := stringMember(header, "kid")
	key, trusted := v.publicKeys[kid]
	if !ok || !IsCanonicalKeyVersion(kid) || !trusted {
		return nil, NewProfileSignatureError(ReasonUnknownKey)
	}
	return key, nil
}

func verifySegments(parts []string, key ed25519.PublicKey) ([]byte, error) {
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, NewProfileSignatureError(ReasonMalformedSignature)
	}
	signature, err := decodeSegment(parts[2])
	if err != nil {
		return nil, NewProfileSignatureError(ReasonMalformedSignature)
	}

	message := []byte(parts[0] + "." + parts[1])
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, message, signature) {
		return nil, NewProfileSignatureError(ReasonInvalidSignature)
	}
	return payload, nil
}

type signedClaims struct {
	iat uint64
	ph  string
	aud string
}

func parseClaims(payload []byte) (signedClaims, error) {
	invalid := NewProfileSignatureError(ReasonInvalidClaims)

	var members map[string]json.RawMessage
	if json.Unmarshal(payload, &members) != nil || members == nil {
		return signedClaims{}, invalid
	}

	iat, iatOK := safeTimestamp(members["iat"])
	ph, phOK := stringMember(members, "ph")
	aud, audOK := stringMember(members, "aud")
	if !iatOK || !phOK || !isCanonicalHash(ph) || !audOK || strings.TrimSpace(aud) == "" {
		return signedClaims{}, invalid
	}
	return signedClaims{iat: iat, ph: ph, aud: aud}, nil
}

// safeTimestamp accepts only a JSON integer literal in [0, 2^53 - 1]:
// floats, exponents, strings, booleans and negatives are rejected.
func safeTimestamp(raw json.RawMessage) (uint64, bool) {
	literal := string(bytes.TrimSpace(raw))
	if !canonicalUnsigned.MatchString(literal) {
		return 0, false
	}
	value, err := strconv.ParseUint(literal, 10, 64)
	return value, err == nil && value <= MaxSafeTimestampSeconds
}

func isCanonicalHash(value string) bool {
	if len(value) != encodedDigestLength {
		return false
	}
	raw, err := decodeSegment(value)
	return err == nil && len(raw) == sha256.Size &&
		base64.RawURLEncoding.EncodeToString(raw) == value
}

func (v *ProfileSignatureVerifier) checkClaims(claims signedClaims, profileHeader string, nowSeconds uint64) error {
	if absoluteDifference(nowSeconds, claims.iat) > v.toleranceSeconds {
		return NewProfileSignatureError(ReasonTimestampOutOfTolerance)
	}

	received := ProfileHeaderHash(profileHeader)
	if subtle.ConstantTimeCompare([]byte(received), []byte(claims.ph)) != 1 {
		return NewProfileSignatureError(ReasonProfileHashMismatch)
	}

	if expected, ok := v.ExpectedAudience(); ok && claims.aud != expected {
		return NewProfileSignatureError(ReasonAudienceMismatch)
	}
	return nil
}

func absoluteDifference(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

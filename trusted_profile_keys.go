package mycelium

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
)

// jwksSetting labels configuration errors about a published key set.
const jwksSetting = "profile JWKS"

// TrustedProfileKeys holds the Ed25519 public keys a downstream service
// trusts, by key version (the JWS kid).
//
// It is read from the gateway profile JWKS and is immutable. The document is
// accepted or refused as a whole: one unsafe entry (private member d, other
// key type or curve, wrong length, non-canonical or duplicated kid) refuses
// the set, so a verifier keeps its last valid one instead of trusting a
// partial set.
type TrustedProfileKeys struct {
	keys map[string]ed25519.PublicKey
}

func emptyTrustedProfileKeys() *TrustedProfileKeys {
	return &TrustedProfileKeys{keys: map[string]ed25519.PublicKey{}}
}

// ParseTrustedProfileKeys parses a JWKS document ({"keys": [...]}). It
// returns a *ProfileSignatureConfigurationError when the set is refused.
func ParseTrustedProfileKeys(document []byte) (*TrustedProfileKeys, error) {
	var top map[string]json.RawMessage
	if json.Unmarshal(document, &top) != nil {
		return nil, invalidJWKS("is not a JSON object")
	}

	var entries []json.RawMessage
	if json.Unmarshal(top["keys"], &entries) != nil || len(entries) == 0 {
		return nil, invalidJWKS("has no keys array")
	}

	keys := map[string]ed25519.PublicKey{}
	for _, entry := range entries {
		kid, key, err := parseEd25519JWK(entry)
		if err != nil {
			return nil, err
		}
		if _, duplicated := keys[kid]; duplicated {
			return nil, invalidJWKS("has a duplicated kid")
		}
		keys[kid] = key
	}
	return &TrustedProfileKeys{keys: keys}, nil
}

// Len returns the number of trusted keys.
func (k *TrustedProfileKeys) Len() int { return len(k.keys) }

// Has reports whether kid selects a trusted key.
func (k *TrustedProfileKeys) Has(kid string) bool {
	_, ok := k.keys[kid]
	return ok
}

func (k *TrustedProfileKeys) keyFor(kid string) (ed25519.PublicKey, bool) {
	if !IsCanonicalKeyVersion(kid) {
		return nil, false
	}
	key, ok := k.keys[kid]
	return key, ok
}

// parseEd25519JWK reads one entry: kty OKP, crv Ed25519, canonical kid,
// 32-byte unpadded Base64URL x; use and alg optional but, when present, sig
// and EdDSA; never d. Unknown members are ignored (RFC 7517).
func parseEd25519JWK(raw json.RawMessage) (string, ed25519.PublicKey, error) {
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil || members == nil {
		return "", nil, invalidJWKS("entry is not a JSON object")
	}
	if _, private := members["d"]; private {
		return "", nil, invalidJWKS("entry carries private key material (d)")
	}

	for _, rule := range []struct {
		name, expected string
		required       bool
	}{{"kty", "OKP", true}, {"crv", "Ed25519", true}, {"use", "sig", false}, {"alg", "EdDSA", false}} {
		if err := expectMember(members, rule.name, rule.expected, rule.required); err != nil {
			return "", nil, err
		}
	}

	kid, ok := stringMember(members, "kid")
	if !ok || !IsCanonicalKeyVersion(kid) {
		return "", nil, invalidJWKS("entry kid must be a canonical positive integer")
	}
	key, err := decodeJWKPublicKey(members)
	return kid, key, err
}

func expectMember(members map[string]json.RawMessage, name, expected string, required bool) error {
	if _, present := members[name]; !present && !required {
		return nil
	}
	if value, ok := stringMember(members, name); ok && value == expected {
		return nil
	}
	return invalidJWKS("entry member " + name + " must be " + expected)
}

func decodeJWKPublicKey(members map[string]json.RawMessage) (ed25519.PublicKey, error) {
	x, ok := stringMember(members, "x")
	if !ok || strings.ContainsAny(x, "\r\n") {
		return nil, invalidJWKS("entry x must be a 32-byte Base64URL key")
	}
	raw, err := segmentEncoding.DecodeString(x)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, invalidJWKS("entry x must be a 32-byte Base64URL key")
	}
	return ed25519.PublicKey(raw), nil
}

func invalidJWKS(problem string) error {
	return NewProfileSignatureConfigurationError(jwksSetting + " " + problem)
}

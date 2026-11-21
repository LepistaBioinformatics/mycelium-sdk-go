package mycelium

import (
	"context"
	"errors"
)

// VerifyProfileSignature verifies that signatureHeader authenticates
// profileHeader at the current time with the cached gateway keys. It
// returns a *ProfileSignatureError with a stable Reason on rejection and
// does not decode the profile.
func (v *ProfileSignatureVerifier) VerifyProfileSignature(ctx context.Context, profileHeader, signatureHeader string) error {
	return v.VerifyProfileSignatureAt(ctx, profileHeader, signatureHeader, currentSeconds())
}

// VerifyProfileSignatureAt is VerifyProfileSignature with an explicit clock,
// in Unix seconds.
func (v *ProfileSignatureVerifier) VerifyProfileSignatureAt(ctx context.Context, profileHeader, signatureHeader string, nowSeconds uint64) error {
	return v.withCurrentKeys(ctx, signatureHeader, func(rules signatureRules) error {
		return rules.verifyAt(profileHeader, signatureHeader, nowSeconds)
	})
}

// VerifyAndDecodeProfile verifies the signature, then decodes the profile
// (invalid_profile when the authenticated header does not decode).
func (v *ProfileSignatureVerifier) VerifyAndDecodeProfile(ctx context.Context, profileHeader, signatureHeader string) (*Profile, error) {
	return v.VerifyAndDecodeProfileAt(ctx, profileHeader, signatureHeader, currentSeconds())
}

// VerifyAndDecodeProfileAt is VerifyAndDecodeProfile with an explicit clock.
func (v *ProfileSignatureVerifier) VerifyAndDecodeProfileAt(ctx context.Context, profileHeader, signatureHeader string, nowSeconds uint64) (*Profile, error) {
	var profile *Profile
	err := v.withCurrentKeys(ctx, signatureHeader, func(rules signatureRules) error {
		decoded, err := rules.verifyAndDecodeAt(profileHeader, signatureHeader, nowSeconds)
		profile = decoded
		return err
	})
	return profile, err
}

// withCurrentKeys refreshes an expired key set, runs check with the cached
// keys and, on unknown_key for a canonical kid, refetches once (subject to
// the cooldown) and runs check again with the newer keys.
func (v *ProfileSignatureVerifier) withCurrentKeys(ctx context.Context, signatureHeader string, check func(signatureRules) error) error {
	v.store.refreshIfStale(ctx)
	keys, generation := v.store.current()

	err := check(v.rules(keys))
	if !deservesRefetch(err, signatureHeader) || !v.store.refreshAfterUnknownKey(ctx, generation) {
		return err
	}

	keys, _ = v.store.current()
	return check(v.rules(keys))
}

func (v *ProfileSignatureVerifier) rules(keys *TrustedProfileKeys) signatureRules {
	audience := v.expectedAudience
	return signatureRules{keys: keys, toleranceSeconds: v.toleranceSeconds, expectedAudience: &audience}
}

func deservesRefetch(err error, signatureHeader string) bool {
	var rejection *ProfileSignatureError
	if !errors.As(err, &rejection) || rejection.Reason != ReasonUnknownKey {
		return false
	}
	_, canonical := readSignatureKeyVersion(signatureHeader)
	return canonical
}

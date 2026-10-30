package mycelium

import (
	"net/http"
	"strconv"
	"testing"
)

// enforcementVerifier trusts key 1 with a tolerance wide enough for the fixed
// vector clock, so the real-time checks accept the contract signature.
func enforcementVerifier(t *testing.T, corpus signatureCorpus) *ProfileSignatureVerifier {
	t.Helper()
	verifier, err := LoadProfileSignatureVerifierFromEnv(map[string]string{
		ProfilePublicKeyEnvPrefix + "1": corpus.PublicKeys["1"],
		ProfileSignatureToleranceEnv:    strconv.FormatUint(MaxSafeTimestampSeconds, 10),
	})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return verifier
}

func signedHeader(vector signatureVector) http.Header {
	header := http.Header{}
	header.Set(DefaultProfileKey, vector.ProfileHeader)
	header.Set(DefaultProfileSignatureKey, vector.Signature)
	return header
}

func TestEnforcementAcceptsTheGatewaySignature(t *testing.T) {
	corpus := readCorpus(t)
	outcome := EnforceProfileSignature(signedHeader(corpus.Vectors[0]), enforcementVerifier(t, corpus))

	if !outcome.Enabled || outcome.Profile == nil || outcome.Reason != "" {
		t.Fatalf("outcome = %+v, want accepted", outcome)
	}
}

func TestEnforcementRefusesWithGenericDetails(t *testing.T) {
	corpus := readCorpus(t)
	valid := corpus.Vectors[0]

	cases := map[string]http.Header{}

	unsigned := http.Header{}
	unsigned.Set(DefaultProfileKey, valid.ProfileHeader)
	cases[ReasonMissingSignature] = unsigned

	signatureOnly := http.Header{}
	signatureOnly.Set(DefaultProfileSignatureKey, valid.Signature)
	cases[ReasonMissingProfile] = signatureOnly

	duplicated := signedHeader(valid)
	duplicated.Add(DefaultProfileKey, valid.ProfileHeader)
	cases[ReasonDuplicateHeader] = duplicated

	folded := signedHeader(valid)
	folded.Set(DefaultProfileSignatureKey, valid.Signature+", "+valid.Signature)
	cases[ReasonDuplicateHeader+"_folded"] = folded

	tampered := signedHeader(valid)
	tampered.Set(DefaultProfileKey, valid.ProfileHeader+"A")
	cases[ReasonProfileHashMismatch] = tampered

	for name, header := range cases {
		outcome := EnforceProfileSignature(header, enforcementVerifier(t, corpus))
		if outcome.Status != http.StatusForbidden || outcome.Detail != SignatureRejectionDetail || outcome.Profile != nil {
			t.Errorf("%s: outcome = %+v", name, outcome)
		}
	}
}

func TestEnforcementDisabledWithoutConfiguration(t *testing.T) {
	ResetProfileSignatureConfiguration()
	t.Cleanup(ResetProfileSignatureConfiguration)

	if outcome := EnforceProfileSignature(http.Header{}, nil); outcome.Enabled {
		t.Fatalf("outcome = %+v, want disabled", outcome)
	}
}

func TestEnforcementInvalidConfigurationFailsClosed(t *testing.T) {
	ResetProfileSignatureConfiguration()
	t.Cleanup(ResetProfileSignatureConfiguration)
	t.Setenv("MYC_PROFILE_PUBLIC_KEY_1", "not a key")

	outcome := EnforceProfileSignature(http.Header{}, nil)
	if outcome.Status != http.StatusInternalServerError || outcome.Reason != ReasonConfigurationInvalid {
		t.Fatalf("outcome = %+v, want 500", outcome)
	}
}

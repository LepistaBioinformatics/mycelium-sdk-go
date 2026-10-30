package mycelium

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"
)

// testdata/profile-signature/vectors.json is a byte-for-byte copy of the
// gateway contract (mycelium-api-gateway/lib/http_tools/test/mock/
// profile-signature/vectors.json), produced by the gateway's real encoder and
// signer. The Python, JavaScript and Rust verifiers run the same corpus.

const (
	vectorsPath        = "testdata/profile-signature/vectors.json"
	gatewayVectorsPath = "../mycelium-api-gateway/lib/http_tools/test/mock/profile-signature/vectors.json"
)

type signatureCorpus struct {
	PublicKeys map[string]string `json:"publicKeys"`
	Vectors    []signatureVector `json:"vectors"`
}

type signatureVector struct {
	Name               string   `json:"name"`
	ProfileHeader      string   `json:"profileHeader"`
	Signature          string   `json:"signature"`
	TrustedKeyVersions []string `json:"trustedKeyVersions"`
	NowSeconds         uint64   `json:"nowSeconds"`
	ToleranceSeconds   uint64   `json:"toleranceSeconds"`
	ExpectedAudience   *string  `json:"expectedAudience"`
	Expected           string   `json:"expected"`
}

func readCorpus(t *testing.T) signatureCorpus {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var corpus signatureCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return corpus
}

func vectorVerifier(t *testing.T, corpus signatureCorpus, vector signatureVector) *ProfileSignatureVerifier {
	t.Helper()
	environ := map[string]string{
		ProfileSignatureToleranceEnv: strconv.FormatUint(vector.ToleranceSeconds, 10),
	}
	for _, version := range vector.TrustedKeyVersions {
		environ[ProfilePublicKeyEnvPrefix+version] = corpus.PublicKeys[version]
	}
	if vector.ExpectedAudience != nil {
		environ[ProfileSignatureAudienceEnv] = *vector.ExpectedAudience
	}

	verifier, err := LoadProfileSignatureVerifierFromEnv(environ)
	if err != nil || verifier == nil {
		t.Fatalf("%s: build verifier: %v", vector.Name, err)
	}
	return verifier
}

func outcomeOf(err error) string {
	if err == nil {
		return "valid"
	}
	var rejection *ProfileSignatureError
	if errors.As(err, &rejection) {
		return rejection.Reason
	}
	return "unexpected: " + err.Error()
}

func TestContractEveryVectorHasTheExpectedOutcome(t *testing.T) {
	corpus := readCorpus(t)
	if len(corpus.Vectors) != 46 {
		t.Fatalf("vectors = %d, want 46", len(corpus.Vectors))
	}

	for _, vector := range corpus.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			_, err := vectorVerifier(t, corpus, vector).VerifyAndDecodeProfileAt(
				vector.ProfileHeader, vector.Signature, vector.NowSeconds)

			if got := outcomeOf(err); got != vector.Expected {
				t.Errorf("outcome = %s, want %s", got, vector.Expected)
			}
		})
	}
}

func TestContractValidVectorDecodesTheSignedAccount(t *testing.T) {
	corpus := readCorpus(t)
	vector := corpus.Vectors[0]

	profile, err := vectorVerifier(t, corpus, vector).VerifyAndDecodeProfileAt(
		vector.ProfileHeader, vector.Signature, vector.NowSeconds)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if profile.AccID.String() != "11111111-1111-4111-8111-111111111111" || !profile.IsStaff {
		t.Errorf("unexpected profile: %+v", profile)
	}
}

func TestContractFixtureCopyMatchesGatewayOutput(t *testing.T) {
	gateway, err := os.ReadFile(gatewayVectorsPath)
	if err != nil {
		t.Skip("gateway checkout not available")
	}
	local, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	normalize := func(raw []byte) [32]byte {
		return sha256.Sum256(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")))
	}
	if normalize(local) != normalize(gateway) {
		t.Error("testdata vectors differ from the gateway fixture; copy it byte for byte")
	}
}

package mycelium

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
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

// jwkOfPEM converts a corpus SPKI PEM to the JWK the gateway publishes.
func jwkOfPEM(t *testing.T, version, publicPEM string) map[string]string {
	t.Helper()
	block, _ := pem.Decode([]byte(publicPEM))
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", version, err)
	}
	return map[string]string{
		"kty": "OKP", "crv": "Ed25519", "kid": version,
		"x": base64.RawURLEncoding.EncodeToString(parsed.(ed25519.PublicKey)),
	}
}

func vectorRules(t *testing.T, corpus signatureCorpus, vector signatureVector) signatureRules {
	t.Helper()
	jwks := []map[string]string{}
	for _, version := range vector.TrustedKeyVersions {
		jwks = append(jwks, jwkOfPEM(t, version, corpus.PublicKeys[version]))
	}
	document, _ := json.Marshal(map[string]any{"keys": jwks})
	keys, err := ParseTrustedProfileKeys(document)
	if err != nil {
		t.Fatalf("%s: keys: %v", vector.Name, err)
	}
	return signatureRules{
		keys:             keys,
		toleranceSeconds: vector.ToleranceSeconds,
		expectedAudience: vector.ExpectedAudience,
	}
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
			_, err := vectorRules(t, corpus, vector).verifyAndDecodeAt(
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

	profile, err := vectorRules(t, corpus, vector).verifyAndDecodeAt(
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

package mycelium

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TEST ONLY: RFC 8032 section 7.1 test vectors 1 and 2 (PKCS#8).
var testPrivatePEMs = map[uint32]string{
	1: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n",
	2: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIEzNCJso/5banbbDRuwRTg9bijGfNaumJNqM9u1PuKb7\n-----END PRIVATE KEY-----\n",
}

const testAudience = "svc"

func isConfigurationError(err error) bool {
	var configErr *ProfileSignatureConfigurationError
	return errors.As(err, &configErr) && configErr.Code == ProfileSignatureConfigInvalidCode
}

func testPrivateKey(t testing.TB, version uint32) ed25519.PrivateKey {
	t.Helper()
	block, _ := pem.Decode([]byte(testPrivatePEMs[version]))
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("key %d: %v", version, err)
	}
	return key.(ed25519.PrivateKey)
}

// testJWKS is the JWKS the gateway would publish for the given versions.
func testJWKS(t testing.TB, versions ...uint32) []byte {
	t.Helper()
	keys := []map[string]string{}
	for _, version := range versions {
		public := testPrivateKey(t, version).Public().(ed25519.PublicKey)
		keys = append(keys, map[string]string{
			"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
			"kid": strconv.FormatUint(uint64(version), 10),
			"x":   base64.RawURLEncoding.EncodeToString(public),
		})
	}
	document, _ := json.Marshal(map[string]any{"keys": keys})
	return document
}

// signedPair returns a (profile header, signature header) pair signed now
// with the given key version, like the gateway does.
func signedPair(t testing.TB, version uint32) (string, string) {
	t.Helper()
	profileHeader, err := CompressAndEncodeProfileToBase64(&Profile{AccID: uuid.Nil, IsStaff: true})
	if err != nil {
		t.Fatal(err)
	}
	encode := func(value any) string {
		raw, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	protected := encode(map[string]string{
		"typ": "JWT", "alg": "EdDSA", "kid": strconv.FormatUint(uint64(version), 10),
	})
	claims := encode(map[string]any{
		"iat": time.Now().Unix(), "ph": ProfileHeaderHash(profileHeader), "aud": testAudience,
	})
	signature := ed25519.Sign(testPrivateKey(t, version), []byte(protected+"."+claims))
	return profileHeader, protected + "." + claims + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// fakeGateway publishes a key set that tests can change, and counts fetches.
// A nil set makes every fetch fail (gateway down).
type fakeGateway struct {
	t        testing.TB
	mu       sync.Mutex
	versions []uint32
	down     bool
	maxAge   time.Duration
	fetches  atomic.Int64
}

func newFakeGateway(t testing.TB, maxAge time.Duration, versions ...uint32) *fakeGateway {
	return &fakeGateway{t: t, versions: versions, maxAge: maxAge}
}

func (g *fakeGateway) publish(versions ...uint32) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.versions, g.down = versions, false
}

func (g *fakeGateway) goDown() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.down = true
}

func (g *fakeGateway) fetcher() ProfileJWKSFetcher {
	return func(context.Context, string) (FetchedProfileJWKS, error) {
		g.fetches.Add(1)
		g.mu.Lock()
		versions, down := append([]uint32(nil), g.versions...), g.down
		g.mu.Unlock()

		if down {
			return FetchedProfileJWKS{}, errors.New("gateway down")
		}
		keys, err := ParseTrustedProfileKeys(testJWKS(g.t, versions...))
		return FetchedProfileJWKS{Keys: keys, MaxAge: g.maxAge}, err
	}
}

func (g *fakeGateway) verifier(t testing.TB, cooldown time.Duration) *ProfileSignatureVerifier {
	t.Helper()
	verifier, err := LoadProfileSignatureVerifierFromEnv(map[string]string{
		ProfileJWKSURLEnv:           "https://gateway.test/jwks.json",
		ProfileSignatureAudienceEnv: testAudience,
	}, WithJWKSFetcher(g.fetcher()), WithJWKSRefetchCooldown(cooldown))
	if err != nil || verifier == nil {
		t.Fatalf("verifier: %v", err)
	}
	return verifier
}

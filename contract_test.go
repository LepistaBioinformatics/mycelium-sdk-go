package mycelium

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
)

// The fixture at testdata/large-profile.json is shared byte-for-byte with the
// Python SDK contract test (mycelium-sdk-py). It is the canonical wire JSON the
// gateway emits: camelCase keys, perm as "read"/"write", Records form.

const (
	fixtureAccID    = "5490dc55-60a2-4049-bfa3-8bedd21fd68a"
	fixtureTenantID = "17fe5508-462f-45f9-bcf0-8ddd80547833"
	fixtureRecords  = 131
)

func readFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/large-profile.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return raw
}

func TestContractDecodeGatewayEncodedProfile(t *testing.T) {
	raw := readFixture(t)

	// Emulate the gateway header: JSON -> ZSTD -> Base64.
	encoded := base64.StdEncoding.EncodeToString(getZstdEncoder().EncodeAll(raw, nil))

	p, err := DecodeAndDecompressProfileFromBase64(encoded)
	if err != nil {
		t.Fatalf("decode gateway-encoded fixture: %v", err)
	}

	if p.AccID != uuid.MustParse(fixtureAccID) {
		t.Errorf("accId = %v, want %s", p.AccID, fixtureAccID)
	}
	if !p.IsManager || p.IsStaff {
		t.Errorf("isManager/isStaff = %v/%v, want true/false", p.IsManager, p.IsStaff)
	}
	if p.VerboseStatus == nil || *p.VerboseStatus != VerboseStatusUnverified {
		t.Errorf("verboseStatus = %v, want unverified", p.VerboseStatus)
	}
	if len(p.Owners) != 1 || p.Owners[0].Email != "user@biotrop.com.br" {
		t.Errorf("owners = %+v", p.Owners)
	}
	if p.LicensedResources == nil {
		t.Fatal("expected licensed resources")
	}
	if got := len(p.LicensedResources.ToLicensesVector()); got != fixtureRecords {
		t.Errorf("licensed records = %d, want %d", got, fixtureRecords)
	}
	if p.TenantsOwnership == nil || len(p.TenantsOwnership.ToOwnershipVector()) != 1 {
		t.Fatalf("expected 1 tenant ownership, got %+v", p.TenantsOwnership)
	}
	own := p.TenantsOwnership.ToOwnershipVector()[0]
	if own.ID != uuid.MustParse(fixtureTenantID) || own.Since.IsZero() {
		t.Errorf("ownership mismatch: %+v", own)
	}
}

func TestContractMethodsOnFixture(t *testing.T) {
	var p Profile
	if err := json.Unmarshal(readFixture(t), &p); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	// Manager profile resolves to manager privileges.
	ra, err := p.GetRelatedAccountOrError()
	if err != nil || ra.Kind != RelatedAccountsHasManagerPrivileges {
		t.Errorf("GetRelatedAccountOrError = %+v, %v", ra, err)
	}

	// Scoping to the fixture tenant retains records.
	scoped := p.OnTenant(uuid.MustParse(fixtureTenantID))
	if scoped.LicensedResources == nil || len(scoped.LicensedResources.ToLicensesVector()) == 0 {
		t.Error("expected records after scoping to fixture tenant")
	}

	// Tenant ownership is recognized.
	if _, err := p.WithTenantOwnershipOrError(uuid.MustParse(fixtureTenantID)); err != nil {
		t.Errorf("WithTenantOwnershipOrError = %v", err)
	}
}

// TestContractDecodePythonEncodedProfile is the true cross-language check: it
// decodes bytes produced by the *Python* SDK's encoder (committed as
// testdata/cross_python_encoded.b64), not a Go self-round-trip. If Python and Go
// ever drift on the wire format, this fails.
func TestContractDecodePythonEncodedProfile(t *testing.T) {
	blob, err := os.ReadFile("testdata/cross_python_encoded.b64")
	if err != nil {
		t.Fatalf("read python-encoded blob: %v", err)
	}

	p, err := DecodeAndDecompressProfileFromBase64(string(blob))
	if err != nil {
		t.Fatalf("Go failed to decode Python-encoded profile: %v", err)
	}
	if p.AccID != uuid.MustParse(fixtureAccID) {
		t.Errorf("accId = %v, want %s", p.AccID, fixtureAccID)
	}
	if p.LicensedResources == nil || len(p.LicensedResources.ToLicensesVector()) != fixtureRecords {
		t.Errorf("licensed records mismatch decoding Python bytes")
	}
	if p.TenantsOwnership == nil || len(p.TenantsOwnership.ToOwnershipVector()) != 1 {
		t.Errorf("tenant ownership mismatch decoding Python bytes")
	}
}

func TestContractRoundTripFixture(t *testing.T) {
	var p Profile
	if err := json.Unmarshal(readFixture(t), &p); err != nil {
		t.Fatal(err)
	}
	encoded, err := CompressAndEncodeProfileToBase64(&p)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeAndDecompressProfileFromBase64(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if back.AccID != p.AccID || len(back.LicensedResources.ToLicensesVector()) != fixtureRecords {
		t.Errorf("round-trip mismatch: %v / %d", back.AccID, len(back.LicensedResources.ToLicensesVector()))
	}
}

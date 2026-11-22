package mycelium

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

var (
	issuerA = uuid.MustParse("12121212-1212-4121-8121-121212121212")
	issuerB = uuid.MustParse("34343434-3434-4343-8343-343434343434")
)

func federatedProfile() Profile {
	p := profileWith(res(tenantA, accX, "reader", PermissionRead))
	p.FederatedResources = []FederatedResource{
		{Issuer: issuerA, LicensedResource: res(tenantB, accY, "reader", PermissionRead)},
		{Issuer: issuerB, LicensedResource: res(tenantB, accY, "reader", PermissionWrite)},
	}
	return p
}

func countLicensed(p Profile) int {
	if p.LicensedResources == nil {
		return 0
	}
	return len(p.LicensedResources.ToLicensesVector())
}

func TestFederatedResourcesRoundTripFlatWithIssuer(t *testing.T) {
	p := federatedProfile()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	var items []map[string]any
	if err := json.Unmarshal(raw["federatedResources"], &items); err != nil {
		t.Fatalf("federatedResources is not a flat array: %v", err)
	}
	if items[0]["issuer"] != issuerA.String() || items[0]["accId"] != accY.String() || items[0]["perm"] != "read" {
		t.Errorf("unexpected element: %v", items[0])
	}
	if _, nested := items[0]["LicensedResource"]; nested {
		t.Error("grant fields must be flattened")
	}

	var back Profile
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.FederatedResources, p.FederatedResources) {
		t.Errorf("round trip mismatch: %+v", back.FederatedResources)
	}

	local, _ := json.Marshal(profileWith(res(tenantA, accX, "reader", PermissionRead)))
	var localRaw map[string]json.RawMessage
	_ = json.Unmarshal(local, &localRaw)
	if _, ok := localRaw["federatedResources"]; ok {
		t.Error("federatedResources must be omitted when absent")
	}
}

func TestDefaultChainIgnoresFederatedGrants(t *testing.T) {
	got := federatedProfile().WithRoles([]string{"reader"})
	if countLicensed(got) != 1 || got.LicensedResources.Records[0].AccID != accX {
		t.Errorf("expected only the local grant, got %+v", got.LicensedResources)
	}
	if got := federatedProfile().OnTenant(tenantB); got.LicensedResources != nil {
		t.Errorf("federated tenant must not match by default: %+v", got.LicensedResources)
	}
}

func TestWithFederatedAddsEveryIssuersGrants(t *testing.T) {
	p := federatedProfile()
	got := p.WithFederated()
	if countLicensed(got) != 3 {
		t.Fatalf("expected 3 grants, got %d", countLicensed(got))
	}
	if got.FilteringState[len(got.FilteringState)-1] != "1:withFederated:true" {
		t.Errorf("filteringState = %v", got.FilteringState)
	}
	if countLicensed(p) != 1 {
		t.Error("original profile mutated")
	}
	if got := got.OnTenant(tenantB); countLicensed(got) != 2 {
		t.Errorf("expected 2 federated grants on tenantB, got %d", countLicensed(got))
	}
}

func TestFromIssuerKeepsOnlyThatIssuersGrants(t *testing.T) {
	p := federatedProfile()
	got := p.FromIssuer(issuerB)
	if countLicensed(got) != 1 || got.LicensedResources.Records[0].Perm != PermissionWrite {
		t.Fatalf("expected issuerB's grant only, got %+v", got.LicensedResources)
	}
	if got.FilteringState[0] != "1:issuer:"+issuerB.String() {
		t.Errorf("filteringState = %v", got.FilteringState)
	}

	if got := p.FromIssuer(uuid.New()); got.LicensedResources != nil {
		t.Errorf("unknown issuer must collapse to nil, got %+v", got.LicensedResources)
	}
	if got := profileWith(res(tenantA, accX, "reader", PermissionRead)).FromIssuer(issuerA); got.LicensedResources != nil {
		t.Errorf("profile without federation must collapse to nil, got %+v", got.LicensedResources)
	}
}

func TestContractFederatedVectorDecodes(t *testing.T) {
	var vector *signatureVector
	for _, v := range readCorpus(t).Vectors {
		if v.Name == "valid_with_federated_resources" {
			vector = &v
			break
		}
	}
	if vector == nil {
		t.Fatal("vector valid_with_federated_resources not found")
	}

	profile, err := DecodeAndDecompressProfileFromBase64(vector.ProfileHeader)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	issuer := uuid.MustParse("77777777-7777-4777-8777-777777777777")
	if len(profile.FederatedResources) != 1 || profile.FederatedResources[0].Issuer != issuer ||
		profile.FederatedResources[0].Role != "federated-role" {
		t.Fatalf("unexpected federated resources: %+v", profile.FederatedResources)
	}

	federatedRole := []string{"federated-role"}
	if got := profile.WithRoles(federatedRole); got.LicensedResources != nil {
		t.Errorf("default chain must not see the federated grant: %+v", got.LicensedResources)
	}
	if got := profile.WithFederated().WithRoles(federatedRole); countLicensed(got) != 1 {
		t.Errorf("WithFederated must expose the federated grant, got %d", countLicensed(got))
	}

	if got := profile.WithRoles([]string{"local-role"}); countLicensed(got) != 1 {
		t.Errorf("expected the local-role grant by default, got %d", countLicensed(got))
	}
	fromIssuer := profile.FromIssuer(issuer)
	if countLicensed(fromIssuer) != 1 || fromIssuer.LicensedResources.Records[0].Role != "federated-role" {
		t.Errorf("FromIssuer must keep only the federated grant: %+v", fromIssuer.LicensedResources)
	}
	if got := fromIssuer.WithRoles([]string{"local-role"}); got.LicensedResources != nil {
		t.Errorf("FromIssuer must drop the local grant: %+v", got.LicensedResources)
	}
}

func TestFederatedOptInsOnlyOpenAChain(t *testing.T) {
	p := federatedProfile()

	got := p.OnTenant(tenantA).WithFederated()
	if got.LicensedResources != nil {
		t.Errorf("WithFederated after a filter must fail closed: %+v", got.LicensedResources)
	}
	if len(got.FilteringState) != 2 || got.FilteringState[1] != "2:withFederated:true" {
		t.Errorf("filteringState = %v", got.FilteringState)
	}

	got = p.WithRoles([]string{"reader"}).FromIssuer(issuerA)
	if got.LicensedResources != nil {
		t.Errorf("FromIssuer after a filter must fail closed: %+v", got.LicensedResources)
	}
	if len(got.FilteringState) != 2 || got.FilteringState[1] != "2:issuer:"+issuerA.String() {
		t.Errorf("filteringState = %v", got.FilteringState)
	}

	got = p.WithFederated().OnTenant(tenantB)
	if countLicensed(got) != 2 || got.LicensedResources.Records[0].TenantID != tenantB {
		t.Errorf("WithFederated first must keep the federated grants: %+v", got.LicensedResources)
	}
}

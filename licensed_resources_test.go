package mycelium

import (
	"encoding/json"
	"testing"
)

func TestLicensedResourcesUnmarshalRecords(t *testing.T) {
	data := `{"records":[{"accId":"11111111-1111-1111-1111-111111111111","sysAcc":false,"tenantId":"22222222-2222-2222-2222-222222222222","accName":"n","role":"admin","roleId":"33333333-3333-3333-3333-333333333333","perm":"read","verified":true}]}`
	var lr LicensedResources
	if err := json.Unmarshal([]byte(data), &lr); err != nil {
		t.Fatal(err)
	}
	if lr.Records == nil || len(lr.Records) != 1 || lr.Urls != nil {
		t.Fatalf("expected records variant, got %+v", lr)
	}
	if lr.Records[0].Role != "admin" || lr.Records[0].Perm != PermissionRead {
		t.Errorf("record mismatch: %+v", lr.Records[0])
	}
}

func TestLicensedResourcesUnmarshalUrls(t *testing.T) {
	url := sampleResource().String()
	data := `{"urls":["` + url + `"]}`
	var lr LicensedResources
	if err := json.Unmarshal([]byte(data), &lr); err != nil {
		t.Fatal(err)
	}
	if lr.Urls == nil || len(lr.Urls) != 1 || lr.Records != nil {
		t.Fatalf("expected urls variant, got %+v", lr)
	}
}

func TestLicensedResourcesMarshalRecords(t *testing.T) {
	lr := LicensedResources{Records: []LicensedResource{sampleResource()}}
	b, err := json.Marshal(lr)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(b), `"records"`) || contains(string(b), `"urls"`) {
		t.Errorf("expected records key only, got %s", b)
	}
}

func TestLicensedResourcesMarshalUrls(t *testing.T) {
	lr := LicensedResources{Urls: []string{"t/x"}}
	b, err := json.Marshal(lr)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(b), `"urls"`) || contains(string(b), `"records"`) {
		t.Errorf("expected urls key only, got %s", b)
	}
}

func TestToLicensesVectorRecordsPrecedence(t *testing.T) {
	lr := LicensedResources{
		Records: []LicensedResource{sampleResource()},
		Urls:    []string{"t/x"},
	}
	if got := lr.ToLicensesVector(); len(got) != 1 || got[0].Role != "admin" {
		t.Errorf("records should take precedence, got %+v", got)
	}
}

func TestToLicensesVectorUrls(t *testing.T) {
	lr := LicensedResources{Urls: []string{sampleResource().String()}}
	got := lr.ToLicensesVector()
	if len(got) != 1 || got[0].TenantID != sampleResource().TenantID {
		t.Errorf("url materialization failed: %+v", got)
	}
}

func TestToLicensesVectorSkipsBadUrl(t *testing.T) {
	lr := LicensedResources{Urls: []string{"garbage", sampleResource().String()}}
	if got := lr.ToLicensesVector(); len(got) != 1 {
		t.Errorf("bad url should be skipped, got %d entries", len(got))
	}
}

func TestToLicensesVectorEmpty(t *testing.T) {
	var lr LicensedResources
	if got := lr.ToLicensesVector(); len(got) != 0 {
		t.Errorf("empty should yield 0, got %d", len(got))
	}
}

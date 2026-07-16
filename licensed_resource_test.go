package mycelium

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func sampleResource() LicensedResource {
	pf := []string{"flagA", "flagB"}
	return LicensedResource{
		AccID:       uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		SysAcc:      true,
		TenantID:    uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		AccName:     "Acme Corp",
		Role:        "admin",
		RoleID:      uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		Perm:        PermissionWrite,
		Verified:    true,
		PermitFlags: &pf,
	}
}

func TestLicensedResourceStringRoundTrip(t *testing.T) {
	orig := sampleResource()
	s := orig.String()

	got, err := LicensedResourceFromString(s)
	if err != nil {
		t.Fatalf("FromString(%q) error: %v", s, err)
	}
	if got.AccID != orig.AccID || got.TenantID != orig.TenantID || got.RoleID != orig.RoleID {
		t.Errorf("uuid mismatch: %+v", got)
	}
	if got.AccName != orig.AccName || got.Role != orig.Role || got.Perm != orig.Perm {
		t.Errorf("field mismatch: %+v", got)
	}
	if !got.SysAcc || !got.Verified {
		t.Errorf("bool mismatch: %+v", got)
	}
	if got.PermitFlags == nil || len(*got.PermitFlags) != 2 || (*got.PermitFlags)[0] != "flagA" {
		t.Errorf("permitFlags mismatch: %+v", got.PermitFlags)
	}
}

func TestLicensedResourceStringUsesHexUUIDs(t *testing.T) {
	s := sampleResource().String()
	if want := "t/22222222222222222222222222222222/a/11111111111111111111111111111111/r/33333333333333333333333333333333"; !contains(s, want) {
		t.Errorf("expected hex path, got %q", s)
	}
	if !contains(s, "p=admin:1") {
		t.Errorf("expected perm int in URL, got %q", s)
	}
}

func TestLicensedResourceFromStringNoOptionalFlags(t *testing.T) {
	r := sampleResource()
	r.PermitFlags = nil
	got, err := LicensedResourceFromString(r.String())
	if err != nil {
		t.Fatal(err)
	}
	if got.PermitFlags != nil || got.DenyFlags != nil {
		t.Errorf("expected nil flags, got pf=%v df=%v", got.PermitFlags, got.DenyFlags)
	}
}

func TestLicensedResourceFromStringErrors(t *testing.T) {
	cases := map[string]string{
		"bad path":        "x/1/a/2/r/3?p=admin:1&s=1&v=1&n=QQ==",
		"bad tenant uuid": "t/nothex/a/11111111111111111111111111111111/r/33333333333333333333333333333333?p=admin:1&s=1&v=1&n=QQ==",
		"missing p":       "t/22222222222222222222222222222222/a/11111111111111111111111111111111/r/33333333333333333333333333333333?s=1&v=1&n=QQ==",
		"bad perm format": "t/22222222222222222222222222222222/a/11111111111111111111111111111111/r/33333333333333333333333333333333?p=admin&s=1&v=1&n=QQ==",
		"bad perm code":   "t/22222222222222222222222222222222/a/11111111111111111111111111111111/r/33333333333333333333333333333333?p=admin:9&s=1&v=1&n=QQ==",
		"bad sys flag":    "t/22222222222222222222222222222222/a/11111111111111111111111111111111/r/33333333333333333333333333333333?p=admin:1&s=2&v=1&n=QQ==",
		"missing name":    "t/22222222222222222222222222222222/a/11111111111111111111111111111111/r/33333333333333333333333333333333?p=admin:1&s=1&v=1",
		"bad name base64": "t/22222222222222222222222222222222/a/11111111111111111111111111111111/r/33333333333333333333333333333333?p=admin:1&s=1&v=1&n=!!!",
	}
	for name, in := range cases {
		if _, err := LicensedResourceFromString(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestLicensedResourceJSONPermString(t *testing.T) {
	b, err := json.Marshal(sampleResource())
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(b), `"perm":"write"`) {
		t.Errorf("expected perm as string in JSON, got %s", b)
	}
}

func TestLicensedResourceJSONDecodePermStringAndInt(t *testing.T) {
	base := `{"accId":"11111111-1111-1111-1111-111111111111","sysAcc":false,"tenantId":"22222222-2222-2222-2222-222222222222","accName":"n","role":"r","roleId":"33333333-3333-3333-3333-333333333333","verified":true,`
	for _, permJSON := range []string{`"perm":"read"}`, `"perm":0}`} {
		var lr LicensedResource
		if err := json.Unmarshal([]byte(base+permJSON), &lr); err != nil {
			t.Fatalf("unmarshal %s: %v", permJSON, err)
		}
		if lr.Perm != PermissionRead {
			t.Errorf("%s -> perm %v, want Read", permJSON, lr.Perm)
		}
	}
}

package mycelium

import (
	"testing"

	"github.com/google/uuid"
)

var (
	tenantA = uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	tenantB = uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	accX    = uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")
	accY    = uuid.MustParse("dddddddd-dddd-dddd-dddd-dddddddddddd")
	roleID  = uuid.MustParse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")
)

func res(tenant, acc uuid.UUID, role string, perm Permission) LicensedResource {
	return LicensedResource{
		AccID: acc, SysAcc: false, TenantID: tenant, AccName: "n",
		Role: role, RoleID: roleID, Perm: perm, Verified: true,
	}
}

func profileWith(records ...LicensedResource) Profile {
	return Profile{
		AccID:             uuid.New(),
		LicensedResources: &LicensedResources{Records: records},
	}
}

func TestOnTenantFilters(t *testing.T) {
	p := profileWith(res(tenantA, accX, "admin", PermissionRead), res(tenantB, accY, "admin", PermissionRead))
	got := p.OnTenant(tenantA)
	recs := got.LicensedResources.ToLicensesVector()
	if len(recs) != 1 || recs[0].TenantID != tenantA {
		t.Fatalf("expected 1 tenantA record, got %+v", recs)
	}
	if len(got.FilteringState) != 1 || got.FilteringState[0] != "1:tenantId:"+tenantA.String() {
		t.Errorf("filteringState = %v", got.FilteringState)
	}
	// original not mutated
	if len(p.LicensedResources.ToLicensesVector()) != 2 {
		t.Error("original profile mutated")
	}
}

func TestEmptyFilterCollapsesToNil(t *testing.T) {
	p := profileWith(res(tenantA, accX, "admin", PermissionRead))
	got := p.OnTenant(tenantB) // no match
	if got.LicensedResources != nil {
		t.Errorf("expected nil LicensedResources after empty filter, got %+v", got.LicensedResources)
	}
	if len(got.FilteringState) != 1 {
		t.Errorf("state should still be recorded: %v", got.FilteringState)
	}
}

func TestWithPermissionFiltersAndKeepsWrite(t *testing.T) {
	p := profileWith(
		res(tenantA, accX, "admin", PermissionRead),
		res(tenantA, accY, "admin", PermissionWrite),
	)
	// read access keeps both
	if got := p.WithReadAccess().LicensedResources.ToLicensesVector(); len(got) != 2 {
		t.Errorf("read access should keep 2, got %d", len(got))
	}
	// write access keeps only write
	got := p.WithWriteAccess().LicensedResources.ToLicensesVector()
	if len(got) != 1 || got[0].Perm != PermissionWrite {
		t.Errorf("write access should keep 1 write record, got %+v", got)
	}
}

func TestWithPermissionStateUsesInt(t *testing.T) {
	p := profileWith(res(tenantA, accX, "admin", PermissionWrite))
	got := p.WithWriteAccess()
	if got.FilteringState[0] != "1:permission:1" {
		t.Errorf("expected permission int state, got %q", got.FilteringState[0])
	}
}

func TestWithPermissionNoShortCircuitOnNilLicenses(t *testing.T) {
	// Following the Rust gateway (not JS/Python), withPermission records the
	// state even when there are no licensed resources.
	p := Profile{AccID: uuid.New()}
	got := p.WithReadAccess()
	if got.LicensedResources != nil {
		t.Error("expected nil licenses")
	}
	if len(got.FilteringState) != 1 || got.FilteringState[0] != "1:permission:0" {
		t.Errorf("expected state appended, got %v", got.FilteringState)
	}
}

func TestWithRolesFilters(t *testing.T) {
	p := profileWith(
		res(tenantA, accX, "admin", PermissionRead),
		res(tenantA, accY, "viewer", PermissionRead),
	)
	got := p.WithRoles([]string{"viewer"})
	recs := got.LicensedResources.ToLicensesVector()
	if len(recs) != 1 || recs[0].Role != "viewer" {
		t.Errorf("expected viewer only, got %+v", recs)
	}
	if got.FilteringState[0] != "1:role:viewer" {
		t.Errorf("state = %q", got.FilteringState[0])
	}
}

func TestOnAccountFilters(t *testing.T) {
	p := profileWith(res(tenantA, accX, "admin", PermissionRead), res(tenantA, accY, "admin", PermissionRead))
	if recs := p.OnAccount(accX).LicensedResources.ToLicensesVector(); len(recs) != 1 || recs[0].AccID != accX {
		t.Errorf("expected accX only, got %+v", recs)
	}
}

func TestPermitAndDenyFlags(t *testing.T) {
	pf := []string{"beta", "gamma"}
	df := []string{"blocked"}
	r1 := res(tenantA, accX, "admin", PermissionRead)
	r1.PermitFlags = &pf
	r2 := res(tenantA, accY, "admin", PermissionRead)
	r2.DenyFlags = &df
	p := profileWith(r1, r2)

	// permit: only r1 has both beta+gamma
	if recs := p.HasPermitFlags([]string{"beta", "gamma"}).LicensedResources.ToLicensesVector(); len(recs) != 1 || recs[0].AccID != accX {
		t.Errorf("permit flags filter failed: %+v", recs)
	}
	// deny: r2 has "blocked" -> dropped; r1 has no deny flags -> kept
	if recs := p.HasNotDenyFlags([]string{"blocked"}).LicensedResources.ToLicensesVector(); len(recs) != 1 || recs[0].AccID != accX {
		t.Errorf("deny flags filter failed: %+v", recs)
	}
}

func TestWithSystemAccountsAccess(t *testing.T) {
	r1 := res(tenantA, accX, "admin", PermissionRead)
	r1.SysAcc = true
	r2 := res(tenantA, accY, "admin", PermissionRead)
	p := profileWith(r1, r2)
	if recs := p.WithSystemAccountsAccess().LicensedResources.ToLicensesVector(); len(recs) != 1 || !recs[0].SysAcc {
		t.Errorf("system accounts filter failed: %+v", recs)
	}
}

func TestChainedFiltersAccumulateState(t *testing.T) {
	p := profileWith(res(tenantA, accX, "admin", PermissionWrite))
	got := p.OnTenant(tenantA).WithWriteAccess().OnAccount(accX)
	want := []string{
		"1:tenantId:" + tenantA.String(),
		"2:permission:1",
		"3:accountId:" + accX.String(),
	}
	if len(got.FilteringState) != 3 {
		t.Fatalf("expected 3 state entries, got %v", got.FilteringState)
	}
	for i, w := range want {
		if got.FilteringState[i] != w {
			t.Errorf("state[%d] = %q, want %q", i, got.FilteringState[i], w)
		}
	}
}

func TestProfileStringAndOwners(t *testing.T) {
	id := uuid.New()
	p := Profile{AccID: id, Owners: []Owner{{ID: accX, Email: "ada@x.com", IsPrincipal: true}}}
	if p.ProfileString() != "profile/"+id.String() {
		t.Errorf("ProfileString = %q", p.ProfileString())
	}
	if ids := p.GetOwnersIds(); len(ids) != 1 || ids[0] != accX {
		t.Errorf("GetOwnersIds = %v", ids)
	}
	if got := p.ProfileRedacted(); !contains(got, "a**@x.com") {
		t.Errorf("ProfileRedacted = %q", got)
	}
}

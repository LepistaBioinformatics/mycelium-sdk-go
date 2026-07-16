package mycelium

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHasAdminPrivileges(t *testing.T) {
	if !(Profile{IsStaff: true}).HasAdminPrivileges() {
		t.Error("staff should be admin")
	}
	if !(Profile{IsManager: true}).HasAdminPrivileges() {
		t.Error("manager should be admin")
	}
	if (Profile{}).HasAdminPrivileges() {
		t.Error("plain profile should not be admin")
	}
	if err := (Profile{}).HasAdminPrivilegesOrError(); err == nil {
		t.Error("expected error for non-admin")
	}
	var priv *InsufficientPrivilegesError
	if err := (Profile{}).HasAdminPrivilegesOrError(); !errors.As(err, &priv) {
		t.Error("expected InsufficientPrivilegesError")
	}
}

func TestGetRelatedAccountOrErrorStaff(t *testing.T) {
	ra, err := (Profile{IsStaff: true}).GetRelatedAccountOrError()
	if err != nil || ra.Kind != RelatedAccountsHasStaffPrivileges {
		t.Errorf("staff -> %+v, %v", ra, err)
	}
}

func TestGetRelatedAccountOrErrorManager(t *testing.T) {
	ra, err := (Profile{IsManager: true}).GetRelatedAccountOrError()
	if err != nil || ra.Kind != RelatedAccountsHasManagerPrivileges {
		t.Errorf("manager -> %+v, %v", ra, err)
	}
}

func TestGetRelatedAccountOrErrorAllowedAccounts(t *testing.T) {
	p := profileWith(res(tenantA, accX, "admin", PermissionRead), res(tenantA, accY, "admin", PermissionRead))
	ra, err := p.GetRelatedAccountOrError()
	if err != nil || ra.Kind != RelatedAccountsAllowedAccounts || len(ra.Accounts) != 2 {
		t.Errorf("allowed -> %+v, %v", ra, err)
	}
}

func TestGetRelatedAccountOrErrorEmptyLicensesIsLicenseError(t *testing.T) {
	p := Profile{AccID: uuid.New(), LicensedResources: &LicensedResources{Records: []LicensedResource{}}}
	_, err := p.GetRelatedAccountOrError()
	var lic *InsufficientLicensesError
	if !errors.As(err, &lic) {
		t.Errorf("expected InsufficientLicensesError, got %v", err)
	}
}

func TestGetRelatedAccountOrErrorNoLicensesIsPrivilegeError(t *testing.T) {
	p := Profile{AccID: uuid.New()}
	_, err := p.GetRelatedAccountOrError()
	var priv *InsufficientPrivilegesError
	if !errors.As(err, &priv) {
		t.Errorf("expected InsufficientPrivilegesError, got %v", err)
	}
}

func TestGetIdsOrError(t *testing.T) {
	p := profileWith(res(tenantA, accX, "admin", PermissionRead))
	ids, err := p.GetIdsOrError()
	if err != nil || len(ids) != 1 || ids[0] != accX {
		t.Errorf("ids -> %v, %v", ids, err)
	}

	// admin with no licenses -> ok, empty ids
	if ids, err := (Profile{IsStaff: true}).GetIdsOrError(); err != nil || len(ids) != 0 {
		t.Errorf("admin ids -> %v, %v", ids, err)
	}

	// no ids, no admin -> error
	if _, err := (Profile{}).GetIdsOrError(); err == nil {
		t.Error("expected error for no ids / no admin")
	}
}

func TestWithTenantOwnershipOrError(t *testing.T) {
	own := TenantOwnership{ID: tenantA, Name: "n", Since: time.Now().UTC()}
	p := Profile{AccID: uuid.New(), TenantsOwnership: &TenantsOwnership{Records: []TenantOwnership{own}}}

	got, err := p.WithTenantOwnershipOrError(tenantA)
	if err != nil {
		t.Fatalf("expected ownership, got %v", err)
	}
	if len(got.FilteringState) != 1 || got.FilteringState[0] != "1:tenantOwnership:"+tenantA.String() {
		t.Errorf("state = %v", got.FilteringState)
	}

	if _, err := p.WithTenantOwnershipOrError(tenantB); err == nil {
		t.Error("expected error for non-owned tenant")
	}
}

func TestGetTenantWidePermission(t *testing.T) {
	// staff short-circuit
	if ra, err := (Profile{IsStaff: true}).GetTenantWidePermissionOrError(tenantA, PermissionRead); err != nil || ra.Kind != RelatedAccountsHasStaffPrivileges {
		t.Errorf("staff -> %+v, %v", ra, err)
	}

	// tenant ownership
	own := TenantOwnership{ID: tenantA, Name: "n", Since: time.Now().UTC()}
	p := Profile{AccID: uuid.New(), TenantsOwnership: &TenantsOwnership{Records: []TenantOwnership{own}}}
	ra, err := p.GetTenantWidePermissionOrError(tenantA, PermissionRead)
	if err != nil || ra.Kind != RelatedAccountsHasTenantWidePrivileges || ra.TenantID == nil || *ra.TenantID != tenantA {
		t.Errorf("ownership -> %+v, %v", ra, err)
	}

	// tenant-manager role fallback
	pm := profileWith(res(tenantA, accX, roleTenantManager, PermissionWrite))
	ra, err = pm.GetTenantWidePermissionOrError(tenantA, PermissionWrite)
	if err != nil || ra.Kind != RelatedAccountsHasTenantWidePrivileges {
		t.Errorf("manager-role -> %+v, %v", ra, err)
	}

	// no access -> error
	if _, err := profileWith(res(tenantA, accX, "viewer", PermissionRead)).GetTenantWidePermissionOrError(tenantB, PermissionWrite); err == nil {
		t.Error("expected error for no tenant-wide permission")
	}
}

func TestGetRelatedAccountsOrTenantWideFallback(t *testing.T) {
	// no tenant-wide, but has account licenses -> falls back to AllowedAccounts
	p := profileWith(res(tenantA, accX, "viewer", PermissionRead))
	ra, err := p.GetRelatedAccountsOrTenantWidePermissionOrError(tenantB, PermissionWrite)
	if err != nil || ra.Kind != RelatedAccountsAllowedAccounts {
		t.Errorf("fallback -> %+v, %v", ra, err)
	}
}

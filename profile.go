package mycelium

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// roleTenantManager is the role name checked by OnTenantAsManager, matching the
// gateway's SystemActor::TenantManager.
const roleTenantManager = "tenant-manager"

// Profile is the authenticated identity context injected by the gateway. Its
// fluent filter methods return copies (the receiver is never mutated), matching
// the immutable-chain semantics of the Rust gateway and sibling SDKs.
type Profile struct {
	Owners             []Owner            `json:"owners"`
	AccID              uuid.UUID          `json:"accId"`
	IsSubscription     bool               `json:"isSubscription"`
	IsStaff            bool               `json:"isStaff"`
	IsManager          bool               `json:"isManager"`
	OwnerIsActive      bool               `json:"ownerIsActive"`
	AccountIsActive    bool               `json:"accountIsActive"`
	AccountWasApproved bool               `json:"accountWasApproved"`
	AccountWasArchived bool               `json:"accountWasArchived"`
	AccountWasDeleted  bool               `json:"accountWasDeleted"`
	VerboseStatus      *VerboseStatus     `json:"verboseStatus,omitempty"`
	LicensedResources  *LicensedResources `json:"licensedResources,omitempty"`
	TenantsOwnership   *TenantsOwnership  `json:"tenantsOwnership,omitempty"`
	Meta               map[string]string  `json:"meta,omitempty"`
	FilteringState     []string           `json:"filteringState,omitempty"`
}

// updateState appends a "<index>:<key>:<value>" entry (1-based) to a copy of the
// filtering state and returns the updated Profile copy.
func (p Profile) updateState(key, value string) Profile {
	state := make([]string, len(p.FilteringState), len(p.FilteringState)+1)
	copy(state, p.FilteringState)
	state = append(state, fmt.Sprintf("%d:%s:%s", len(state)+1, key, value))
	p.FilteringState = state
	return p
}

// filterLicensed applies pred to the materialized licensed resources, returning
// a fresh Records union or nil when the profile has no resources or the filter
// yields nothing (the gateway's collapse-empty-to-none rule).
func (p Profile) filterLicensed(pred func(LicensedResource) bool) *LicensedResources {
	if p.LicensedResources == nil {
		return nil
	}
	var records []LicensedResource
	for _, r := range p.LicensedResources.ToLicensesVector() {
		if pred(r) {
			records = append(records, r)
		}
	}
	if len(records) == 0 {
		return nil
	}
	return &LicensedResources{Records: records}
}

// GetOwnersIds returns the ids of the profile owners.
func (p Profile) GetOwnersIds() []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(p.Owners))
	for _, o := range p.Owners {
		ids = append(ids, o.ID)
	}
	return ids
}

// ProfileString returns a stable "profile/<accId>" identifier.
func (p Profile) ProfileString() string {
	return "profile/" + p.AccID.String()
}

// ProfileRedacted returns the profile identifier plus the owner emails with
// their local parts masked.
func (p Profile) ProfileRedacted() string {
	redacted := make([]string, 0, len(p.Owners))
	for _, o := range p.Owners {
		redacted = append(redacted, o.RedactedEmail())
	}
	return fmt.Sprintf("profile/%s owners: [%s]", p.AccID, strings.Join(redacted, ", "))
}

// HasAdminPrivileges reports whether the profile is staff or manager.
func (p Profile) HasAdminPrivileges() bool {
	return p.IsStaff || p.IsManager
}

// HasAdminPrivilegesOrError returns an error when the profile lacks admin
// privileges.
func (p Profile) HasAdminPrivilegesOrError() error {
	if p.HasAdminPrivileges() {
		return nil
	}
	return NewInsufficientPrivilegesError("Current account has no administration privileges", p.FilteringState)
}

// HasPermitFlags keeps resources whose permit_flags contain ALL the given flags.
func (p Profile) HasPermitFlags(flags []string) Profile {
	filtered := p.filterLicensed(func(r LicensedResource) bool {
		if r.PermitFlags == nil {
			return false
		}
		return containsAll(*r.PermitFlags, flags)
	})
	np := p.updateState("permittedFlags", strings.Join(flags, ","))
	np.LicensedResources = filtered
	return np
}

// HasNotDenyFlags keeps resources that have NONE of the given flags in their
// deny_flags (resources with no deny_flags are kept).
func (p Profile) HasNotDenyFlags(flags []string) Profile {
	filtered := p.filterLicensed(func(r LicensedResource) bool {
		if r.DenyFlags == nil {
			return true
		}
		return !containsAny(*r.DenyFlags, flags)
	})
	np := p.updateState("deniedFlags", strings.Join(flags, ","))
	np.LicensedResources = filtered
	return np
}

// OnTenant keeps resources scoped to the given tenant.
func (p Profile) OnTenant(tenantID uuid.UUID) Profile {
	filtered := p.filterLicensed(func(r LicensedResource) bool {
		return r.TenantID == tenantID
	})
	np := p.updateState("tenantId", tenantID.String())
	np.LicensedResources = filtered
	return np
}

// OnTenantAsManager scopes to the tenant with the required permission and the
// tenant-manager role.
func (p Profile) OnTenantAsManager(tenantID uuid.UUID, permission Permission) Profile {
	profile := p.OnTenant(tenantID).withPermission(permission).WithRoles([]string{roleTenantManager})
	return profile.updateState("isTenantManager", "true")
}

// OnAccount keeps resources scoped to the given account.
func (p Profile) OnAccount(accountID uuid.UUID) Profile {
	filtered := p.filterLicensed(func(r LicensedResource) bool {
		return r.AccID == accountID
	})
	np := p.updateState("accountId", accountID.String())
	np.LicensedResources = filtered
	return np
}

// WithSystemAccountsAccess keeps resources belonging to system accounts.
func (p Profile) WithSystemAccountsAccess() Profile {
	filtered := p.filterLicensed(func(r LicensedResource) bool {
		return r.SysAcc
	})
	np := p.updateState("isAccStd", "true")
	np.LicensedResources = filtered
	return np
}

// WithReadAccess keeps resources granting at least read permission.
func (p Profile) WithReadAccess() Profile {
	return p.withPermission(PermissionRead)
}

// WithWriteAccess keeps resources granting write permission.
func (p Profile) WithWriteAccess() Profile {
	return p.withPermission(PermissionWrite)
}

// withPermission keeps resources whose permission is at least the given level.
// Following the gateway, it always records the filter state (no short-circuit)
// and collapses an empty result to no resources.
func (p Profile) withPermission(permission Permission) Profile {
	filtered := p.filterLicensed(func(r LicensedResource) bool {
		return r.Perm.ToInt() >= permission.ToInt()
	})
	np := p.updateState("permission", strconv.Itoa(permission.ToInt()))
	np.LicensedResources = filtered
	return np
}

// WithRoles keeps resources whose role is in the given list.
func (p Profile) WithRoles(roles []string) Profile {
	filtered := p.filterLicensed(func(r LicensedResource) bool {
		return containsString(roles, r.Role)
	})
	np := p.updateState("role", strings.Join(roles, ","))
	np.LicensedResources = filtered
	return np
}

// WithTenantOwnershipOrError returns a filtered profile when it owns the tenant,
// otherwise an InsufficientPrivilegesError.
func (p Profile) WithTenantOwnershipOrError(tenantID uuid.UUID) (Profile, error) {
	if p.TenantsOwnership != nil {
		for _, t := range p.TenantsOwnership.ToOwnershipVector() {
			if t.ID == tenantID {
				return p.updateState("tenantOwnership", tenantID.String()), nil
			}
		}
	}
	return Profile{}, NewInsufficientPrivilegesError(
		fmt.Sprintf("Insufficient privileges to perform these action (no tenant ownership): %s", strings.Join(p.FilteringState, ", ")),
		p.FilteringState,
	)
}

// GetRelatedAccountOrError resolves the effective access scope, checking staff
// and manager privileges before licensed resources.
func (p Profile) GetRelatedAccountOrError() (RelatedAccounts, error) {
	if p.IsStaff {
		return NewHasStaffPrivileges(), nil
	}
	if p.IsManager {
		return NewHasManagerPrivileges(), nil
	}
	if p.LicensedResources != nil {
		records := p.LicensedResources.ToLicensesVector()
		if len(records) == 0 {
			return RelatedAccounts{}, NewInsufficientLicensesError("")
		}
		accounts := make([]uuid.UUID, 0, len(records))
		for _, r := range records {
			accounts = append(accounts, r.AccID)
		}
		return NewAllowedAccounts(accounts), nil
	}
	return RelatedAccounts{}, NewInsufficientPrivilegesError(
		fmt.Sprintf("Insufficient privileges to perform these action (no accounts): %s", strings.Join(p.FilteringState, ", ")),
		p.FilteringState,
	)
}

// GetTenantWidePermissionOrError resolves tenant-wide access: staff, manager,
// tenant ownership, or tenant-manager role fallback.
func (p Profile) GetTenantWidePermissionOrError(tenantID uuid.UUID, permission Permission) (RelatedAccounts, error) {
	if p.IsStaff {
		return NewHasStaffPrivileges(), nil
	}
	if p.IsManager {
		return NewHasManagerPrivileges(), nil
	}
	if p.TenantsOwnership != nil {
		for _, t := range p.TenantsOwnership.ToOwnershipVector() {
			if t.ID == tenantID {
				return NewHasTenantWidePrivileges(tenantID), nil
			}
		}
	}
	if _, err := p.OnTenantAsManager(tenantID, permission).GetIdsOrError(); err == nil {
		return NewHasTenantWidePrivileges(tenantID), nil
	}
	return RelatedAccounts{}, NewInsufficientPrivilegesError(
		fmt.Sprintf("Insufficient privileges to perform these action (no tenant wide permission): %s", strings.Join(p.FilteringState, ", ")),
		p.FilteringState,
	)
}

// GetRelatedAccountsOrTenantWidePermissionOrError tries tenant-wide resolution
// first, falling back to the account-scoped resolution.
func (p Profile) GetRelatedAccountsOrTenantWidePermissionOrError(tenantID uuid.UUID, permission Permission) (RelatedAccounts, error) {
	if ra, err := p.GetTenantWidePermissionOrError(tenantID, permission); err == nil {
		return ra, nil
	}
	return p.GetRelatedAccountOrError()
}

// GetIdsOrError returns the account ids of the licensed resources. It succeeds
// when there is at least one id OR the profile has admin privileges.
func (p Profile) GetIdsOrError() ([]uuid.UUID, error) {
	var ids []uuid.UUID
	if p.LicensedResources != nil {
		for _, r := range p.LicensedResources.ToLicensesVector() {
			ids = append(ids, r.AccID)
		}
	}
	if len(ids) > 0 || p.HasAdminPrivileges() {
		return ids, nil
	}
	return nil, NewInsufficientPrivilegesError(
		fmt.Sprintf("Insufficient privileges to perform these action (no ids): %s", strings.Join(p.FilteringState, ", ")),
		p.FilteringState,
	)
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func containsAll(haystack, needles []string) bool {
	for _, n := range needles {
		if !containsString(haystack, n) {
			return false
		}
	}
	return true
}

func containsAny(haystack, needles []string) bool {
	for _, n := range needles {
		if containsString(haystack, n) {
			return true
		}
	}
	return false
}

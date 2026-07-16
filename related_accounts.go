package mycelium

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// RelatedAccountsKind discriminates the RelatedAccounts variants.
type RelatedAccountsKind string

const (
	RelatedAccountsAllowedAccounts         RelatedAccountsKind = "AllowedAccounts"
	RelatedAccountsHasTenantWidePrivileges RelatedAccountsKind = "HasTenantWidePrivileges"
	RelatedAccountsHasStaffPrivileges      RelatedAccountsKind = "HasStaffPrivileges"
	RelatedAccountsHasManagerPrivileges    RelatedAccountsKind = "HasManagerPrivileges"
)

// RelatedAccounts is the effective access scope resolved from a Profile. It maps
// to the externally-tagged Rust enum and (un)marshals to the same wire form:
//
//	{"allowedAccounts": ["<uuid>", ...]}
//	{"hasTenantWidePrivileges": "<uuid>"}
//	"hasStaffPrivileges"
//	"hasManagerPrivileges"
type RelatedAccounts struct {
	Kind     RelatedAccountsKind
	Accounts []uuid.UUID
	TenantID *uuid.UUID
}

// NewAllowedAccounts builds an AllowedAccounts scope.
func NewAllowedAccounts(accounts []uuid.UUID) RelatedAccounts {
	return RelatedAccounts{Kind: RelatedAccountsAllowedAccounts, Accounts: accounts}
}

// NewHasTenantWidePrivileges builds a HasTenantWidePrivileges scope.
func NewHasTenantWidePrivileges(tenantID uuid.UUID) RelatedAccounts {
	return RelatedAccounts{Kind: RelatedAccountsHasTenantWidePrivileges, TenantID: &tenantID}
}

// NewHasStaffPrivileges builds a HasStaffPrivileges scope.
func NewHasStaffPrivileges() RelatedAccounts {
	return RelatedAccounts{Kind: RelatedAccountsHasStaffPrivileges}
}

// NewHasManagerPrivileges builds a HasManagerPrivileges scope.
func NewHasManagerPrivileges() RelatedAccounts {
	return RelatedAccounts{Kind: RelatedAccountsHasManagerPrivileges}
}

// MarshalJSON emits the externally-tagged camelCase form matching the gateway.
func (ra RelatedAccounts) MarshalJSON() ([]byte, error) {
	switch ra.Kind {
	case RelatedAccountsAllowedAccounts:
		accs := ra.Accounts
		if accs == nil {
			accs = []uuid.UUID{}
		}
		return json.Marshal(map[string][]uuid.UUID{"allowedAccounts": accs})
	case RelatedAccountsHasTenantWidePrivileges:
		if ra.TenantID == nil {
			return nil, fmt.Errorf("hasTenantWidePrivileges requires a tenant id")
		}
		return json.Marshal(map[string]uuid.UUID{"hasTenantWidePrivileges": *ra.TenantID})
	case RelatedAccountsHasStaffPrivileges:
		return json.Marshal("hasStaffPrivileges")
	case RelatedAccountsHasManagerPrivileges:
		return json.Marshal("hasManagerPrivileges")
	default:
		return nil, fmt.Errorf("unknown RelatedAccounts kind: %q", ra.Kind)
	}
}

// UnmarshalJSON parses the externally-tagged form back into a RelatedAccounts.
func (ra *RelatedAccounts) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		switch s {
		case "hasStaffPrivileges":
			*ra = NewHasStaffPrivileges()
			return nil
		case "hasManagerPrivileges":
			*ra = NewHasManagerPrivileges()
			return nil
		default:
			return fmt.Errorf("unknown RelatedAccounts variant: %q", s)
		}
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	if raw, ok := obj["allowedAccounts"]; ok {
		var accs []uuid.UUID
		if err := json.Unmarshal(raw, &accs); err != nil {
			return err
		}
		*ra = NewAllowedAccounts(accs)
		return nil
	}
	if raw, ok := obj["hasTenantWidePrivileges"]; ok {
		var id uuid.UUID
		if err := json.Unmarshal(raw, &id); err != nil {
			return err
		}
		*ra = NewHasTenantWidePrivileges(id)
		return nil
	}
	return fmt.Errorf("unknown RelatedAccounts object")
}

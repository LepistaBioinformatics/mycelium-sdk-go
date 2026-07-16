package mycelium

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Permission models the gateway's access level. It is backed by an integer
// (Read=0, Write=1) but the gateway serializes it as the JSON string "read" /
// "write" in the Records form, while the LicensedResource URL form encodes it
// as the integer. To stay compatible with the gateway wire format, Permission
// always MARSHALS to the string form and ACCEPTS both string and integer on
// unmarshal.
type Permission int

const (
	// PermissionRead grants read access (integer 0).
	PermissionRead Permission = 0
	// PermissionWrite grants write access (integer 1).
	PermissionWrite Permission = 1
)

// ToInt returns the integer representation (0 for Read, 1 for Write).
func (p Permission) ToInt() int { return int(p) }

// String returns the wire string form ("read" / "write").
func (p Permission) String() string {
	if p == PermissionWrite {
		return "write"
	}
	return "read"
}

// PermissionFromInt converts an integer code to a Permission, erroring outside
// {0, 1}.
func PermissionFromInt(v int) (Permission, error) {
	switch v {
	case 0:
		return PermissionRead, nil
	case 1:
		return PermissionWrite, nil
	default:
		return 0, fmt.Errorf("invalid permission code: %d", v)
	}
}

// PermissionFromString converts the wire string form to a Permission, erroring
// on any value other than "read" / "write".
func PermissionFromString(s string) (Permission, error) {
	switch s {
	case "read":
		return PermissionRead, nil
	case "write":
		return PermissionWrite, nil
	default:
		return 0, fmt.Errorf("invalid permission: %q", s)
	}
}

// MarshalJSON always emits the string form to match the gateway.
func (p Permission) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

// UnmarshalJSON accepts both the string form ("read"/"write") and the integer
// form (0/1) so a Profile can be decoded from either the Records or the URL
// representation.
func (p *Permission) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		perm, err := PermissionFromString(s)
		if err != nil {
			return err
		}
		*p = perm
		return nil
	}

	var i int
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}
	perm, err := PermissionFromInt(i)
	if err != nil {
		return err
	}
	*p = perm
	return nil
}

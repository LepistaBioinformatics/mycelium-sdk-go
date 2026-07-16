package mycelium

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// LicensedResource is a single guest grant: an account, a role, and the
// permission held over it within a tenant.
type LicensedResource struct {
	AccID       uuid.UUID  `json:"accId"`
	SysAcc      bool       `json:"sysAcc"`
	TenantID    uuid.UUID  `json:"tenantId"`
	AccName     string     `json:"accName"`
	Role        string     `json:"role"`
	RoleID      uuid.UUID  `json:"roleId"`
	Perm        Permission `json:"perm"`
	Verified    bool       `json:"verified"`
	PermitFlags *[]string  `json:"permitFlags,omitempty"`
	DenyFlags   *[]string  `json:"denyFlags,omitempty"`
}

// String encodes the resource into the compact URL form used by the gateway's
// client-facing profile endpoint:
//
//	t/{tenantHex}/a/{accHex}/r/{roleHex}?p={role}:{permInt}&s={0|1}&v={0|1}&n={base64(accName)}[&pf=..][&df=..]
//
// UUIDs are hex without hyphens and accName is Base64 STANDARD, byte-matching
// the Rust LicensedResource ToString impl.
func (r LicensedResource) String() string {
	encName := base64.StdEncoding.EncodeToString([]byte(r.AccName))
	s := fmt.Sprintf(
		"t/%s/a/%s/r/%s?p=%s:%d&s=%d&v=%d&n=%s",
		uuidHex(r.TenantID), uuidHex(r.AccID), uuidHex(r.RoleID),
		r.Role, r.Perm.ToInt(), boolToInt(r.SysAcc), boolToInt(r.Verified), encName,
	)
	if r.PermitFlags != nil {
		s += "&pf=" + strings.Join(*r.PermitFlags, ",")
	}
	if r.DenyFlags != nil {
		s += "&df=" + strings.Join(*r.DenyFlags, ",")
	}
	return s
}

// LicensedResourceFromString parses the compact URL form produced by String.
func LicensedResourceFromString(value string) (LicensedResource, error) {
	var lr LicensedResource

	pathPart, rawQuery, _ := strings.Cut(value, "?")

	segments := make([]string, 0, 6)
	for _, seg := range strings.Split(pathPart, "/") {
		if seg != "" {
			segments = append(segments, seg)
		}
	}
	if len(segments) != 6 || segments[0] != "t" || segments[2] != "a" || segments[4] != "r" {
		return lr, fmt.Errorf("invalid path format")
	}

	tenantID, err := uuid.Parse(segments[1])
	if err != nil {
		return lr, fmt.Errorf("invalid tenant UUID")
	}
	accID, err := uuid.Parse(segments[3])
	if err != nil {
		return lr, fmt.Errorf("invalid account UUID")
	}
	roleID, err := uuid.Parse(segments[5])
	if err != nil {
		return lr, fmt.Errorf("invalid role UUID")
	}

	// Parse the query manually so Base64 STANDARD values (which may contain '+'
	// or '/') are preserved verbatim rather than form-decoded.
	q := parseRawQuery(rawQuery)

	permParam, ok := q["p"]
	if !ok {
		return lr, fmt.Errorf("parameter permissions not found")
	}
	permParts := strings.Split(permParam, ":")
	if len(permParts) != 2 {
		return lr, fmt.Errorf("invalid permissioned role format")
	}
	permCode, err := strconv.Atoi(permParts[1])
	if err != nil {
		return lr, fmt.Errorf("failed to parse permission code")
	}
	perm, err := PermissionFromInt(permCode)
	if err != nil {
		return lr, err
	}

	sysAcc, err := parseBoolFlag(q, "s", "sys", "account standard")
	if err != nil {
		return lr, err
	}
	verified, err := parseBoolFlag(q, "v", "v", "account verification")
	if err != nil {
		return lr, err
	}

	nameParam, ok := q["n"]
	if !ok {
		return lr, fmt.Errorf("parameter name not found")
	}
	nameBytes, err := base64.StdEncoding.DecodeString(nameParam)
	if err != nil {
		return lr, fmt.Errorf("failed to decode account name")
	}

	lr = LicensedResource{
		AccID:    accID,
		SysAcc:   sysAcc,
		TenantID: tenantID,
		AccName:  string(nameBytes),
		Role:     permParts[0],
		RoleID:   roleID,
		Perm:     perm,
		Verified: verified,
	}
	if pf, ok := q["pf"]; ok && pf != "" {
		flags := strings.Split(pf, ",")
		lr.PermitFlags = &flags
	}
	if df, ok := q["df"]; ok && df != "" {
		flags := strings.Split(df, ",")
		lr.DenyFlags = &flags
	}
	return lr, nil
}

func parseBoolFlag(q map[string]string, key, notFoundName, invalidName string) (bool, error) {
	v, ok := q[key]
	if !ok {
		return false, fmt.Errorf("parameter %s not found", notFoundName)
	}
	switch v {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("invalid %s", invalidName)
	}
}

func parseRawQuery(raw string) map[string]string {
	m := make(map[string]string)
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		m[k] = v
	}
	return m
}

func uuidHex(id uuid.UUID) string {
	return strings.ReplaceAll(id.String(), "-", "")
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

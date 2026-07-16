package mycelium

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TenantOwnership records a tenant a profile owns. Note the JSON keys are
// id/name/since (NOT camelCased) because the Rust TenantOwnership struct has no
// rename_all attribute.
type TenantOwnership struct {
	ID    uuid.UUID `json:"id"`
	Name  string    `json:"name"`
	Since time.Time `json:"since"`
}

// String encodes the ownership into the compact URL form
// tid/{tenantHex}?since={rfc3339}&name={base64(name)}.
func (t TenantOwnership) String() string {
	encName := base64.StdEncoding.EncodeToString([]byte(t.Name))
	return fmt.Sprintf("tid/%s?since=%s&name=%s", uuidHex(t.ID), t.Since.Format(time.RFC3339), encName)
}

// TenantOwnershipFromString parses the compact URL form produced by String.
func TenantOwnershipFromString(value string) (TenantOwnership, error) {
	var to TenantOwnership

	pathPart, rawQuery, _ := strings.Cut(value, "?")

	segments := make([]string, 0, 2)
	for _, seg := range strings.Split(pathPart, "/") {
		if seg != "" {
			segments = append(segments, seg)
		}
	}
	if len(segments) != 2 || segments[0] != "tid" {
		return to, fmt.Errorf("invalid path format")
	}

	id, err := uuid.Parse(segments[1])
	if err != nil {
		return to, fmt.Errorf("invalid tenant UUID")
	}

	q := parseRawQuery(rawQuery)

	sinceParam, ok := q["since"]
	if !ok {
		return to, fmt.Errorf("parameter since not found")
	}
	since, err := time.Parse(time.RFC3339, sinceParam)
	if err != nil {
		return to, fmt.Errorf("failed to parse since")
	}

	nameParam, ok := q["name"]
	if !ok {
		return to, fmt.Errorf("parameter name not found")
	}
	nameBytes, err := base64.StdEncoding.DecodeString(nameParam)
	if err != nil {
		return to, fmt.Errorf("failed to decode tenant name")
	}

	return TenantOwnership{ID: id, Name: string(nameBytes), Since: since}, nil
}

// TenantsOwnership is a records|urls tagged union of tenant ownerships.
type TenantsOwnership struct {
	Records []TenantOwnership
	Urls    []string
}

type tenantsOwnershipRecords struct {
	Records []TenantOwnership `json:"records"`
}

type tenantsOwnershipUrls struct {
	Urls []string `json:"urls"`
}

// MarshalJSON emits the records form when Records is set, otherwise the urls form.
func (to TenantsOwnership) MarshalJSON() ([]byte, error) {
	if to.Records != nil {
		return json.Marshal(tenantsOwnershipRecords{Records: to.Records})
	}
	if to.Urls != nil {
		return json.Marshal(tenantsOwnershipUrls{Urls: to.Urls})
	}
	return json.Marshal(tenantsOwnershipRecords{Records: []TenantOwnership{}})
}

// UnmarshalJSON detects the variant by the presence of "records" vs "urls".
func (to *TenantsOwnership) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if rec, ok := raw["records"]; ok {
		var records []TenantOwnership
		if err := json.Unmarshal(rec, &records); err != nil {
			return err
		}
		to.Records = records
		to.Urls = nil
		return nil
	}
	if u, ok := raw["urls"]; ok {
		var urls []string
		if err := json.Unmarshal(u, &urls); err != nil {
			return err
		}
		to.Urls = urls
		to.Records = nil
		return nil
	}
	return nil
}

// ToOwnershipVector returns the materialized ownerships. Records take precedence
// over urls; unparseable url entries are skipped.
func (to TenantsOwnership) ToOwnershipVector() []TenantOwnership {
	if to.Records != nil {
		return to.Records
	}
	if to.Urls != nil {
		out := make([]TenantOwnership, 0, len(to.Urls))
		for _, u := range to.Urls {
			t, err := TenantOwnershipFromString(u)
			if err != nil {
				continue
			}
			out = append(out, t)
		}
		return out
	}
	return []TenantOwnership{}
}

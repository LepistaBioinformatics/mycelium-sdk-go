package mycelium

import "encoding/json"

// LicensedResources is a tagged union: either an inline list of records or a
// list of compact URL strings. On the wire it is exactly one of
// {"records": [...]} or {"urls": [...]}, mirroring the Rust enum.
type LicensedResources struct {
	Records []LicensedResource
	Urls    []string
}

type licensedResourcesRecords struct {
	Records []LicensedResource `json:"records"`
}

type licensedResourcesUrls struct {
	Urls []string `json:"urls"`
}

// MarshalJSON emits the records form when Records is set, otherwise the urls
// form. An empty value marshals as an empty records list.
func (lr LicensedResources) MarshalJSON() ([]byte, error) {
	if lr.Records != nil {
		return json.Marshal(licensedResourcesRecords{Records: lr.Records})
	}
	if lr.Urls != nil {
		return json.Marshal(licensedResourcesUrls{Urls: lr.Urls})
	}
	return json.Marshal(licensedResourcesRecords{Records: []LicensedResource{}})
}

// UnmarshalJSON detects the variant by the presence of "records" vs "urls".
func (lr *LicensedResources) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if rec, ok := raw["records"]; ok {
		var records []LicensedResource
		if err := json.Unmarshal(rec, &records); err != nil {
			return err
		}
		lr.Records = records
		lr.Urls = nil
		return nil
	}
	if u, ok := raw["urls"]; ok {
		var urls []string
		if err := json.Unmarshal(u, &urls); err != nil {
			return err
		}
		lr.Urls = urls
		lr.Records = nil
		return nil
	}
	return nil
}

// ToLicensesVector returns the materialized records. Records take precedence
// over urls. URL entries are lazily parsed; entries that fail to parse are
// skipped (dropping a grant fails safe by reducing access).
func (lr LicensedResources) ToLicensesVector() []LicensedResource {
	if lr.Records != nil {
		return lr.Records
	}
	if lr.Urls != nil {
		out := make([]LicensedResource, 0, len(lr.Urls))
		for _, u := range lr.Urls {
			r, err := LicensedResourceFromString(u)
			if err != nil {
				continue
			}
			out = append(out, r)
		}
		return out
	}
	return []LicensedResource{}
}

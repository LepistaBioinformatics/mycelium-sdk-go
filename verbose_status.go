package mycelium

// VerboseStatus is the human-readable account status. It is a plain string on
// the wire (single lowercase word), so the zero value marshals/unmarshals via
// the default string codec.
type VerboseStatus string

const (
	VerboseStatusUnverified VerboseStatus = "unverified"
	VerboseStatusVerified   VerboseStatus = "verified"
	VerboseStatusInactive   VerboseStatus = "inactive"
	VerboseStatusArchived   VerboseStatus = "archived"
	VerboseStatusDeleted    VerboseStatus = "deleted"
	VerboseStatusUnknown    VerboseStatus = "unknown"
)

// IsValid reports whether v is one of the recognized statuses.
func (v VerboseStatus) IsValid() bool {
	switch v {
	case VerboseStatusUnverified,
		VerboseStatusVerified,
		VerboseStatusInactive,
		VerboseStatusArchived,
		VerboseStatusDeleted,
		VerboseStatusUnknown:
		return true
	default:
		return false
	}
}

// ParseVerboseStatus returns the matching status, falling back to Unknown for
// unrecognized values (mirroring the gateway's lenient FromStr).
func ParseVerboseStatus(s string) VerboseStatus {
	v := VerboseStatus(s)
	if v.IsValid() {
		return v
	}
	return VerboseStatusUnknown
}

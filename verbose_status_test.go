package mycelium

import "testing"

func TestVerboseStatusIsValid(t *testing.T) {
	valid := []VerboseStatus{
		VerboseStatusUnverified, VerboseStatusVerified, VerboseStatusInactive,
		VerboseStatusArchived, VerboseStatusDeleted, VerboseStatusUnknown,
	}
	for _, v := range valid {
		if !v.IsValid() {
			t.Errorf("%q should be valid", v)
		}
	}
	if VerboseStatus("bogus").IsValid() {
		t.Error("bogus should be invalid")
	}
}

func TestParseVerboseStatus(t *testing.T) {
	if ParseVerboseStatus("verified") != VerboseStatusVerified {
		t.Error("verified parse failed")
	}
	if ParseVerboseStatus("nope") != VerboseStatusUnknown {
		t.Error("unknown value should fall back to Unknown")
	}
}

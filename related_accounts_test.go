package mycelium

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestRelatedAccountsMarshal(t *testing.T) {
	id := uuid.MustParse("55555555-5555-5555-5555-555555555555")
	cases := []struct {
		ra   RelatedAccounts
		want string
	}{
		{NewAllowedAccounts([]uuid.UUID{id}), `{"allowedAccounts":["55555555-5555-5555-5555-555555555555"]}`},
		{NewHasTenantWidePrivileges(id), `{"hasTenantWidePrivileges":"55555555-5555-5555-5555-555555555555"}`},
		{NewHasStaffPrivileges(), `"hasStaffPrivileges"`},
		{NewHasManagerPrivileges(), `"hasManagerPrivileges"`},
	}
	for _, c := range cases {
		b, err := json.Marshal(c.ra)
		if err != nil {
			t.Fatalf("marshal %v: %v", c.ra.Kind, err)
		}
		if string(b) != c.want {
			t.Errorf("marshal = %s, want %s", b, c.want)
		}
	}
}

func TestRelatedAccountsRoundTrip(t *testing.T) {
	id := uuid.New()
	for _, ra := range []RelatedAccounts{
		NewAllowedAccounts([]uuid.UUID{id}),
		NewHasTenantWidePrivileges(id),
		NewHasStaffPrivileges(),
		NewHasManagerPrivileges(),
	} {
		b, err := json.Marshal(ra)
		if err != nil {
			t.Fatal(err)
		}
		var back RelatedAccounts
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if back.Kind != ra.Kind {
			t.Errorf("kind %v -> %v", ra.Kind, back.Kind)
		}
	}
}

func TestRelatedAccountsAllowedEmptyMarshalsArray(t *testing.T) {
	b, _ := json.Marshal(NewAllowedAccounts(nil))
	if string(b) != `{"allowedAccounts":[]}` {
		t.Errorf("got %s", b)
	}
}

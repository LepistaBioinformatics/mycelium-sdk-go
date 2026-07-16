package mycelium

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestOwnerJSONRoundTrip(t *testing.T) {
	id := uuid.New()
	first := "Ada"
	o := Owner{ID: id, Email: "ada@example.com", FirstName: &first, IsPrincipal: true}

	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	// Optional nil fields must be omitted.
	if got := string(b); !json.Valid(b) || contains(got, "lastName") || contains(got, "username") {
		t.Errorf("unexpected marshal output: %s", got)
	}

	var back Owner
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.ID != id || back.Email != o.Email || back.FirstName == nil || *back.FirstName != "Ada" || !back.IsPrincipal {
		t.Errorf("round-trip mismatch: %+v", back)
	}
}

func TestOwnerCamelCaseKeys(t *testing.T) {
	o := Owner{ID: uuid.New(), Email: "x@y.z", IsPrincipal: false}
	b, _ := json.Marshal(o)
	if !contains(string(b), `"isPrincipal"`) || !contains(string(b), `"accId"`) && !contains(string(b), `"id"`) {
		t.Errorf("expected camelCase keys, got %s", b)
	}
}

func TestRedactedEmail(t *testing.T) {
	cases := map[string]string{
		"samuel@biotrop.com.br": "s*****@biotrop.com.br",
		"a@b.com":               "a*@b.com",
		"no-at-sign":            "no-at-sign",
		"@nolocal.com":          "@nolocal.com",
	}
	for in, want := range cases {
		if got := redactEmail(in); got != want {
			t.Errorf("redactEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOwnerRedactedEmail(t *testing.T) {
	o := Owner{Email: "ada@example.com"}
	if got := o.RedactedEmail(); got != "a**@example.com" {
		t.Errorf("RedactedEmail() = %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

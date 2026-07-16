package mycelium

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func sampleOwnership() TenantOwnership {
	return TenantOwnership{
		ID:    uuid.MustParse("44444444-4444-4444-4444-444444444444"),
		Name:  "Acme Tenant",
		Since: time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC),
	}
}

func TestTenantOwnershipJSONKeysNotCamelCased(t *testing.T) {
	b, err := json.Marshal(sampleOwnership())
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !contains(s, `"id"`) || !contains(s, `"name"`) || !contains(s, `"since"`) {
		t.Errorf("expected id/name/since keys, got %s", s)
	}
}

func TestTenantOwnershipSinceRFC3339(t *testing.T) {
	data := `{"id":"44444444-4444-4444-4444-444444444444","name":"n","since":"2026-01-02T15:04:05Z"}`
	var to TenantOwnership
	if err := json.Unmarshal([]byte(data), &to); err != nil {
		t.Fatal(err)
	}
	if !to.Since.Equal(time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)) {
		t.Errorf("since = %v", to.Since)
	}
}

func TestTenantOwnershipStringRoundTrip(t *testing.T) {
	orig := sampleOwnership()
	got, err := TenantOwnershipFromString(orig.String())
	if err != nil {
		t.Fatalf("FromString error: %v", err)
	}
	if got.ID != orig.ID || got.Name != orig.Name || !got.Since.Equal(orig.Since) {
		t.Errorf("round-trip mismatch: %+v vs %+v", got, orig)
	}
}

func TestTenantOwnershipFromStringErrors(t *testing.T) {
	for name, in := range map[string]string{
		"bad path":  "x/44444444444444444444444444444444?since=2026-01-02T15:04:05Z&name=bg==",
		"bad uuid":  "tid/nothex?since=2026-01-02T15:04:05Z&name=bg==",
		"no since":  "tid/44444444444444444444444444444444?name=bg==",
		"bad since": "tid/44444444444444444444444444444444?since=notadate&name=bg==",
		"no name":   "tid/44444444444444444444444444444444?since=2026-01-02T15:04:05Z",
	} {
		if _, err := TenantOwnershipFromString(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestTenantsOwnershipUnion(t *testing.T) {
	rec := TenantsOwnership{Records: []TenantOwnership{sampleOwnership()}}
	b, _ := json.Marshal(rec)
	if !contains(string(b), `"records"`) {
		t.Errorf("expected records key, got %s", b)
	}

	var back TenantsOwnership
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.ToOwnershipVector()) != 1 {
		t.Errorf("expected 1 ownership")
	}

	urls := TenantsOwnership{Urls: []string{sampleOwnership().String()}}
	if len(urls.ToOwnershipVector()) != 1 {
		t.Errorf("expected 1 ownership from urls")
	}
}

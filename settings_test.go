package mycelium

import "testing"

func TestHeaderKeyConstants(t *testing.T) {
	cases := map[string]string{
		DefaultProfileKey:          "x-mycelium-profile",
		DefaultEmailKey:            "x-mycelium-email",
		DefaultScopeKey:            "x-mycelium-scope",
		DefaultMyceliumRoleKey:     "x-mycelium-role",
		DefaultRequestIDKey:        "x-mycelium-request-id",
		DefaultConnectionStringKey: "x-mycelium-connection-string",
		DefaultTenantIDKey:         "x-mycelium-tenant-id",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("header key = %q, want %q", got, want)
		}
	}
}

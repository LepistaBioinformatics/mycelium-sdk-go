package mycelium

import (
	"encoding/json"
	"testing"
)

func TestPermissionToInt(t *testing.T) {
	if PermissionRead.ToInt() != 0 {
		t.Errorf("Read.ToInt() = %d, want 0", PermissionRead.ToInt())
	}
	if PermissionWrite.ToInt() != 1 {
		t.Errorf("Write.ToInt() = %d, want 1", PermissionWrite.ToInt())
	}
}

func TestPermissionString(t *testing.T) {
	if PermissionRead.String() != "read" {
		t.Errorf("Read.String() = %q", PermissionRead.String())
	}
	if PermissionWrite.String() != "write" {
		t.Errorf("Write.String() = %q", PermissionWrite.String())
	}
}

func TestPermissionFromInt(t *testing.T) {
	if p, err := PermissionFromInt(0); err != nil || p != PermissionRead {
		t.Errorf("FromInt(0) = %v, %v", p, err)
	}
	if p, err := PermissionFromInt(1); err != nil || p != PermissionWrite {
		t.Errorf("FromInt(1) = %v, %v", p, err)
	}
	if _, err := PermissionFromInt(2); err == nil {
		t.Error("FromInt(2) should error")
	}
}

func TestPermissionFromString(t *testing.T) {
	if p, err := PermissionFromString("read"); err != nil || p != PermissionRead {
		t.Errorf("FromString(read) = %v, %v", p, err)
	}
	if p, err := PermissionFromString("write"); err != nil || p != PermissionWrite {
		t.Errorf("FromString(write) = %v, %v", p, err)
	}
	if _, err := PermissionFromString("admin"); err == nil {
		t.Error("FromString(admin) should error")
	}
}

func TestPermissionMarshalEmitsString(t *testing.T) {
	b, err := json.Marshal(PermissionWrite)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"write"` {
		t.Errorf("Marshal(Write) = %s, want \"write\"", b)
	}
}

func TestPermissionUnmarshalFromString(t *testing.T) {
	var p Permission
	if err := json.Unmarshal([]byte(`"read"`), &p); err != nil {
		t.Fatal(err)
	}
	if p != PermissionRead {
		t.Errorf("got %v, want Read", p)
	}
}

func TestPermissionUnmarshalFromInt(t *testing.T) {
	var p Permission
	if err := json.Unmarshal([]byte(`1`), &p); err != nil {
		t.Fatal(err)
	}
	if p != PermissionWrite {
		t.Errorf("got %v, want Write", p)
	}
}

func TestPermissionUnmarshalInvalid(t *testing.T) {
	var p Permission
	if err := json.Unmarshal([]byte(`"nope"`), &p); err == nil {
		t.Error("unmarshal invalid string should error")
	}
	if err := json.Unmarshal([]byte(`7`), &p); err == nil {
		t.Error("unmarshal invalid int should error")
	}
}

func TestPermissionRoundTrip(t *testing.T) {
	for _, perm := range []Permission{PermissionRead, PermissionWrite} {
		b, err := json.Marshal(perm)
		if err != nil {
			t.Fatal(err)
		}
		var got Permission
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if got != perm {
			t.Errorf("round-trip %v -> %v", perm, got)
		}
	}
}

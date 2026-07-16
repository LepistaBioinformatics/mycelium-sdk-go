package mycelium

import (
	"errors"
	"testing"
)

func TestMyceliumErrorImplementsError(t *testing.T) {
	var err error = &MyceliumError{Message: "boom", Code: "X", ExpTrue: false}
	if err.Error() != "boom" {
		t.Fatalf("Error() = %q, want %q", err.Error(), "boom")
	}
}

func TestInsufficientPrivilegesError(t *testing.T) {
	state := []string{"1:tenantId:abc"}
	err := NewInsufficientPrivilegesError("no privileges", state)

	if err.Code != codeInsufficient {
		t.Errorf("Code = %q, want %q", err.Code, codeInsufficient)
	}
	if !err.ExpTrue {
		t.Error("ExpTrue = false, want true")
	}
	if len(err.FilteringState) != 1 || err.FilteringState[0] != "1:tenantId:abc" {
		t.Errorf("FilteringState = %v", err.FilteringState)
	}

	var base *MyceliumError
	if !errors.As(error(err), &base) {
		t.Fatal("errors.As should unwrap to *MyceliumError")
	}
	if base.Code != codeInsufficient {
		t.Errorf("unwrapped Code = %q", base.Code)
	}
}

func TestInsufficientPrivilegesErrorNilStateDefaultsEmpty(t *testing.T) {
	err := NewInsufficientPrivilegesError("x", nil)
	if err.FilteringState == nil || len(err.FilteringState) != 0 {
		t.Errorf("FilteringState = %v, want empty non-nil", err.FilteringState)
	}
}

func TestInsufficientLicensesErrorDefaultMessage(t *testing.T) {
	err := NewInsufficientLicensesError("")
	if err.Message != "Insufficient licenses to perform these action" {
		t.Errorf("Message = %q", err.Message)
	}
	if err.Code != codeInsufficient || !err.ExpTrue {
		t.Errorf("Code/ExpTrue = %q/%v", err.Code, err.ExpTrue)
	}
}

func TestProfileDecodingError(t *testing.T) {
	err := NewProfileDecodingError("bad base64")
	if err.Code != codeDecoding {
		t.Errorf("Code = %q, want %q", err.Code, codeDecoding)
	}
	if err.ExpTrue {
		t.Error("ExpTrue = true, want false")
	}

	var target *ProfileDecodingError
	if !errors.As(error(err), &target) {
		t.Fatal("errors.As should match *ProfileDecodingError")
	}
}

func TestErrorCodesShared(t *testing.T) {
	priv := NewInsufficientPrivilegesError("a", nil)
	lic := NewInsufficientLicensesError("b")
	if priv.Code != lic.Code {
		t.Errorf("privilege and license codes differ: %q vs %q", priv.Code, lic.Code)
	}
}

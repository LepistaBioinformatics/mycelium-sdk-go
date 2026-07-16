package mycelium

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func fullProfile() Profile {
	first := "Ada"
	return Profile{
		Owners:  []Owner{{ID: uuid.New(), Email: "ada@example.com", FirstName: &first, IsPrincipal: true}},
		AccID:   uuid.New(),
		IsStaff: false,
		LicensedResources: &LicensedResources{Records: []LicensedResource{
			res(tenantA, accX, "admin", PermissionWrite),
		}},
		Meta: map[string]string{"locale": "pt-BR"},
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	orig := fullProfile()
	encoded, err := CompressAndEncodeProfileToBase64(&orig)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAndDecompressProfileFromBase64(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if got.AccID != orig.AccID {
		t.Errorf("accId mismatch: %v vs %v", got.AccID, orig.AccID)
	}
	if len(got.Owners) != 1 || got.Owners[0].Email != "ada@example.com" {
		t.Errorf("owners mismatch: %+v", got.Owners)
	}
	if got.LicensedResources == nil || len(got.LicensedResources.ToLicensesVector()) != 1 {
		t.Errorf("licensed resources mismatch: %+v", got.LicensedResources)
	}
	if got.Meta["locale"] != "pt-BR" {
		t.Errorf("meta mismatch: %+v", got.Meta)
	}
}

func TestDecodeEmptyInput(t *testing.T) {
	_, err := DecodeAndDecompressProfileFromBase64("")
	var dec *ProfileDecodingError
	if !errors.As(err, &dec) {
		t.Errorf("expected ProfileDecodingError, got %v", err)
	}
}

func TestDecodeInvalidBase64(t *testing.T) {
	_, err := DecodeAndDecompressProfileFromBase64("!!!not base64!!!")
	var dec *ProfileDecodingError
	if !errors.As(err, &dec) {
		t.Errorf("expected ProfileDecodingError, got %v", err)
	}
}

func TestDecodeInvalidJSONStrictZstdFails(t *testing.T) {
	// Valid base64 of non-zstd, non-json bytes -> strict zstd failure.
	raw := base64.StdEncoding.EncodeToString([]byte("not compressed not json"))
	_, err := DecodeAndDecompressProfileFromBase64(raw)
	var dec *ProfileDecodingError
	if !errors.As(err, &dec) {
		t.Errorf("expected ProfileDecodingError, got %v", err)
	}
}

func TestDecodeNonStrictUncompressedFallback(t *testing.T) {
	// Base64 of raw JSON (uncompressed). Strict fails; non-strict falls back.
	rawJSON := `{"owners":[],"accId":"` + accX.String() + `","isSubscription":false,"isStaff":true,"isManager":false,"ownerIsActive":true,"accountIsActive":true,"accountWasApproved":true,"accountWasArchived":false,"accountWasDeleted":false}`
	encoded := base64.StdEncoding.EncodeToString([]byte(rawJSON))

	if _, err := DecodeAndDecompressProfileFromBase64(encoded); err == nil {
		t.Error("strict mode should fail on uncompressed input")
	}

	got, err := DecodeAndDecompressProfileFromBase64(encoded, WithStrict(false))
	if err != nil {
		t.Fatalf("non-strict fallback failed: %v", err)
	}
	if got.AccID != accX || !got.IsStaff {
		t.Errorf("fallback decode mismatch: %+v", got)
	}
}

func TestDecodeBadJSONAfterDecompress(t *testing.T) {
	// Valid zstd of invalid JSON -> deserialize error.
	compressed := getZstdEncoder().EncodeAll([]byte("{not json"), nil)
	encoded := base64.StdEncoding.EncodeToString(compressed)
	_, err := DecodeAndDecompressProfileFromBase64(encoded)
	var dec *ProfileDecodingError
	if !errors.As(err, &dec) {
		t.Errorf("expected ProfileDecodingError, got %v", err)
	}
}

func TestPermSerializesAsStringInEncodedProfile(t *testing.T) {
	orig := fullProfile()
	encoded, _ := CompressAndEncodeProfileToBase64(&orig)
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	jsonBytes, err := getZstdDecoder().DecodeAll(decoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(jsonBytes), `"perm":"write"`) {
		t.Errorf("expected perm as string in wire JSON, got %s", jsonBytes)
	}
}

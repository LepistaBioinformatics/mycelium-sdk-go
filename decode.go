package mycelium

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

var (
	zstdDecoder     *zstd.Decoder
	zstdDecoderOnce sync.Once
	zstdEncoder     *zstd.Encoder
	zstdEncoderOnce sync.Once
)

func getZstdDecoder() *zstd.Decoder {
	zstdDecoderOnce.Do(func() {
		zstdDecoder, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(0))
	})
	return zstdDecoder
}

func getZstdEncoder() *zstd.Encoder {
	zstdEncoderOnce.Do(func() {
		// SpeedDefault corresponds to zstd level 3, matching the gateway's
		// DEFAULT_COMPRESSION_LEVEL. (Level only affects output size; any valid
		// frame decodes regardless.)
		zstdEncoder, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	})
	return zstdEncoder
}

type decodeConfig struct {
	strict bool
}

// DecodeOption configures DecodeAndDecompressProfileFromBase64.
type DecodeOption func(*decodeConfig)

// WithStrict controls ZSTD failure handling. When strict (the default), a ZSTD
// decompression failure returns an error. When not strict, the Base64-decoded
// bytes are treated as already-uncompressed (dev mode where the gateway did not
// compress the profile).
func WithStrict(strict bool) DecodeOption {
	return func(c *decodeConfig) { c.strict = strict }
}

// DecodeAndDecompressProfileFromBase64 reverses the gateway's header encoding:
// Base64 STANDARD decode -> ZSTD decompress -> JSON deserialize. Any failure
// returns a *ProfileDecodingError.
func DecodeAndDecompressProfileFromBase64(input string, opts ...DecodeOption) (*Profile, error) {
	cfg := decodeConfig{strict: true}
	for _, o := range opts {
		o(&cfg)
	}

	if input == "" {
		return nil, NewProfileDecodingError("Profile input is empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, NewProfileDecodingError(fmt.Sprintf("Failed to decode base64 profile: %v", err))
	}

	decompressed, err := getZstdDecoder().DecodeAll(decoded, nil)
	if err != nil {
		if cfg.strict {
			return nil, NewProfileDecodingError(fmt.Sprintf("Failed to decompress zstd profile: %v", err))
		}
		decompressed = decoded
	}

	var p Profile
	if err := json.Unmarshal(decompressed, &p); err != nil {
		return nil, NewProfileDecodingError(fmt.Sprintf("Failed to deserialize profile: %v", err))
	}
	return &p, nil
}

// CompressAndEncodeProfileToBase64 mirrors the gateway encode chain: JSON
// serialize -> ZSTD compress (level 3) -> Base64 STANDARD. The output decodes
// with DecodeAndDecompressProfileFromBase64 and the gateway alike.
func CompressAndEncodeProfileToBase64(p *Profile) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("failed to serialize profile: %w", err)
	}
	compressed := getZstdEncoder().EncodeAll(data, nil)
	return base64.StdEncoding.EncodeToString(compressed), nil
}

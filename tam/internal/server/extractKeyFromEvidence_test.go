package server

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

const (
	sampleEvidenceHex = "" +
		"a708a201a4010220012158205886cd61dd875862e5aaa820e7a15274c968a9bc96048ddc" +
		"ace32f50c3651ba32258209eed8125e932cd60c0ead3650d0a485cf726d378d1b016ed42" +
		"98b2961e258f1b035820e96788b10b1610abe478f9ce8dcfe2304c0911dd8cfeadde25ec" +
		"30ccb5a7b5af0a49948f8860d13a463e8e190100500198f50a4ff6c05861c8860d13a638" +
		"ea1901024389482319010350549dcecc8b987c737b44e40f7c635ce81901048265312e33" +
		"2e34011901097475726e3a696574663a7266633a72666339373131"
)

func TestExtractCOSEKey(t *testing.T) {
	data := decodeHex(t, sampleEvidenceHex)

	key, err := ExtractCOSEKey(data)
	if err != nil {
		t.Fatalf("ExtractCOSEKey returned error: %v", err)
	}

	if key.Kty != 2 {
		t.Errorf("unexpected kty: got %d, want 2", key.Kty)
	}
	if key.Crv != 1 {
		t.Errorf("unexpected crv: got %d, want 1", key.Crv)
	}

	wantX := "5886cd61dd875862e5aaa820e7a15274c968a9bc96048ddcace32f50c3651ba3"
	if got := hex.EncodeToString(key.X); got != wantX {
		t.Errorf("unexpected x: got %s, want %s", got, wantX)
	}

	wantY := "9eed8125e932cd60c0ead3650d0a485cf726d378d1b016ed4298b2961e258f1b"
	if got := hex.EncodeToString(key.Y); got != wantY {
		t.Errorf("unexpected y: got %s, want %s", got, wantY)
	}

	wantKid := "e96788b10b1610abe478f9ce8dcfe2304c0911dd8cfeadde25ec30ccb5a7b5af"
	if got := hex.EncodeToString(key.Kid); got != wantKid {
		t.Errorf("unexpected kid: got %s, want %s", got, wantKid)
	}
}

func TestExtractCOSEKeyMissing(t *testing.T) {
	payload := mustMarshal(t, map[any]any{
		uint64(10): []byte{0x01}, // unrelated field
	})

	if _, err := ExtractCOSEKey(payload); !errors.Is(err, ErrCOSEKeyNotFound) {
		t.Fatalf("expected ErrCOSEKeyNotFound, got %v", err)
	}
}

func TestExtractCOSEKeyWithoutKid(t *testing.T) {
	coseKey := map[any]any{
		int64(1):  uint64(1),
		int64(-1): uint64(1),
		int64(-2): []byte{0x00},
		int64(-3): []byte{0x01},
	}
	payload := mustMarshal(t, map[any]any{
		uint64(8): map[any]any{
			uint64(1): coseKey,
		},
	})

	key, err := ExtractCOSEKey(payload)
	if err != nil {
		t.Fatalf("ExtractCOSEKey returned error: %v", err)
	}
	if key.Kid != nil {
		t.Fatalf("expected nil kid, got %x", key.Kid)
	}
}

func TestExtractCOSEKeyFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.cbor")

	data := decodeHex(t, sampleEvidenceHex)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	key, err := ExtractCOSEKeyFromFile(path)
	if err != nil {
		t.Fatalf("ExtractCOSEKeyFromFile returned error: %v", err)
	}

	if key == nil {
		t.Fatal("ExtractCOSEKeyFromFile returned nil key without error")
	}
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()

	clean := strings.TrimSpace(s)
	clean = strings.ReplaceAll(clean, "\n", "")

	data, err := hex.DecodeString(clean)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}
	return data
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()

	data, err := cbor.Marshal(value)
	if err != nil {
		t.Fatalf("failed to marshal CBOR: %v", err)
	}
	return data
}

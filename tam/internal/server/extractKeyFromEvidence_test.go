package server

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const sampleEvidence = `{
  / cnf / 8: {
    / COSE_Key / 1: {
      / kty / 1: 2 / EC2 /,
      / crv / -1: 1 / P-256 /,
      / x / -2: h'5886CD61DD875862E5AAA820E7A15274C968A9BC96048DDCACE32F50C3651BA3',
      / y / -3: h'9EED8125E932CD60C0EAD3650D0A485CF726D378D1B016ED4298B2961E258F1B'
    },
    / kid / 3: h'E96788B10B1610ABE478F9CE8DCFE2304C0911DD8CFEADDE25EC30CCB5A7B5AF'
  }
}`

func TestParseCOSEKey(t *testing.T) {
	key, err := parseCOSEKey(sampleEvidence)
	if err != nil {
		t.Fatalf("parseCOSEKey returned error: %v", err)
	}

	if key.Kty != 2 {
		t.Errorf("unexpected kty: got %d, want 2", key.Kty)
	}
	if key.Crv != 1 {
		t.Errorf("unexpected crv: got %d, want 1", key.Crv)
	}

	wantX := "5886cd61dd875862e5aaa820e7a15274c968a9bc96048ddcace32f50c3651ba3"
	if got := stringToHex(key.X); got != wantX {
		t.Errorf("unexpected x: got %s, want %s", got, wantX)
	}

	wantY := "9eed8125e932cd60c0ead3650d0a485cf726d378d1b016ed4298b2961e258f1b"
	if got := stringToHex(key.Y); got != wantY {
		t.Errorf("unexpected y: got %s, want %s", got, wantY)
	}

	wantKid := "e96788b10b1610abe478f9ce8dcfe2304c0911dd8cfeadde25ec30ccb5a7b5af"
	if got := stringToHex(key.Kid); got != wantKid {
		t.Errorf("unexpected kid: got %s, want %s", got, wantKid)
	}
}

func TestParseCOSEKeyMissing(t *testing.T) {
	_, err := parseCOSEKey("{ / cnf / 8: { } }")
	if !errors.Is(err, ErrCOSEKeyNotFound) {
		t.Fatalf("expected ErrCOSEKeyNotFound, got %v", err)
	}
}

func TestParseCOSEKeyWithoutKid(t *testing.T) {
	input := `{
  / cnf / 8: {
    / COSE_Key / 1: {
      / kty / 1: 1,
      / crv / -1: 1,
      / x / -2: h'00',
      / y / -3: h'01'
    }
  }
}`

	key, err := parseCOSEKey(input)
	if err != nil {
		t.Fatalf("parseCOSEKey returned error: %v", err)
	}
	if key.Kid != nil {
		t.Fatalf("expected nil kid, got %x", key.Kid)
	}
}

func TestExtractCOSEKeyFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.rediag")

	if err := os.WriteFile(path, []byte(sampleEvidence), 0o644); err != nil {
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

func stringToHex(data []byte) string {
	return hex.EncodeToString(data)
}

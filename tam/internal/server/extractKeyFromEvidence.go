package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ErrCOSEKeyNotFound indicates that the CBOR diagnostic text does not contain a COSE_Key entry.
var (
	ErrCOSEKeyNotFound = errors.New("COSE_Key not found")
	errAnchorNotFound  = errors.New("anchor not found")
)

// COSEKey captures the fields we care about from the COSE_Key map present in EAT evidence.
type COSEKey struct {
	Kty int
	Crv int
	X   []byte
	Y   []byte
	Kid []byte
}

// ExtractCOSEKeyFromFile loads a diagnostic notation (.rediag) file and returns the COSE_Key block.
func ExtractCOSEKeyFromFile(path string) (*COSEKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return parseCOSEKey(string(data))
}

func parseCOSEKey(src string) (*COSEKey, error) {
	cnfBlock, err := extractBlock(src, "/ cnf /")
	if err != nil {
		return nil, fmt.Errorf("extract cnf block: %w", err)
	}

	coseBlock, err := extractBlock(cnfBlock, "/ COSE_Key /")
	if err != nil {
		if errors.Is(err, errAnchorNotFound) {
			return nil, ErrCOSEKeyNotFound
		}
		return nil, fmt.Errorf("extract COSE_Key block: %w", err)
	}

	var key COSEKey
	if key.Kty, err = extractIntField(coseBlock, "/ kty /"); err != nil {
		return nil, err
	}
	if key.Crv, err = extractIntField(coseBlock, "/ crv /"); err != nil {
		return nil, err
	}
	if key.X, err = extractHexField(coseBlock, "/ x /"); err != nil {
		return nil, err
	}
	if key.Y, err = extractHexField(coseBlock, "/ y /"); err != nil {
		return nil, err
	}
	if kid, err := extractHexField(cnfBlock, "/ kid /"); err == nil {
		key.Kid = kid
	} else if !errors.Is(err, errAnchorNotFound) {
		return nil, err
	}

	return &key, nil
}

func extractBlock(src, anchor string) (string, error) {
	idx := strings.Index(src, anchor)
	if idx == -1 {
		return "", fmt.Errorf("%w: %s", errAnchorNotFound, anchor)
	}

	fragment := src[idx:]
	open := strings.Index(fragment, "{")
	if open == -1 {
		return "", fmt.Errorf("opening brace missing after %q", anchor)
	}

	content := fragment[open+1:]
	depth := 1
	for i := 0; i < len(content); i++ {
		switch content[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return content[:i], nil
			}
		}
	}

	return "", errors.New("unterminated block")
}

func extractIntField(src, anchor string) (int, error) {
	field, err := locateField(src, anchor)
	if err != nil {
		return 0, err
	}

	value := firstToken(field, func(r rune) bool {
		return r == '-' || ('0' <= r && r <= '9')
	})
	if value == "" {
		return 0, fmt.Errorf("no integer value found for %q", anchor)
	}

	out, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse integer for %q: %w", anchor, err)
	}
	return out, nil
}

func extractHexField(src, anchor string) ([]byte, error) {
	field, err := locateField(src, anchor)
	if err != nil {
		return nil, err
	}

	start := strings.Index(field, "h'")
	if start == -1 {
		return nil, fmt.Errorf("hex literal missing for %q", anchor)
	}
	start += 2

	end := strings.Index(field[start:], "'")
	if end == -1 {
		return nil, fmt.Errorf("unterminated hex literal for %q", anchor)
	}
	hexStr := field[start : start+end]

	if len(hexStr)%2 != 0 {
		return nil, fmt.Errorf("invalid hex string length for %q", anchor)
	}

	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("decode hex for %q: %w", anchor, err)
	}
	return data, nil
}

func locateField(src, anchor string) (string, error) {
	idx := strings.Index(src, anchor)
	if idx == -1 {
		return "", fmt.Errorf("%w: %s", errAnchorNotFound, anchor)
	}
	field := src[idx:]
	colon := strings.Index(field, ":")
	if colon == -1 {
		return "", fmt.Errorf("colon missing after %q", anchor)
	}
	return field[colon+1:], nil
}

func firstToken(input string, isAllowed func(r rune) bool) string {
	var builder strings.Builder
	started := false

	for _, r := range input {
		if !started {
			if isAllowed(r) {
				builder.WriteRune(r)
				started = true
			}
			continue
		}
		if !isAllowed(r) {
			break
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

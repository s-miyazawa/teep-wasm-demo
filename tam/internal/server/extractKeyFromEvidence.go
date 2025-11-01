package server

import (
	"errors"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
)

// ErrCOSEKeyNotFound indicates that the CBOR structure does not contain a COSE_Key entry.
var ErrCOSEKeyNotFound = errors.New("COSE_Key not found")

var errLabelNotFound = errors.New("label not found")

// COSEKey captures the fields we care about from the COSE_Key map present in EAT evidence.
type COSEKey struct {
	Kty int
	Crv int
	X   []byte
	Y   []byte
	Kid []byte
}

// ExtractCOSEKeyFromFile loads a COSE/CBOR file and returns the COSE_Key block.
func ExtractCOSEKeyFromFile(path string) (*COSEKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ExtractCOSEKey(data)
}

// ExtractCOSEKey decodes a COSE/CBOR payload and extracts the contained COSE_Key.
func ExtractCOSEKey(data []byte) (*COSEKey, error) {
	if len(data) == 0 {
		return nil, errors.New("COSE payload empty")
	}

	var decoded any
	if err := cbor.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("decode COSE CBOR: %w", err)
	}

	cnfMap, err := locateMap(decoded, 8) // 8 == cnf
	if err != nil {
		if errors.Is(err, errLabelNotFound) {
			return nil, ErrCOSEKeyNotFound
		}
		return nil, err
	}

	coseMap, err := locateMap(cnfMap, 1) // 1 == COSE_Key
	if err != nil {
		if errors.Is(err, errLabelNotFound) {
			return nil, ErrCOSEKeyNotFound
		}
		return nil, err
	}

	var key COSEKey
	if key.Kty, err = extractInt(coseMap, 1); err != nil { // 1 == kty
		return nil, err
	}
	if key.Crv, err = extractInt(coseMap, -1); err != nil { // -1 == crv
		return nil, err
	}
	if key.X, err = extractBytes(coseMap, -2); err != nil { // -2 == x
		return nil, err
	}
	if key.Y, err = extractBytes(coseMap, -3); err != nil { // -3 == y
		return nil, err
	}

	if kid, err := extractBytesOptional(cnfMap, 3); err == nil { // 3 == kid
		key.Kid = kid
	} else if err != nil && !errors.Is(err, errLabelNotFound) {
		return nil, err
	}

	return &key, nil
}

func locateMap(node any, label int64) (map[any]any, error) {
	m, err := toMap(node)
	if err != nil {
		return nil, err
	}
	value, ok := lookupLabel(m, label)
	if !ok {
		return nil, fmt.Errorf("%w: %d", errLabelNotFound, label)
	}
	out, err := toMap(value)
	if err != nil {
		return nil, fmt.Errorf("label %d is not a map: %w", label, err)
	}
	return out, nil
}

func extractInt(m map[any]any, label int64) (int, error) {
	value, ok := lookupLabel(m, label)
	if !ok {
		return 0, fmt.Errorf("%w: %d", errLabelNotFound, label)
	}

	switch v := value.(type) {
	case uint64:
		if v > uint64(^uint(0)>>1) {
			return 0, fmt.Errorf("integer overflow for label %d", label)
		}
		return int(v), nil
	case uint32:
		return int(v), nil
	case uint16:
		return int(v), nil
	case uint8:
		return int(v), nil
	case int64:
		return int(v), nil
	case int32:
		return int(v), nil
	case int16:
		return int(v), nil
	case int8:
		return int(v), nil
	case int:
		return v, nil
	case float64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("unsupported integer type %T for label %d", value, label)
	}
}

func extractBytes(m map[any]any, label int64) ([]byte, error) {
	value, ok := lookupLabel(m, label)
	if !ok {
		return nil, fmt.Errorf("%w: %d", errLabelNotFound, label)
	}
	return parseBytes(value, label)
}

func extractBytesOptional(m map[any]any, label int64) ([]byte, error) {
	value, ok := lookupLabel(m, label)
	if !ok {
		return nil, fmt.Errorf("%w: %d", errLabelNotFound, label)
	}
	return parseBytes(value, label)
}

func parseBytes(value any, label int64) ([]byte, error) {
	switch v := value.(type) {
	case []byte:
		return copyBytes(v), nil
	case cbor.RawMessage:
		return copyBytes(v), nil
	default:
		return nil, fmt.Errorf("unsupported byte string type %T for label %d", value, label)
	}
}

func lookupLabel(m map[any]any, label int64) (any, bool) {
	for key, value := range m {
		switch k := key.(type) {
		case uint64:
			if int64(k) == label {
				return value, true
			}
		case int64:
			if k == label {
				return value, true
			}
		case uint32:
			if int64(k) == label {
				return value, true
			}
		case int32:
			if int64(k) == label {
				return value, true
			}
		case uint16:
			if int64(k) == label {
				return value, true
			}
		case int16:
			if int64(k) == label {
				return value, true
			}
		case uint8:
			if int64(k) == label {
				return value, true
			}
		case int8:
			if int64(k) == label {
				return value, true
			}
		case int:
			if int64(k) == label {
				return value, true
			}
		case string:
			if k == fmt.Sprint(label) {
				return value, true
			}
		}
	}
	return nil, false
}

func toMap(value any) (map[any]any, error) {
	switch v := value.(type) {
	case map[any]any:
		return v, nil
	case map[string]any:
		out := make(map[any]any, len(v))
		for k, val := range v {
			out[k] = val
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected map, got %T", value)
	}
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

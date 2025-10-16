package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

var (
	updateArtifactAffirmingPath = filepath.Join("resources", "update.tam.esp256.cose")
	updateArtifactErrorPath     = filepath.Join("resources", "update.tam.esp256.error.cose")
)

// AttestationResponse represents the verifier response stored on disk.
type AttestationResponse struct {
	Status   string   `json:"status"`
	Nonce    string   `json:"nonce"`
	Expiry   string   `json:"expiry"`
	Accept   []string `json:"accept"`
	Evidence Evidence `json:"evidence"`
	Result   string   `json:"result"`
}

// Evidence captures the verifier evidence block.
type Evidence struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ProcessedAttestation collects the decoded assets derived from the verifier response.
type ProcessedAttestation struct {
	Response           *AttestationResponse
	EvidencePretty     string
	JWTHeaderPretty    string
	JWTPayloadPretty   string
	SendUpdate         bool
	updateArtifactPath string
	updateSelectionErr error
}

// DecodeAttestationResponse decodes the verifier response payload and prepares derived artefacts.
func DecodeAttestationResponse(payload []byte) (*ProcessedAttestation, error) {
	if len(payload) == 0 {
		return nil, errors.New("attestation response payload empty")
	}

	var resp AttestationResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil, fmt.Errorf("decode attestation response JSON: %w", err)
	}

	evidencePretty, err := resp.PrettyEvidence()
	if err != nil {
		return nil, fmt.Errorf("pretty print evidence: %w", err)
	}

	headerPretty, payloadPretty, err := resp.PrettyResultJWT()
	if err != nil {
		return nil, fmt.Errorf("pretty print result JWT: %w", err)
	}

	var payloadObj map[string]any
	if payloadPretty != "" {
		if err := json.Unmarshal([]byte(payloadPretty), &payloadObj); err != nil {
			return nil, fmt.Errorf("parse JWT payload JSON: %w", err)
		}
	}

	updatePath, selectionErr := selectUpdateArtifact(&resp, payloadObj)

	respCopy := resp

	return &ProcessedAttestation{
		Response:           &respCopy,
		EvidencePretty:     evidencePretty,
		JWTHeaderPretty:    headerPretty,
		JWTPayloadPretty:   payloadPretty,
		SendUpdate:         resp.ShouldSendUpdate(),
		updateArtifactPath: updatePath,
		updateSelectionErr: selectionErr,
	}, nil
}

// ShouldSendUpdate reports whether an Update message must be sent back to the client.
func (r *AttestationResponse) ShouldSendUpdate() bool {
	return strings.EqualFold(r.Status, "complete")
}

// PrettyEvidence decodes the CBOR evidence payload and returns a formatted JSON view.
func (r *AttestationResponse) PrettyEvidence() (string, error) {
	rawCBOR, err := decodeBase64String(r.Evidence.Value)
	if err != nil {
		return "", fmt.Errorf("decode evidence: %w", err)
	}

	if len(rawCBOR) == 0 {
		return "", errors.New("evidence CBOR payload empty")
	}

	var decoded any
	if err := cbor.Unmarshal(rawCBOR, &decoded); err != nil {
		return "", fmt.Errorf("unmarshal evidence CBOR: %w", err)
	}

	rendered, err := renderCBORPretty(decoded)
	if err != nil {
		return "", fmt.Errorf("render evidence CBOR: %w", err)
	}
	return rendered, nil
}

// PrettyResultJWT decodes the JWT header and payload parts, returning each in formatted JSON form.
func (r *AttestationResponse) PrettyResultJWT() (string, string, error) {
	if r.Result == "" {
		return "", "", errors.New("result field empty")
	}

	parts := strings.Split(r.Result, ".")
	if len(parts) < 2 {
		return "", "", errors.New("result field does not contain valid JWT segments")
	}

	headerPretty, err := decodeJWTSection(parts[0])
	if err != nil {
		return "", "", fmt.Errorf("decode JWT header: %w", err)
	}

	payloadPretty, err := decodeJWTSection(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("decode JWT payload: %w", err)
	}

	return headerPretty, payloadPretty, nil
}

func decodeJWTSection(segment string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", fmt.Errorf("parse JSON: %w", err)
	}

	pretty, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return "", fmt.Errorf("format JSON: %w", err)
	}
	return string(pretty), nil
}

func decodeBase64String(value string) ([]byte, error) {
	stripped := strings.TrimSpace(value)
	if stripped == "" {
		return nil, errors.New("base64 string empty")
	}

	var lastErr error
	decoders := [...]*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}

	for _, enc := range decoders {
		out, err := enc.DecodeString(stripped)
		if err == nil {
			return out, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("decode base64 string: %w", lastErr)
}

func selectUpdateArtifact(resp *AttestationResponse, payload map[string]any) (string, error) {
	if resp == nil || !resp.ShouldSendUpdate() {
		return "", nil
	}

	status, err := extractPSAIOTEarStatus(payload)
	if err != nil {
		return updateArtifactErrorPath, err
	}

	if strings.EqualFold(status, "affirming") {
		return updateArtifactAffirmingPath, nil
	}
	return updateArtifactErrorPath, nil
}

func extractPSAIOTEarStatus(payload map[string]any) (string, error) {
	if len(payload) == 0 {
		return "", errors.New("JWT payload empty")
	}

	submodsVal, ok := payload["submods"]
	if !ok {
		return "", errors.New("JWT payload missing submods")
	}
	submods, ok := submodsVal.(map[string]any)
	if !ok {
		return "", errors.New("JWT payload submods is not an object")
	}

	psaVal, ok := submods["PSA_IOT"]
	if !ok {
		return "", errors.New(`JWT payload missing submods["PSA_IOT"]`)
	}
	psa, ok := psaVal.(map[string]any)
	if !ok {
		return "", errors.New(`JWT payload submods["PSA_IOT"] is not an object`)
	}

	statusVal, ok := psa["ear.status"]
	if !ok {
		return "", errors.New(`JWT payload missing submods["PSA_IOT"]["ear.status"]`)
	}
	status, ok := statusVal.(string)
	if !ok {
		return "", errors.New(`JWT payload submods["PSA_IOT"]["ear.status"] is not a string`)
	}

	return strings.TrimSpace(status), nil
}

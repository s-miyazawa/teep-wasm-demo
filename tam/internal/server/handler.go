package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/s-miyazawa/tam4wasm-mock/resources"
)

const (
	maxRequestBodyBytes = 1 << 20 // 1 MiB should cover all test vectors.

	teepTypeUnknown       teepMessageType = 0
	teepTypeQueryRequest  teepMessageType = 1
	teepTypeQueryResponse teepMessageType = 2
	teepTypeUpdate        teepMessageType = 3
	teepTypeTeepError     teepMessageType = 4
	teepTypeSuccess       teepMessageType = 5
)

var (
	attestationPayloadPath        = filepath.Join("resources", "attestation_payload.bin")
	errAttestationPayloadNotFound = errors.New("attestation payload (TEEP field 7) not found")
)

type teepMessageType int

func (t teepMessageType) String() string {
	switch t {
	case teepTypeQueryRequest:
		return "query-request"
	case teepTypeQueryResponse:
		return "query-response"
	case teepTypeUpdate:
		return "update"
	case teepTypeTeepError:
		return "teep-error"
	case teepTypeSuccess:
		return "success"
	case teepTypeUnknown:
		return "unknown"
	default:
		return fmt.Sprintf("unknown(%d)", int(t))
	}
}

type handler struct {
	logger      *log.Logger
	disableCOSE bool
	verifier    *challengeClient
	assets      responseAssets
	attestation *ProcessedAttestation
}

type responseAssets struct {
	queryCOSE   []byte
	queryPlain  []byte
	updateCOSE  []byte
	updatePlain []byte
}

type responseSpec struct {
	status      int
	body        []byte
	contentType string
}

func newHandler(logger *log.Logger, disableCOSE bool, verifier *challengeClient) (*handler, error) {
	a := responseAssets{
		queryCOSE:   bytes.Clone(resources.QueryRequestCOSE),
		queryPlain:  bytes.Clone(resources.QueryRequestPlain),
		updateCOSE:  bytes.Clone(resources.UpdateCOSE),
		updatePlain: bytes.Clone(resources.UpdatePlain),
	}

	if len(a.queryCOSE) == 0 {
		return nil, errors.New("missing embedded query request COSE payload")
	}
	if len(a.updateCOSE) == 0 {
		return nil, errors.New("missing embedded update COSE payload")
	}

	return &handler{
		logger:      logger,
		disableCOSE: disableCOSE,
		verifier:    verifier,
		assets:      a,
	}, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/tam/" {
		http.NotFound(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes))
	if err != nil {
		h.logger.Printf("failed reading request body: %v", err)
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	if err := r.Body.Close(); err != nil {
		h.logger.Printf("failed closing request body: %v", err)
	}

	msgType, payload := detectTeepMessage(body)

	resp := h.pickResponse(msgType)

	h.writeResponse(w, resp)

	if msgType == teepTypeQueryResponse {
		h.logQueryResponseCBOR(payload)
	}

	h.logger.Printf("Received message type %s -> sent %s.", msgType.String(), resp.describe())
}

func (h *handler) logQueryResponseCBOR(payload []byte) {
	if len(payload) == 0 {
		h.logger.Printf("QueryResponse payload missing; unable to pretty print CBOR contents.")
		return
	}

	var decoded any
	if err := cbor.Unmarshal(payload, &decoded); err != nil {
		h.logger.Printf("failed to decode QueryResponse payload: %v", err)
		if diag, diagErr := cbor.Diagnose(payload); diagErr == nil {
			h.logger.Printf("QueryResponse payload (diagnostic notation):\n%s", diag)
		}
		h.logger.Printf("QueryResponse payload (hex): %x", payload)
		return
	}

	rendered, err := renderCBORPretty(decoded)
	if err != nil {
		h.logger.Printf("failed to pretty print QueryResponse payload: %v", err)
		if diag, diagErr := cbor.Diagnose(payload); diagErr == nil {
			h.logger.Printf("QueryResponse payload (diagnostic notation):\n%s", diag)
		}
	} else {
		h.logger.Printf("QueryResponse payload (COSE CBOR):\n%s", rendered)
	}

	attestation, err := extractAttestationPayload(decoded)
	if err != nil {
		if errors.Is(err, errAttestationPayloadNotFound) {
			h.logger.Printf("QueryResponse missing attestation-payload (field 7).")
			return
		}
		h.logger.Printf("failed to extract attestation payload: %v", err)
		return
	}

	if err := h.submitAttestationPayload(attestation); err != nil {
		h.logger.Printf("failed to save attestation payload: %v", err)
		return
	}

	h.logger.Printf("Saved attestation payload to %s (%d bytes).", attestationPayloadPath, len(attestation))
}

func (h *handler) pickResponse(msgType teepMessageType) responseSpec {
	switch msgType {
	case teepTypeQueryResponse:
		if h.shouldSendUpdate() {
			return h.newUpdateResponse()
		}
		return responseSpec{status: http.StatusNoContent}
	case teepTypeSuccess:
		return responseSpec{status: http.StatusNoContent}
	default:
		return h.newQueryRequestResponse()
	}
}

func (h *handler) newQueryRequestResponse() responseSpec {
	body := h.assets.queryCOSE
	if h.disableCOSE && len(h.assets.queryPlain) > 0 {
		body = h.assets.queryPlain
	}
	return newCBORResponse(http.StatusOK, body)
}

func (h *handler) newUpdateResponse() responseSpec {
	if h.disableCOSE && len(h.assets.updatePlain) > 0 {
		return newCBORResponse(http.StatusOK, h.assets.updatePlain)
	}

	body := h.assets.updateCOSE
	if path, ok := h.selectedUpdateArtifact(); ok {
		data, err := os.ReadFile(path)
		if err != nil {
			if h.logger != nil {
				h.logger.Printf("Failed to read selected update artifact %s: %v", path, err)
			}
		} else {
			body = data
		}
	}
	return newCBORResponse(http.StatusOK, body)
}

func (h *handler) shouldSendUpdate() bool {
	if h.attestation == nil {
		return false
	}
	return h.attestation.SendUpdate
}

func (h *handler) writeResponse(w http.ResponseWriter, spec responseSpec) {
	w.Header().Set("Server", "Bar/2.2")

	if len(spec.body) > 0 {
		for k, v := range defaultHeaders {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", spec.contentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(spec.body)))
		w.WriteHeader(spec.status)
		if _, err := w.Write(spec.body); err != nil {
			h.logger.Printf("failed writing response body: %v", err)
		}
		return
	}

	w.WriteHeader(spec.status)
}

func (r responseSpec) describe() string {
	switch r.status {
	case http.StatusNoContent:
		return "HTTP 204 No Content"
	default:
		return fmt.Sprintf("HTTP %d (%s payload)", r.status, r.contentType)
	}
}

func newCBORResponse(status int, body []byte) responseSpec {
	return responseSpec{
		status:      status,
		body:        body,
		contentType: "application/teep+cbor",
	}
}

var defaultHeaders = map[string]string{
	"Cache-Control":           "no-store",
	"X-Content-Type-Options":  "nosniff",
	"Content-Security-Policy": "default-src 'none'",
	"Referrer-Policy":         "no-referrer",
}

func detectTeepMessage(raw []byte) (teepMessageType, []byte) {
	if len(raw) == 0 {
		return teepTypeUnknown, nil
	}

	// Try COSE_Sign1
	var sign1 cose.Sign1Message
	if err := sign1.UnmarshalCBOR(raw); err == nil {
		payload := bytes.Clone(sign1.Payload)
		if msgType, ok := extractTeepType(payload); ok {
			return msgType, payload
		}
	}

	// Try COSE_Sign
	var sign cose.SignMessage
	if err := sign.UnmarshalCBOR(raw); err == nil {
		payload := bytes.Clone(sign.Payload)
		if msgType, ok := extractTeepType(payload); ok {
			return msgType, payload
		}
	}

	if msgType, ok := extractTeepType(raw); ok {
		return msgType, bytes.Clone(raw)
	}

	return teepTypeUnknown, nil
}

func extractTeepType(payload []byte) (teepMessageType, bool) {
	if len(payload) == 0 {
		return teepTypeUnknown, false
	}

	var msg []any
	if err := cbor.Unmarshal(payload, &msg); err != nil {
		return teepTypeUnknown, false
	}
	if len(msg) == 0 {
		return teepTypeUnknown, false
	}

	switch v := msg[0].(type) {
	case uint64:
		return teepMessageType(v), true
	case int64:
		return teepMessageType(v), true
	case int:
		return teepMessageType(v), true
	default:
		return teepTypeUnknown, false
	}
}

func renderCBORPretty(decoded any) (string, error) {
	normalised, err := normaliseCBORForJSON(decoded)
	if err != nil {
		return "", err
	}

	pretty, err := json.MarshalIndent(normalised, "", "  ")
	if err != nil {
		return "", err
	}
	return string(pretty), nil
}

func normaliseCBORForJSON(value any) (any, error) {
	switch v := value.(type) {
	case []any:
		out := make([]any, len(v))
		for i, elem := range v {
			norm, err := normaliseCBORForJSON(elem)
			if err != nil {
				return nil, err
			}
			out[i] = norm
		}
		return out, nil
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		out := make(map[string]any, len(v))
		for _, k := range keys {
			norm, err := normaliseCBORForJSON(v[k])
			if err != nil {
				return nil, err
			}
			out[k] = norm
		}
		return out, nil
	case map[any]any:
		type entry struct {
			key string
			val any
		}

		entries := make([]entry, 0, len(v))
		for key, val := range v {
			keyStr := stringifyCBORKey(key)
			norm, err := normaliseCBORForJSON(val)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry{key: keyStr, val: norm})
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].key < entries[j].key
		})

		out := make(map[string]any, len(entries))
		for _, e := range entries {
			out[e.key] = e.val
		}
		return out, nil
	case []byte:
		return fmt.Sprintf("h'%x'", v), nil
	case cbor.Tag:
		content, err := normaliseCBORForJSON(v.Content)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"_cborTag": v.Number,
			"content":  content,
		}, nil
	default:
		return v, nil
	}
}

func stringifyCBORKey(key any) string {
	switch k := key.(type) {
	case string:
		return k
	case fmt.Stringer:
		return k.String()
	case []byte:
		return fmt.Sprintf("h'%x'", k)
	default:
		return fmt.Sprint(k)
	}
}

func extractAttestationPayload(value any) ([]byte, error) {
	data, found, err := findAttestationPayload(value)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errAttestationPayloadNotFound
	}
	return data, nil
}

func findAttestationPayload(value any) ([]byte, bool, error) {
	switch v := value.(type) {
	case cbor.Tag:
		return findAttestationPayload(v.Content)
	case []any:
		for _, elem := range v {
			data, found, err := findAttestationPayload(elem)
			if err != nil || found {
				return data, found, err
			}
		}
		return nil, false, nil
	case map[any]any:
		for key, elem := range v {
			if isAttestationKey(key) {
				data, ok := cloneBytes(elem)
				if !ok {
					return nil, true, fmt.Errorf("attestation-payload (field 7) has unsupported type %T", elem)
				}
				return data, true, nil
			}
			data, found, err := findAttestationPayload(elem)
			if err != nil || found {
				return data, found, err
			}
		}
		return nil, false, nil
	default:
		return nil, false, nil
	}
}

func cloneBytes(content any) ([]byte, bool) {
	switch c := content.(type) {
	case []byte:
		return bytes.Clone(c), true
	case cbor.RawMessage:
		return bytes.Clone(c), true
	case cbor.Tag:
		return cloneBytes(c.Content)
	default:
		return nil, false
	}
}

func isAttestationKey(key any) bool {
	return fmt.Sprint(key) == "7"
}

func (h *handler) selectedUpdateArtifact() (string, bool) {
	if h.attestation == nil {
		return "", false
	}
	if h.attestation.updateArtifactPath == "" {
		return "", false
	}
	return h.attestation.updateArtifactPath, true
}

func (h *handler) updateAttestation(att *ProcessedAttestation) {
	if att == nil {
		return
	}

	h.attestation = att

	if h.logger == nil {
		return
	}
	if att.updateArtifactPath != "" {
		h.logger.Printf("Selected update artifact: %s", att.updateArtifactPath)
	}
	if att.updateSelectionErr != nil {
		h.logger.Printf("Update artifact selection fallback: %v", att.updateSelectionErr)
	}
}

func (h *handler) submitAttestationPayload(data []byte) error {
	if h.verifier != nil {
		att, err := h.verifier.process(data)
		if err != nil {
			h.logger.Printf("challenge-response submission failed: %v", err)
		} else {
			h.updateAttestation(att)
		}
	}
	return nil
}

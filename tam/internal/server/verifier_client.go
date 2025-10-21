package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	challengeNonce              = "QUp8F0FBs9DpodKK8xUg8NQimf6sQAfe2J1ormzZLxk="
	defaultChallengeTimeout     = 60 * time.Second
	defaultChallengeUserAgent   = "tam4wasm-mock/cha-client"
	defaultChallengeContentType = "application/psa-attestation-token"
)

type challengeConfig struct {
	BaseURL     string
	ContentType string
	InsecureTLS bool
	Timeout     time.Duration
	Logger      *log.Logger
}

type challengeClient struct {
	baseURL     *url.URL
	httpClient  *http.Client
	contentType string
	timeout     time.Duration
	logger      *log.Logger
}

func newChallengeClient(cfg challengeConfig) (*challengeClient, error) {
	if cfg.BaseURL == "" {
		return nil, nil
	}

	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse challenge server URL: %w", err)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultChallengeTimeout
	}

	transport := &http.Transport{}
	if base.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.InsecureTLS}
	}

	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	return &challengeClient{
		baseURL:     base,
		httpClient:  httpClient,
		contentType: cfg.ContentType,
		timeout:     timeout,
		logger:      cfg.Logger,
	}, nil
}

func (c *challengeClient) process(payload []byte) (*ProcessedAttestation, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("refusing to submit empty payload")
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	sessionURL, err := c.createSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("create challenge session: %w", err)
	}

	responseBody, err := c.submitPayload(ctx, sessionURL, payload)
	if err != nil {
		return nil, fmt.Errorf("submit evidence: %w", err)
	}

	logVerifierResponse(c.logger, responseBody)

	att, decodeErr := DecodeAttestationResponse(responseBody)
	if decodeErr != nil {
		return nil, fmt.Errorf("decode attestation response: %w", decodeErr)
	}

	return att, nil
}

func (c *challengeClient) createSession(ctx context.Context) (*url.URL, error) {
	newSessionURL, err := c.baseURL.Parse("/challenge-response/v1/newSession")
	if err != nil {
		return nil, fmt.Errorf("build new session URL: %w", err)
	}

	query := newSessionURL.Query()
	query.Set("nonce", challengeNonce)
	newSessionURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, newSessionURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", defaultChallengeUserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perform request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("unexpected session status %s: %s", resp.Status, bytes.TrimSpace(body))
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return nil, fmt.Errorf("session response missing Location header")
	}

	sessionURL, err := newSessionURL.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("parse session location %q: %w", location, err)
	}

	if c.logger != nil {
		if sessionID := extractSessionID(sessionURL); sessionID != "" {
			c.logger.Printf("Challenge session UUID %s", sessionID)
		}
	}

	return sessionURL, nil
}

func (c *challengeClient) submitPayload(ctx context.Context, sessionURL *url.URL, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sessionURL.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create payload request: %w", err)
	}

	contentType := c.contentType
	if contentType == "" {
		contentType = defaultChallengeContentType
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", defaultChallengeUserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perform payload request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("unexpected evidence status %s: %s", resp.Status, bytes.TrimSpace(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	return body, nil
}

func logVerifierResponse(logger *log.Logger, body []byte) {
	baseLogger := logger
	if baseLogger == nil {
		baseLogger = log.Default()
	}

	decoded, decodeErr := renderDecodedVerifierResponse(body)
	if decodeErr != nil {
		baseLogger.Printf("Verifier response body:\n%s", string(body))
		baseLogger.Printf("Failed to decode verifier response for pretty print: %v", decodeErr)
		return
	}

	baseLogger.Printf("Verifier response (decoded):\n%s", decoded)
}

func extractSessionID(u *url.URL) string {
	if u == nil {
		return ""
	}
	path := u.Path
	if path == "" {
		return ""
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func renderDecodedVerifierResponse(body []byte) (string, error) {
	var printable map[string]any
	if err := json.Unmarshal(body, &printable); err != nil {
		return "", fmt.Errorf("decode JSON: %w", err)
	}

	var resp AttestationResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("decode attestation response: %w", err)
	}

	if evidenceMap, ok := printable["evidence"].(map[string]any); ok {
		if prettyEvidence, err := resp.PrettyEvidence(); err == nil && prettyEvidence != "" {
			var decoded any
			if err := json.Unmarshal([]byte(prettyEvidence), &decoded); err == nil {
				evidenceMap["decoded"] = decoded
			}
		}
	}

	if headerPretty, payloadPretty, err := resp.PrettyResultJWT(); err == nil {
		var headerObj any
		if err := json.Unmarshal([]byte(headerPretty), &headerObj); err != nil {
			return "", fmt.Errorf("decode JWT header JSON: %w", err)
		}

		var payloadObj any
		if err := json.Unmarshal([]byte(payloadPretty), &payloadObj); err != nil {
			return "", fmt.Errorf("decode JWT payload JSON: %w", err)
		}

		printable["result"] = map[string]any{
			"header":  headerObj,
			"payload": payloadObj,
		}
	}

	formatted, err := json.MarshalIndent(printable, "", "  ")
	if err != nil {
		return "", fmt.Errorf("pretty print decoded response: %w", err)
	}
	return string(formatted), nil
}

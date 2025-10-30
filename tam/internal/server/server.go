/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"
)

// Config captures the tunables required to start the TAM mock server.
type Config struct {
	Addr                 string
	DisableCOSE          bool
	Logger               *log.Logger
	ChallengeServerURL   string
	ChallengeContentType string
	ChallengeInsecureTLS bool
	ChallengeTimeout     time.Duration
}

// Server wires the HTTP listener and request handling stack.
type Server struct {
	cfg     Config
	handler *handler
	http    *http.Server
	logger  *log.Logger
}

// New constructs a Server using the provided configuration.
func New(cfg Config) (*Server, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	challengeClient, err := newChallengeClient(challengeConfig{
		BaseURL:     cfg.ChallengeServerURL,
		ContentType: cfg.ChallengeContentType,
		InsecureTLS: cfg.ChallengeInsecureTLS,
		Timeout:     cfg.ChallengeTimeout,
		Logger:      logger,
	})
	if err != nil {
		return nil, err
	}

	h, err := newHandler(logger, cfg.DisableCOSE, challengeClient)
	if err != nil {
		return nil, err
	}

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return &Server{
		cfg:     cfg,
		handler: h,
		http:    httpSrv,
		logger:  logger,
	}, nil
}

// ListenAndServe starts the HTTP server and blocks until it stops.
func (s *Server) ListenAndServe() error {
	s.logger.Printf("Run TAM Server on %s.", s.http.Addr)

	err := s.http.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown gracefully takes down the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// Package core defines the TrapModule plugin interface, Persona loader, and
// Canary Token generator used by all sensor protocol engines.
package core

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// CanaryTokenKind is the type of canary token.
type CanaryTokenKind string

const (
	// CanaryTokenCredential is a fake credential embedded in a decoy response.
	CanaryTokenCredential CanaryTokenKind = "credential"
	// CanaryTokenURL is a fake callback URL embedded in a decoy response.
	CanaryTokenURL CanaryTokenKind = "url"
)

// CanaryToken is a unique, session-bound fake credential/URL injected into
// decoy responses. Reuse of a canary token links the original reconnaissance
// session to secondary attacker infrastructure.
type CanaryToken struct {
	ID        string          `json:"id"`
	Token     string          `json:"token"`
	SessionID string          `json:"session_id"`
	Kind      CanaryTokenKind `json:"kind"`
	CreatedAt time.Time       `json:"created_at"`
	Value     string          `json:"value"`
}

// Generator creates session-bound canary tokens and tracks them for
// callback attribution.
type Generator struct {
	mu       sync.RWMutex
	tokens   map[string]*CanaryToken   // token -> CanaryToken
	sessions map[string][]*CanaryToken // sessionID -> tokens
}

// NewGenerator creates a canary token generator.
func NewGenerator() *Generator {
	return &Generator{
		tokens:   make(map[string]*CanaryToken),
		sessions: make(map[string][]*CanaryToken),
	}
}

// Generate creates a unique canary token bound to the given session.
func (g *Generator) Generate(sessionID string, kind CanaryTokenKind, value string) (*CanaryToken, error) {
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	t := &CanaryToken{
		ID:        "cnry_" + token,
		Token:     token,
		SessionID: sessionID,
		Kind:      kind,
		CreatedAt: time.Now().UTC(),
		Value:     value,
	}
	g.mu.Lock()
	g.tokens[token] = t
	g.sessions[sessionID] = append(g.sessions[sessionID], t)
	g.mu.Unlock()
	return t, nil
}

// Validate returns true if the token exists and was issued.
func (g *Generator) Validate(token string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	_, ok := g.tokens[token]
	return ok
}

// SessionTokens returns all tokens issued for a session.
func (g *Generator) SessionTokens(sessionID string) []*CanaryToken {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.sessions[sessionID]
}

// Len returns the total number of tokens issued.
func (g *Generator) Len() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.tokens)
}

// newToken generates a random hex token.
func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

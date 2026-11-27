package core

import (
	"testing"
)

func TestCanaryTokenGenerate(t *testing.T) {
	g := NewGenerator()
	if g.Len() != 0 {
		t.Fatalf("expected empty generator")
	}

	t1, err := g.Generate("sess-1", CanaryTokenCredential, "fake-password")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if t1.ID == "" || t1.Token == "" || t1.SessionID != "sess-1" || t1.Kind != CanaryTokenCredential || t1.Value != "fake-password" {
		t.Fatalf("unexpected token: %+v", t1)
	}
	if t1.CreatedAt.IsZero() {
		t.Fatal("expected created_at")
	}

	t2, err := g.Generate("sess-1", CanaryTokenURL, "http://callback")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Tokens must be unique
	if t1.Token == t2.Token {
		t.Fatal("expected unique tokens")
	}

	if g.Len() != 2 {
		t.Fatalf("expected len 2, got %d", g.Len())
	}
}

func TestCanaryTokenValidate(t *testing.T) {
	g := NewGenerator()
	tok, _ := g.Generate("sess-1", CanaryTokenCredential, "val")
	if !g.Validate(tok.Token) {
		t.Fatal("expected valid token")
	}
	if g.Validate("nonexistent") {
		t.Fatal("expected invalid token")
	}
}

func TestCanaryTokenSessionTokens(t *testing.T) {
	g := NewGenerator()
	g.Generate("sess-1", CanaryTokenCredential, "a")
	g.Generate("sess-1", CanaryTokenURL, "b")
	g.Generate("sess-2", CanaryTokenCredential, "c")

	tokens := g.SessionTokens("sess-1")
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens for sess-1, got %d", len(tokens))
	}
	tokens = g.SessionTokens("sess-2")
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token for sess-2, got %d", len(tokens))
	}
	tokens = g.SessionTokens("missing")
	if len(tokens) != 0 {
		t.Fatalf("expected 0 tokens for missing session, got %d", len(tokens))
	}
}

func TestCanaryTokenKind(t *testing.T) {
	if CanaryTokenCredential != "credential" {
		t.Errorf("CanaryTokenCredential = %s", CanaryTokenCredential)
	}
	if CanaryTokenURL != "url" {
		t.Errorf("CanaryTokenURL = %s", CanaryTokenURL)
	}
}

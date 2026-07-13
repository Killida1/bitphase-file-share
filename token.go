package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// clientToken mirrors broker.ClientToken's JSON shape (broker/types.go).
// Duplicated rather than imported — chat-server is an independently
// deployable binary with its own go.mod (STACK.md: at most one near-stdlib
// dependency, no shared internal module across services), and this is a
// small, easy-to-audit struct, not a maintenance burden worth a shared
// package for.
type clientToken struct {
	ClientID  string `json:"client_id"`
	Tier      string `json:"tier"`
	Plan      string `json:"plan,omitempty"` // "vpn" or "full" — see broker.ClientToken.Plan; empty (legacy tokens, or Tier=="free") is treated as "full" below
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// tierRank orders tiers so verifyToken can accept "at least minTier"
// instead of hardcoding "paid" — lets file-share run free-tier-accessible
// during local testing (-min-tier=free) without ripping out the check.
var tierRank = map[string]int{"free": 0, "paid": 1}

// verifyToken checks a broker-issued access token — "<base64
// payload>.<base64 signature>", the same concatenation
// website/lib/broker.js builds from POST /enroll's response body and
// X-Signature header — entirely offline against the broker's public key.
// No callback to the broker happens here, matching WHITEPAPER §7.5's
// "self-contained and self-verifying" design. minTier defaults to "paid"
// (WHITEPAPER §9 — file-share is paid-tier only) but is settable to "free"
// via -min-tier for testing before real payments are wired up.
func verifyToken(brokerPub ed25519.PublicKey, token string, minTier string) (clientToken, error) {
	payloadB64, sigB64, ok := strings.Cut(token, ".")
	if !ok {
		return clientToken{}, errors.New("malformed token: expected <payload>.<signature>")
	}
	payload, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return clientToken{}, errors.New("malformed token payload encoding")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return clientToken{}, errors.New("malformed token signature encoding")
	}
	if !ed25519.Verify(brokerPub, payload, sig) {
		return clientToken{}, errors.New("token signature verification failed")
	}
	var tok clientToken
	if err := json.Unmarshal(payload, &tok); err != nil {
		return clientToken{}, errors.New("malformed token claims")
	}
	if tierRank[tok.Tier] < tierRank[minTier] {
		return clientToken{}, errors.New("token tier " + tok.Tier + " is below the required " + minTier + " tier")
	}
	// File-share requires the "full" plan (MONETIZATION.md §5.2) — a
	// "vpn"-plan paid token is legitimately paid but didn't buy chat/file-share.
	// Empty is treated as "full": either a legacy token minted before Plan
	// existed, or Tier=="free" (already rejected above by the tier check
	// whenever minTier is "paid", so Plan is moot for it either way).
	if tok.Plan != "" && tok.Plan != "full" {
		return clientToken{}, errors.New("token plan " + tok.Plan + " does not include this service")
	}
	if time.Now().Unix() > tok.ExpiresAt {
		return clientToken{}, errors.New("token expired")
	}
	return tok, nil
}

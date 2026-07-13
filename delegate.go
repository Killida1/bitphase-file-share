package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// This file mirrors mesh-host/connect/main.go's resolveVerificationKey and
// broker/delegate.go's loadDelegateIdentity — file-share is a separate
// binary with its own go.mod (STACK.md: no shared internal module across
// services), so the delegateCertBody shape and verification logic are
// duplicated here rather than imported, same reasoning as clientToken in
// token.go (and the identical copy of this file in chat-server/delegate.go).
// See broker/KEY_POLICY.md §4 for why this rollout exists: the broker's
// root+delegate model (-key-mode=delegate) isn't safe to deploy until every
// verifier that used to pin a flat BROKER_PUBKEY does this chain check
// instead.

type delegateCertBody struct {
	DelegatePubKey string `json:"delegate_pubkey"`
	RootPubKey     string `json:"root_pubkey"`
	IssuedAt       int64  `json:"issued_at"`
	ExpiresAt      int64  `json:"expires_at"`
}

// brokerKeySource is what verifyToken's caller actually reads from — either
// a static flat pubkey (legacy mode, unchanged default behavior) or a
// periodically-refreshed root-certified delegate pubkey (delegate mode).
// Safe for concurrent use: a new WebSocket connection's auth check and the
// background refresh loop can both touch it at once.
type brokerKeySource struct {
	mu        sync.RWMutex
	pub       ed25519.PublicKey
	expiresAt int64 // unix seconds; 0 means "no expiry" (legacy mode)
}

func newStaticKeySource(pub ed25519.PublicKey) *brokerKeySource {
	return &brokerKeySource{pub: pub}
}

// current returns the pubkey to verify against right now, or an error if
// delegate mode's cached certificate has genuinely expired — fails closed
// rather than silently verifying against a lapsed trust chain, matching
// loadDelegateIdentity's own posture in broker/delegate.go.
func (s *brokerKeySource) current() (ed25519.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.expiresAt != 0 && time.Now().Unix() > s.expiresAt {
		return nil, fmt.Errorf("cached delegate certificate has expired and could not be refreshed — refusing to verify")
	}
	return s.pub, nil
}

func (s *brokerKeySource) set(pub ed25519.PublicKey, expiresAt int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pub = pub
	s.expiresAt = expiresAt
}

// resolveDelegateKey fetches the broker's current delegate certificate,
// verifies it against the pinned root, and returns the certified delegate
// pubkey plus its expiry. Byte-for-byte the same chain mesh-host/connect's
// resolveVerificationKey checks.
func resolveDelegateKey(client *http.Client, brokerURL string, rootPub ed25519.PublicKey) (ed25519.PublicKey, int64, error) {
	resp, err := client.Get(brokerURL + "/broker/delegate-cert")
	if err != nil {
		return nil, 0, fmt.Errorf("fetching delegate cert: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("delegate cert request failed: %s: %s", resp.Status, string(body))
	}
	sig, err := unb64(resp.Header.Get("X-Signature"))
	if err != nil {
		return nil, 0, fmt.Errorf("missing/invalid X-Signature header on delegate cert")
	}
	if !ed25519.Verify(rootPub, body, sig) {
		return nil, 0, fmt.Errorf("delegate certificate signature verification FAILED against the pinned root pubkey — refusing to trust it")
	}
	var cert delegateCertBody
	if err := json.Unmarshal(body, &cert); err != nil {
		return nil, 0, fmt.Errorf("delegate cert is not valid JSON: %w", err)
	}
	if cert.RootPubKey != b64(rootPub) {
		return nil, 0, fmt.Errorf("delegate cert was minted for a different root pubkey than the one pinned here")
	}
	now := time.Now().Unix()
	if now < cert.IssuedAt || now > cert.ExpiresAt {
		return nil, 0, fmt.Errorf("delegate cert is not currently valid (issued_at=%d expires_at=%d now=%d)", cert.IssuedAt, cert.ExpiresAt, now)
	}
	delegatePubRaw, err := unb64(cert.DelegatePubKey)
	if err != nil || len(delegatePubRaw) != ed25519.PublicKeySize {
		return nil, 0, fmt.Errorf("delegate cert's delegate_pubkey is not a valid Ed25519 public key")
	}
	return ed25519.PublicKey(delegatePubRaw), cert.ExpiresAt, nil
}

// newDelegateKeySource resolves the delegate chain once synchronously (fails
// startup on error, matching loadDelegateIdentity's fail-closed behavior —
// a file-share that can't verify its trust chain shouldn't start accepting
// connections it can't actually authenticate) and starts a background
// refresh loop so a broker-side delegate rotation (broker/KEY_POLICY.md v2's
// "no hard break, no manual client re-trust" rotation runbook) is picked up
// without restarting file-share. 30-minute interval — delegate TTLs in
// practice are weeks/months (KEY_POLICY.md's own example is 720h), so this
// is comfortably frequent without hammering the broker.
func newDelegateKeySource(client *http.Client, brokerURL string, rootPub ed25519.PublicKey) (*brokerKeySource, error) {
	pub, expiresAt, err := resolveDelegateKey(client, brokerURL, rootPub)
	if err != nil {
		return nil, fmt.Errorf("resolving initial delegate key: %w", err)
	}
	src := &brokerKeySource{pub: pub, expiresAt: expiresAt}
	if remaining := time.Unix(expiresAt, 0).Sub(time.Now()); remaining < 7*24*time.Hour {
		log.Printf("WARNING: broker delegate certificate expires in %s — mint and deploy a replacement soon", remaining.Round(time.Hour))
	}

	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			newPub, newExpiresAt, err := resolveDelegateKey(client, brokerURL, rootPub)
			if err != nil {
				// Fail safe, not fail open: keep serving the last-known-good
				// delegate key across a transient refresh failure (broker
				// restart, network blip) instead of breaking every in-flight
				// auth check — current() above still fails closed once the
				// cached cert's own expiry genuinely passes.
				log.Printf("WARNING: delegate key refresh failed, keeping last-known-good key: %v", err)
				continue
			}
			src.set(newPub, newExpiresAt)
			if remaining := time.Unix(newExpiresAt, 0).Sub(time.Now()); remaining < 7*24*time.Hour {
				log.Printf("WARNING: broker delegate certificate expires in %s — mint and deploy a replacement soon", remaining.Round(time.Hour))
			}
		}
	}()

	return src, nil
}

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func mustGenKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

// fakeDelegateCertServer mirrors mesh-host/connect/connect_delegate_test.go's
// helper of the same name (and chat-server/delegate_test.go's identical
// copy) — stands in for a real broker running -key-mode=delegate, serving
// GET /broker/delegate-cert with the same byte-exact body+X-Signature
// contract broker/handlers.go's real handleDelegateCert uses.
func fakeDelegateCertServer(t *testing.T, rootPub ed25519.PublicKey, rootPriv ed25519.PrivateKey, delegatePub ed25519.PublicKey, issuedAt, expiresAt time.Time) *httptest.Server {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"delegate_pubkey": base64.StdEncoding.EncodeToString(delegatePub),
		"root_pubkey":     base64.StdEncoding.EncodeToString(rootPub),
		"issued_at":       issuedAt.Unix(),
		"expires_at":      expiresAt.Unix(),
	})
	if err != nil {
		t.Fatalf("marshal cert body: %v", err)
	}
	sig := ed25519.Sign(rootPriv, body)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/broker/delegate-cert" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("X-Signature", base64.StdEncoding.EncodeToString(sig))
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
}

func TestResolveDelegateKeyAcceptsValidChain(t *testing.T) {
	rootPub, rootPriv := mustGenKeyPair(t)
	delegatePub, _ := mustGenKeyPair(t)
	now := time.Now()
	srv := fakeDelegateCertServer(t, rootPub, rootPriv, delegatePub, now.Add(-time.Hour), now.Add(30*24*time.Hour))
	defer srv.Close()

	got, expiresAt, err := resolveDelegateKey(&http.Client{}, srv.URL, rootPub)
	if err != nil {
		t.Fatalf("resolveDelegateKey: %v", err)
	}
	if !got.Equal(delegatePub) {
		t.Fatal("resolved verification key does not match the delegate pubkey certified by the root")
	}
	if expiresAt != now.Add(30*24*time.Hour).Unix() {
		t.Fatal("resolved expiry does not match the certificate's expires_at")
	}
}

func TestResolveDelegateKeyRejectsWrongRoot(t *testing.T) {
	rootPub, rootPriv := mustGenKeyPair(t)
	otherRootPub, _ := mustGenKeyPair(t)
	delegatePub, _ := mustGenKeyPair(t)
	now := time.Now()
	srv := fakeDelegateCertServer(t, rootPub, rootPriv, delegatePub, now.Add(-time.Hour), now.Add(30*24*time.Hour))
	defer srv.Close()

	if _, _, err := resolveDelegateKey(&http.Client{}, srv.URL, otherRootPub); err == nil {
		t.Fatal("expected an error verifying a delegate cert against the wrong root pubkey, got nil")
	}
}

func TestResolveDelegateKeyRejectsExpiredCert(t *testing.T) {
	rootPub, rootPriv := mustGenKeyPair(t)
	delegatePub, _ := mustGenKeyPair(t)
	now := time.Now()
	srv := fakeDelegateCertServer(t, rootPub, rootPriv, delegatePub, now.Add(-2*time.Hour), now.Add(-time.Hour))
	defer srv.Close()

	if _, _, err := resolveDelegateKey(&http.Client{}, srv.URL, rootPub); err == nil {
		t.Fatal("expected an error verifying an expired delegate cert, got nil")
	}
}

func TestNewDelegateKeySourceFailsClosedOnInitialResolveError(t *testing.T) {
	rootPub, rootPriv := mustGenKeyPair(t)
	delegatePub, _ := mustGenKeyPair(t)
	now := time.Now()
	srv := fakeDelegateCertServer(t, rootPub, rootPriv, delegatePub, now.Add(-2*time.Hour), now.Add(-time.Hour))
	defer srv.Close()

	if _, err := newDelegateKeySource(&http.Client{}, srv.URL, rootPub); err == nil {
		t.Fatal("expected newDelegateKeySource to fail when the initial delegate cert is already expired")
	}
}

func TestNewDelegateKeySourceResolvesAndVerifies(t *testing.T) {
	rootPub, rootPriv := mustGenKeyPair(t)
	delegatePub, _ := mustGenKeyPair(t)
	now := time.Now()
	srv := fakeDelegateCertServer(t, rootPub, rootPriv, delegatePub, now.Add(-time.Hour), now.Add(30*24*time.Hour))
	defer srv.Close()

	src, err := newDelegateKeySource(&http.Client{}, srv.URL, rootPub)
	if err != nil {
		t.Fatalf("newDelegateKeySource: %v", err)
	}
	got, err := src.current()
	if err != nil {
		t.Fatalf("current(): %v", err)
	}
	if !got.Equal(delegatePub) {
		t.Fatal("current() did not return the resolved delegate pubkey")
	}
}

func TestBrokerKeySourceCurrentFailsClosedOnceExpired(t *testing.T) {
	pub, _ := mustGenKeyPair(t)
	src := &brokerKeySource{pub: pub, expiresAt: time.Now().Add(-time.Minute).Unix()}
	if _, err := src.current(); err == nil {
		t.Fatal("expected current() to fail once the cached delegate certificate's expiry has passed")
	}
}

func TestStaticKeySourceNeverExpires(t *testing.T) {
	pub, _ := mustGenKeyPair(t)
	src := newStaticKeySource(pub)
	got, err := src.current()
	if err != nil {
		t.Fatalf("legacy static key source should never fail closed: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("current() did not return the static pubkey")
	}
}

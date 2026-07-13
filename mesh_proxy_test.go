package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMeshProxiedHoldOpenForAdversarialCheck is a throwaway verification
// aid, not a permanent part of the suite — it authenticates through the
// mesh proxy exactly like the test above, then holds the connection open
// for MESH_PROXY_HOLD_SECONDS so an operator can snapshot file-share's own
// /proc/net/tcp{,6} mid-connection and confirm the remote address is the
// exit hop's container IP, never the real test client's. Skips unless
// explicitly asked for, same gating as the test above.
func TestMeshProxiedHoldOpenForAdversarialCheck(t *testing.T) {
	proxyAddr := os.Getenv("MESH_PROXY_ADDR")
	brokerURL := os.Getenv("TEST_BROKER_URL")
	holdSecs := os.Getenv("MESH_PROXY_HOLD_SECONDS")
	if proxyAddr == "" || brokerURL == "" || holdSecs == "" {
		t.Skip("set MESH_PROXY_ADDR, TEST_BROKER_URL, and MESH_PROXY_HOLD_SECONDS to run this")
	}
	token := realFreeEnrollToken(t, brokerURL)
	client := dialAndAuthWithRealToken(t, proxyAddr, token)
	defer client.ws.Close()
	secs, _ := time.ParseDuration(holdSecs + "s")
	t.Logf("authenticated through %s, holding open for %s — snapshot file-share's /proc/net/tcp now", proxyAddr, secs)
	time.Sleep(secs)
}

// TestMeshProxiedUploadDownloadRoundTrip is the file-share counterpart to
// chat-server/mesh_proxy_test.go — same env-var-gated, real-live-infra-only
// verification tool (PRE_LAUNCH_ENGINEERING.md §2), proving file-share is
// also reachable through mesh-host/clientproxy.go's circuit bridge, not
// just chat. Skips unless pointed at real infra, so `go test ./...` stays
// hermetic. See CHECKLIST.md's "chat behind the mesh" entry for the pattern
// this follows.
func TestMeshProxiedUploadDownloadRoundTrip(t *testing.T) {
	proxyAddr := os.Getenv("MESH_PROXY_ADDR")
	brokerURL := os.Getenv("TEST_BROKER_URL")
	if proxyAddr == "" || brokerURL == "" {
		t.Skip("set MESH_PROXY_ADDR and TEST_BROKER_URL to run this against real live infra")
	}

	aliceToken := realFreeEnrollToken(t, brokerURL)
	bobToken := realFreeEnrollToken(t, brokerURL)

	alice := dialAndAuthWithRealToken(t, proxyAddr, aliceToken)
	bob := dialAndAuthWithRealToken(t, proxyAddr, bobToken)
	defer alice.ws.Close()
	defer bob.ws.Close()

	chunk := bytes.Repeat([]byte{0xAA}, 512)
	const transferID = "mesh-proxy-transfer-1"

	start, _ := json.Marshal(wsEnvelope{Type: "start_upload", TransferID: transferID, To: bob.pub, TotalChunks: 1})
	if err := alice.ws.WriteMessage(start); err != nil {
		t.Fatalf("write start_upload: %v", err)
	}
	raw, _, err := alice.ws.ReadMessage()
	if err != nil {
		t.Fatalf("read upload_ready: %v", err)
	}
	var ready wsEnvelope
	if err := json.Unmarshal(raw, &ready); err != nil || ready.Type != "upload_ready" {
		t.Fatalf("expected upload_ready, got %+v (err=%v)", ready, err)
	}

	header, _ := json.Marshal(wsEnvelope{Type: "chunk", TransferID: transferID, Index: 0, Nonce: []byte("nonce")})
	if err := alice.ws.WriteMessage(header); err != nil {
		t.Fatalf("write chunk header: %v", err)
	}
	if err := alice.ws.WriteBinary(chunk); err != nil {
		t.Fatalf("write chunk binary: %v", err)
	}
	raw, _, err = alice.ws.ReadMessage()
	if err != nil {
		t.Fatalf("read chunk_ack: %v", err)
	}
	var ack wsEnvelope
	if err := json.Unmarshal(raw, &ack); err != nil || ack.Type != "chunk_ack" || ack.Index != 0 {
		t.Fatalf("expected chunk_ack, got %+v (err=%v)", ack, err)
	}

	download, _ := json.Marshal(wsEnvelope{Type: "download", TransferID: transferID})
	if err := bob.ws.WriteMessage(download); err != nil {
		t.Fatalf("write download: %v", err)
	}
	hraw, opcode, err := bob.ws.ReadMessage()
	if err != nil {
		t.Fatalf("read chunk header: %v", err)
	}
	if opcode != opText {
		t.Fatalf("expected text chunk header, got opcode %d", opcode)
	}
	var hdr wsEnvelope
	if err := json.Unmarshal(hraw, &hdr); err != nil || hdr.Type != "chunk" {
		t.Fatalf("expected chunk header, got %+v (err=%v)", hdr, err)
	}
	data, opcode, err := bob.ws.ReadMessage()
	if err != nil {
		t.Fatalf("read chunk binary: %v", err)
	}
	if opcode != opBinary {
		t.Fatalf("expected binary chunk, got opcode %d", opcode)
	}
	if !bytes.Equal(data, chunk) {
		t.Fatalf("downloaded chunk corrupted in transit through the mesh")
	}
	t.Logf("file chunk relayed alice -> bob through a real onion circuit (proxy=%s)", proxyAddr)
}

// realFreeEnrollToken/dialAndAuthWithRealToken mirror chat-server's own
// copies exactly (same broker wire format, same handshake) — duplicated
// rather than shared since chat-server and file-share are separate
// `package main`s with no common importable library between them, same
// reasoning as mesh-host/connect's own duplication of broker DTOs.
func realFreeEnrollToken(t *testing.T, brokerURL string) string {
	t.Helper()
	resp, err := http.Post(brokerURL+"/enroll/free", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /enroll/free: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /enroll/free body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/enroll/free: status %d: %s", resp.StatusCode, body)
	}
	sig := resp.Header.Get("X-Signature")
	if sig == "" {
		t.Fatal("/enroll/free response missing X-Signature header")
	}
	return b64(body) + "." + sig
}

func dialAndAuthWithRealToken(t *testing.T, addr, token string) *testClient {
	t.Helper()
	priv, err := generateX25519Keypair()
	if err != nil {
		t.Fatalf("generateX25519Keypair: %v", err)
	}
	pubB64 := b64(priv.PublicKey().Bytes())

	ws, err := dialWebSocket(addr, "/ws")
	if err != nil {
		t.Fatalf("dialWebSocket(%s): %v", addr, err)
	}

	hello, _ := json.Marshal(wsEnvelope{Type: "hello", PubKey: pubB64, Token: token})
	if err := ws.WriteMessage(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	raw, _, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	var chal wsEnvelope
	if err := json.Unmarshal(raw, &chal); err != nil || chal.Type != "challenge" {
		t.Fatalf("expected challenge, got %+v (err=%v, raw=%s)", chal, err, strings.TrimSpace(string(raw)))
	}
	serverEphPub, err := parseX25519Public(chal.ServerEphemeralPub)
	if err != nil {
		t.Fatalf("parse server ephemeral pubkey: %v", err)
	}
	shared, err := priv.ECDH(serverEphPub)
	if err != nil {
		t.Fatalf("client ECDH: %v", err)
	}
	authKey := deriveAuthKey(shared)
	challenge, err := open(authKey, chal.Nonce, chal.Ciphertext)
	if err != nil {
		t.Fatalf("decrypt challenge: %v", err)
	}

	respMsg, _ := json.Marshal(wsEnvelope{Type: "challenge_response", Response: challenge})
	if err := ws.WriteMessage(respMsg); err != nil {
		t.Fatalf("write challenge_response: %v", err)
	}
	raw, _, err = ws.ReadMessage()
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	var authResult wsEnvelope
	if err := json.Unmarshal(raw, &authResult); err != nil || authResult.Type != "auth_ok" {
		t.Fatalf("expected auth_ok, got %+v (err=%v, raw=%s)", authResult, err, strings.TrimSpace(string(raw)))
	}

	return &testClient{ws: ws, priv: priv, pub: pubB64}
}

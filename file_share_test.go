package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testBrokerKey stands in for the broker's real signing key, same as
// chat-server/chat_test.go's testBrokerPub/testBrokerPriv — tests mint their
// own tokens rather than running a broker.
var testBrokerPub, testBrokerPriv, _ = ed25519.GenerateKey(nil)

func makeToken(t *testing.T, priv ed25519.PrivateKey, tier string, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	payload, err := json.Marshal(clientToken{ClientID: "test-client", Tier: tier, IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix()})
	if err != nil {
		t.Fatalf("marshal token payload: %v", err)
	}
	sig := ed25519.Sign(priv, payload)
	return b64(payload) + "." + b64(sig)
}

func validTestToken(t *testing.T) string { return makeToken(t, testBrokerPriv, "paid", time.Hour) }

// makeTokenWithPlan is makeToken plus an explicit Plan claim — covers
// MONETIZATION.md §5.2's plan-gating (a "vpn"-plan paid token is legitimately
// paid but shouldn't reach file-share), which the plain tier-only makeToken
// above can't express.
func makeTokenWithPlan(t *testing.T, priv ed25519.PrivateKey, tier, plan string, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	payload, err := json.Marshal(clientToken{ClientID: "test-client", Tier: tier, Plan: plan, IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix()})
	if err != nil {
		t.Fatalf("marshal token payload: %v", err)
	}
	sig := ed25519.Sign(priv, payload)
	return b64(payload) + "." + b64(sig)
}

type testClient struct {
	ws   *wsConn
	priv *ecdh.PrivateKey
	pub  string
}

func startTestServer(t *testing.T) string {
	t.Helper()
	st, err := newStore(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	fs := &fileShareServer{store: st, brokerPub: newStaticKeySource(testBrokerPub), minTier: "paid"}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", fs.handleWS)
	mux.HandleFunc("POST /link/start", withLinkCORS(fs.handleLinkStart))
	mux.HandleFunc("OPTIONS /link/start", withLinkCORS(fs.handleLinkStart))
	mux.HandleFunc("PUT /link/{id}/chunk/{index}", withLinkCORS(fs.handleLinkChunkUpload))
	mux.HandleFunc("OPTIONS /link/{id}/chunk/{index}", withLinkCORS(fs.handleLinkChunkUpload))
	mux.HandleFunc("GET /link/{id}/chunk/{index}", withLinkCORS(fs.handleLinkChunkDownload))
	mux.HandleFunc("GET /link/{id}/meta", withLinkCORS(fs.handleLinkMeta))
	mux.HandleFunc("DELETE /link/{id}", withLinkCORS(fs.handleLinkDelete))
	mux.HandleFunc("OPTIONS /link/{id}", withLinkCORS(fs.handleLinkDelete))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: mux}}
	srv.Start()
	t.Cleanup(srv.Close)
	return ln.Addr().String()
}

func dialAndAuthWithKey(t *testing.T, addr string, priv *ecdh.PrivateKey) *testClient {
	t.Helper()
	pubB64 := b64(priv.PublicKey().Bytes())

	ws, err := dialWebSocket(addr, "/ws")
	if err != nil {
		t.Fatalf("dialWebSocket: %v", err)
	}
	hello, _ := json.Marshal(wsEnvelope{Type: "hello", PubKey: pubB64, Token: validTestToken(t)})
	if err := ws.WriteMessage(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	raw, _, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	var chal wsEnvelope
	if err := json.Unmarshal(raw, &chal); err != nil || chal.Type != "challenge" {
		t.Fatalf("expected challenge, got %+v (err=%v)", chal, err)
	}
	serverEphPub, err := parseX25519Public(chal.ServerEphemeralPub)
	if err != nil {
		t.Fatalf("parse server ephemeral pubkey: %v", err)
	}
	shared, err := priv.ECDH(serverEphPub)
	if err != nil {
		t.Fatalf("client ECDH: %v", err)
	}
	challenge, err := open(deriveAuthKey(shared), chal.Nonce, chal.Ciphertext)
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
		t.Fatalf("expected auth_ok, got %+v (err=%v)", authResult, err)
	}
	return &testClient{ws: ws, priv: priv, pub: pubB64}
}

func dialAndAuth(t *testing.T, addr string) *testClient {
	t.Helper()
	priv, err := generateX25519Keypair()
	if err != nil {
		t.Fatalf("generateX25519Keypair: %v", err)
	}
	return dialAndAuthWithKey(t, addr, priv)
}

// dialAndAuthWithToken is dialAndAuthWithKey with the access token
// parameterized — needed by the session-expiry test, which must auth with
// a token that's valid now but about to expire.
func dialAndAuthWithToken(t *testing.T, addr, token string) *testClient {
	t.Helper()
	priv, err := generateX25519Keypair()
	if err != nil {
		t.Fatalf("generateX25519Keypair: %v", err)
	}
	pubB64 := b64(priv.PublicKey().Bytes())

	ws, err := dialWebSocket(addr, "/ws")
	if err != nil {
		t.Fatalf("dialWebSocket: %v", err)
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
		t.Fatalf("expected challenge, got %+v (err=%v)", chal, err)
	}
	serverEphPub, err := parseX25519Public(chal.ServerEphemeralPub)
	if err != nil {
		t.Fatalf("parse server ephemeral pubkey: %v", err)
	}
	shared, err := priv.ECDH(serverEphPub)
	if err != nil {
		t.Fatalf("client ECDH: %v", err)
	}
	challenge, err := open(deriveAuthKey(shared), chal.Nonce, chal.Ciphertext)
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
		t.Fatalf("expected auth_ok, got %+v (err=%v)", authResult, err)
	}
	return &testClient{ws: ws, priv: priv, pub: pubB64}
}

// TestSessionDisconnectedWhenTokenExpires mirrors chat-server's test of the
// same name: a token valid at auth but expiring mid-session must get a
// session_expired envelope and a server-side close at its expires_at, not
// indefinite service until the client chooses to disconnect.
func TestSessionDisconnectedWhenTokenExpires(t *testing.T) {
	addr := startTestServer(t)
	token := makeToken(t, testBrokerPriv, "paid", 2*time.Second)
	client := dialAndAuthWithToken(t, addr, token)
	defer client.ws.Close()

	type outcome struct {
		sawExpired bool
		readErr    error
	}
	resCh := make(chan outcome, 1)
	go func() {
		saw := false
		for {
			raw, _, err := client.ws.ReadMessage()
			if err != nil {
				resCh <- outcome{saw, err}
				return
			}
			var env wsEnvelope
			if json.Unmarshal(raw, &env) == nil && env.Type == "session_expired" {
				saw = true
			}
		}
	}()

	select {
	case res := <-resCh:
		if !res.sawExpired {
			t.Fatalf("connection closed without a session_expired envelope first (read err: %v)", res.readErr)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("session still alive 13s after its 2s token expired — mid-session expiry enforcement never fired")
	}
}

// uploadChunks sends start_upload then every chunk in chunks (in order),
// waiting for each chunk_ack — the "happy path" half of resumability.
func uploadChunks(t *testing.T, tc *testClient, transferID, to string, chunks [][]byte, from int) {
	t.Helper()
	if from == 0 {
		start, _ := json.Marshal(wsEnvelope{Type: "start_upload", TransferID: transferID, To: to, TotalChunks: len(chunks)})
		if err := tc.ws.WriteMessage(start); err != nil {
			t.Fatalf("write start_upload: %v", err)
		}
		raw, _, err := tc.ws.ReadMessage()
		if err != nil {
			t.Fatalf("read upload_ready: %v", err)
		}
		var resp wsEnvelope
		json.Unmarshal(raw, &resp)
		if resp.Type != "upload_ready" {
			t.Fatalf("expected upload_ready, got %+v", resp)
		}
	}
	for i := from; i < len(chunks); i++ {
		header, _ := json.Marshal(wsEnvelope{Type: "chunk", TransferID: transferID, Index: i, Nonce: []byte("nonce")})
		if err := tc.ws.WriteMessage(header); err != nil {
			t.Fatalf("write chunk header %d: %v", i, err)
		}
		if err := tc.ws.WriteBinary(chunks[i]); err != nil {
			t.Fatalf("write chunk binary %d: %v", i, err)
		}
		raw, _, err := tc.ws.ReadMessage()
		if err != nil {
			t.Fatalf("read chunk_ack %d: %v", i, err)
		}
		var ack wsEnvelope
		json.Unmarshal(raw, &ack)
		if ack.Type != "chunk_ack" || ack.Index != i {
			t.Fatalf("expected chunk_ack for index %d, got %+v", i, ack)
		}
	}
}

func TestUploadDownloadRoundTrip(t *testing.T) {
	addr := startTestServer(t)
	alice := dialAndAuth(t, addr)
	bob := dialAndAuth(t, addr)
	defer alice.ws.Close()
	defer bob.ws.Close()

	chunks := [][]byte{
		bytes.Repeat([]byte{0xAA}, 1024),
		bytes.Repeat([]byte{0xBB}, 1024),
		bytes.Repeat([]byte{0xCC}, 512),
	}
	const transferID = "transfer-1"
	uploadChunks(t, alice, transferID, bob.pub, chunks, 0)

	list, _ := json.Marshal(wsEnvelope{Type: "list"})
	if err := bob.ws.WriteMessage(list); err != nil {
		t.Fatalf("write list: %v", err)
	}
	raw, _, err := bob.ws.ReadMessage()
	if err != nil {
		t.Fatalf("read list_result: %v", err)
	}
	var listResult wsEnvelope
	json.Unmarshal(raw, &listResult)
	if len(listResult.Transfers) != 1 || listResult.Transfers[0].TransferID != transferID || listResult.Transfers[0].From != alice.pub {
		t.Fatalf("expected one pending transfer from alice, got %+v", listResult.Transfers)
	}

	download, _ := json.Marshal(wsEnvelope{Type: "download", TransferID: transferID})
	if err := bob.ws.WriteMessage(download); err != nil {
		t.Fatalf("write download: %v", err)
	}
	got := make([][]byte, len(chunks))
	for range chunks {
		hraw, opcode, err := bob.ws.ReadMessage()
		if err != nil {
			t.Fatalf("read chunk header: %v", err)
		}
		if opcode != opText {
			t.Fatalf("expected a text chunk header, got opcode %d", opcode)
		}
		var hdr wsEnvelope
		json.Unmarshal(hraw, &hdr)
		if hdr.Type != "chunk" {
			t.Fatalf("expected chunk header, got %+v", hdr)
		}
		data, opcode, err := bob.ws.ReadMessage()
		if err != nil {
			t.Fatalf("read chunk binary: %v", err)
		}
		if opcode != opBinary {
			t.Fatalf("expected a binary chunk payload, got opcode %d", opcode)
		}
		got[hdr.Index] = data
	}
	doneRaw, _, err := bob.ws.ReadMessage()
	if err != nil {
		t.Fatalf("read download_done: %v", err)
	}
	var done wsEnvelope
	json.Unmarshal(doneRaw, &done)
	if done.Type != "download_done" {
		t.Fatalf("expected download_done, got %+v", done)
	}

	for i, want := range chunks {
		if !bytes.Equal(got[i], want) {
			t.Fatalf("chunk %d corrupted in transit", i)
		}
	}

	complete, _ := json.Marshal(wsEnvelope{Type: "complete", TransferID: transferID})
	if err := bob.ws.WriteMessage(complete); err != nil {
		t.Fatalf("write complete: %v", err)
	}

	// Give the server a beat to process complete, then confirm the transfer
	// is gone — status on a deleted transfer should error.
	time.Sleep(50 * time.Millisecond)
	status, _ := json.Marshal(wsEnvelope{Type: "status", TransferID: transferID})
	if err := bob.ws.WriteMessage(status); err != nil {
		t.Fatalf("write status: %v", err)
	}
	raw, _, err = bob.ws.ReadMessage()
	if err != nil {
		t.Fatalf("read status error: %v", err)
	}
	var errResult wsEnvelope
	json.Unmarshal(raw, &errResult)
	if errResult.Type != "error" {
		t.Fatalf("expected the completed transfer to be gone, got %+v", errResult)
	}
}

// TestShareableTransferCanBeDownloadedRepeatedly covers CHECKLIST.md Phase
// 9's "'Shareable' transfer flag (repeat redemption past first download)" —
// unlike TestUploadDownloadRoundTrip's plain transfer (deleted the moment
// "complete" arrives), a transfer created with Shareable=true must still be
// there — and still downloadable — after the recipient completes it once.
func TestShareableTransferCanBeDownloadedRepeatedly(t *testing.T) {
	addr := startTestServer(t)
	alice := dialAndAuth(t, addr)
	bob := dialAndAuth(t, addr)
	defer alice.ws.Close()
	defer bob.ws.Close()

	chunks := [][]byte{bytes.Repeat([]byte{0xDD}, 256)}
	const transferID = "shareable-transfer"

	start, _ := json.Marshal(wsEnvelope{Type: "start_upload", TransferID: transferID, To: bob.pub, TotalChunks: len(chunks), Shareable: true})
	if err := alice.ws.WriteMessage(start); err != nil {
		t.Fatalf("write start_upload: %v", err)
	}
	if _, _, err := alice.ws.ReadMessage(); err != nil {
		t.Fatalf("read upload_ready: %v", err)
	}
	// uploadChunks sends its own (redundant, harmless) start_upload — createTransfer
	// is idempotent and the Shareable=true set above is only honored on genuine
	// creation, so it's untouched by this second call — then the real chunk data.
	uploadChunks(t, alice, transferID, bob.pub, chunks, 0)

	downloadOnce := func() {
		t.Helper()
		download, _ := json.Marshal(wsEnvelope{Type: "download", TransferID: transferID})
		if err := bob.ws.WriteMessage(download); err != nil {
			t.Fatalf("write download: %v", err)
		}
		for range chunks {
			if _, _, err := bob.ws.ReadMessage(); err != nil { // chunk header
				t.Fatalf("read chunk header: %v", err)
			}
			if _, _, err := bob.ws.ReadMessage(); err != nil { // chunk binary
				t.Fatalf("read chunk binary: %v", err)
			}
		}
		raw, _, err := bob.ws.ReadMessage()
		if err != nil {
			t.Fatalf("read download_done: %v", err)
		}
		var done wsEnvelope
		json.Unmarshal(raw, &done)
		if done.Type != "download_done" {
			t.Fatalf("expected download_done, got %+v", done)
		}
	}

	// First download, then complete — for a non-shareable transfer this is
	// exactly what deletes it (TestUploadDownloadRoundTrip above).
	downloadOnce()
	complete, _ := json.Marshal(wsEnvelope{Type: "complete", TransferID: transferID})
	if err := bob.ws.WriteMessage(complete); err != nil {
		t.Fatalf("write complete: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // let the server process complete before checking it didn't delete anything

	// The whole point: a second download after complete must still succeed.
	downloadOnce()

	status, _ := json.Marshal(wsEnvelope{Type: "status", TransferID: transferID})
	if err := bob.ws.WriteMessage(status); err != nil {
		t.Fatalf("write status: %v", err)
	}
	raw, _, err := bob.ws.ReadMessage()
	if err != nil {
		t.Fatalf("read status_result: %v", err)
	}
	var statusResult wsEnvelope
	json.Unmarshal(raw, &statusResult)
	if statusResult.Type != "status_result" {
		t.Fatalf("expected the shareable transfer to still exist after complete, got %+v", statusResult)
	}
}

// TestResumableUploadAfterDisconnect covers CHECKLIST.md Phase 5's
// resumability requirement: a dropped connection only costs re-sending
// whatever wasn't acknowledged yet, not the whole file.
func TestResumableUploadAfterDisconnect(t *testing.T) {
	addr := startTestServer(t)
	bobPriv, _ := generateX25519Keypair()
	bobPub := b64(bobPriv.PublicKey().Bytes())

	alicePriv, _ := generateX25519Keypair()
	chunks := [][]byte{
		bytes.Repeat([]byte{1}, 100),
		bytes.Repeat([]byte{2}, 100),
		bytes.Repeat([]byte{3}, 100),
	}

	const transferID2 = "transfer-resume"
	alice2 := dialAndAuthWithKey(t, addr, alicePriv)
	start, _ := json.Marshal(wsEnvelope{Type: "start_upload", TransferID: transferID2, To: bobPub, TotalChunks: len(chunks)})
	if err := alice2.ws.WriteMessage(start); err != nil {
		t.Fatalf("write start_upload: %v", err)
	}
	if _, _, err := alice2.ws.ReadMessage(); err != nil {
		t.Fatalf("read upload_ready: %v", err)
	}
	// Send only chunk 0, then "disconnect".
	header, _ := json.Marshal(wsEnvelope{Type: "chunk", TransferID: transferID2, Index: 0})
	alice2.ws.WriteMessage(header)
	alice2.ws.WriteBinary(chunks[0])
	if _, _, err := alice2.ws.ReadMessage(); err != nil {
		t.Fatalf("read chunk_ack 0: %v", err)
	}
	alice2.ws.Close()

	// Reconnect as the same identity and check status before resuming.
	alice3 := dialAndAuthWithKey(t, addr, alicePriv)
	defer alice3.ws.Close()
	statusMsg, _ := json.Marshal(wsEnvelope{Type: "status", TransferID: transferID2})
	if err := alice3.ws.WriteMessage(statusMsg); err != nil {
		t.Fatalf("write status: %v", err)
	}
	raw, _, err := alice3.ws.ReadMessage()
	if err != nil {
		t.Fatalf("read status_result: %v", err)
	}
	var statusResult wsEnvelope
	json.Unmarshal(raw, &statusResult)
	if len(statusResult.ReceivedIndices) != 1 || statusResult.ReceivedIndices[0] != 0 {
		t.Fatalf("expected only chunk 0 received so far, got %+v", statusResult.ReceivedIndices)
	}

	// Resume: send the remaining chunks only.
	uploadChunks(t, alice3, transferID2, bobPub, chunks, 1)

	// Download as bob and confirm the full, uncorrupted file.
	bob := dialAndAuthWithKey(t, addr, bobPriv)
	defer bob.ws.Close()
	download, _ := json.Marshal(wsEnvelope{Type: "download", TransferID: transferID2})
	bob.ws.WriteMessage(download)
	got := make([][]byte, len(chunks))
	for range chunks {
		hraw, _, err := bob.ws.ReadMessage()
		if err != nil {
			t.Fatalf("read chunk header: %v", err)
		}
		var hdr wsEnvelope
		json.Unmarshal(hraw, &hdr)
		data, _, err := bob.ws.ReadMessage()
		if err != nil {
			t.Fatalf("read chunk binary: %v", err)
		}
		got[hdr.Index] = data
	}
	for i, want := range chunks {
		if !bytes.Equal(got[i], want) {
			t.Fatalf("chunk %d corrupted after resume", i)
		}
	}
}

func TestSweepPurgesExpiredTransfers(t *testing.T) {
	st, err := newStore(t.TempDir(), 50*time.Millisecond)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	if err := st.createTransfer("expiring", "alice", "bob", 1, false); err != nil {
		t.Fatalf("createTransfer: %v", err)
	}
	if err := st.writeChunk("expiring", 0, []byte("data")); err != nil {
		t.Fatalf("writeChunk: %v", err)
	}
	if _, ok := st.getMeta("expiring"); !ok {
		t.Fatalf("expected transfer to exist before sweep")
	}
	time.Sleep(100 * time.Millisecond)
	st.sweep()
	if _, ok := st.getMeta("expiring"); ok {
		t.Fatalf("expected sweep to purge the expired transfer")
	}
}

// TestShareableTransferSurvivesCompleteButNotSweep covers CHECKLIST.md Phase
// 9's "'Shareable' transfer flag" — "complete" no-ops instead of deleting, so
// the recipient can download again later, but the sweep's TTL still applies
// exactly as it would for a transfer nobody ever downloaded at all: shareable
// changes what "complete" does, not how long the data is retained.
func TestShareableTransferSurvivesCompleteButNotSweep(t *testing.T) {
	st, err := newStore(t.TempDir(), 50*time.Millisecond)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	if err := st.createTransfer("shareable-1", "alice", "bob", 1, true); err != nil {
		t.Fatalf("createTransfer: %v", err)
	}
	if err := st.writeChunk("shareable-1", 0, []byte("data")); err != nil {
		t.Fatalf("writeChunk: %v", err)
	}
	// "complete" itself is only ever a no server-side deletion when Shareable
	// is set (server.go's dispatch enforces this) — at the store level that
	// just means: don't call deleteTransfer, which this test confirms by
	// simply never calling it and checking the transfer is still there.
	if _, ok := st.getMeta("shareable-1"); !ok {
		t.Fatalf("expected shareable transfer to still exist (no delete called)")
	}
	time.Sleep(100 * time.Millisecond)
	st.sweep()
	if _, ok := st.getMeta("shareable-1"); ok {
		t.Fatalf("expected sweep to purge the shareable transfer once its TTL passed, same as any other")
	}
}

// TestCreateTransferRejectsPathTraversalID covers a real finding from this
// project's own security review: TransferID is entirely client-supplied and
// used directly in filesystem paths (store.go's transferDir) — unvalidated,
// a value like "../../../etc/whatever" would let an authenticated client
// write, and later recursively delete (via complete/sweep), a path outside
// dataDir. Confirms both that createTransfer rejects it and that nothing
// escaped dataDir on disk.
func TestCreateTransferRejectsPathTraversalID(t *testing.T) {
	dir := t.TempDir()
	st, err := newStore(dir, time.Hour)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	malicious := []string{
		"../../../../tmp/evil",
		"..",
		"a/b",
		"a\\b",
		"",
		strings.Repeat("x", 129), // over the 128-character cap, length alone should reject this
	}
	for _, id := range malicious {
		if err := st.createTransfer(id, "alice", "bob", 1, false); err == nil {
			t.Fatalf("expected createTransfer to reject transfer id %q, got no error", id)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir dataDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no directories created under dataDir from rejected IDs, found: %v", entries)
	}
	// A legitimate ID (matches what the real client generates, see
	// chat-client/app.js's randomTransferId) must still work.
	if err := st.createTransfer("legit_Transfer-ID123", "alice", "bob", 1, false); err != nil {
		t.Fatalf("expected a valid transfer id to be accepted, got: %v", err)
	}
}

// TestStartUploadRejectsPathTraversalID is the protocol-level counterpart —
// confirms the rejection happens over the real WebSocket handshake with a
// clear error, not just at the store layer.
func TestStartUploadRejectsPathTraversalID(t *testing.T) {
	addr := startTestServer(t)
	tc := dialAndAuth(t, addr)
	defer tc.ws.Close()

	start, _ := json.Marshal(wsEnvelope{Type: "start_upload", TransferID: "../../../../etc/passwd", To: "bob", TotalChunks: 1})
	if err := tc.ws.WriteMessage(start); err != nil {
		t.Fatalf("write start_upload: %v", err)
	}
	raw, _, err := tc.ws.ReadMessage()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var resp wsEnvelope
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Type != "error" {
		t.Fatalf("expected a rejection (type=error) for a path-traversal transfer_id, got %+v", resp)
	}
}

// TestCreateTransferEnforcesSenderCap covers a real security-review
// finding: start_upload had no rate limit and no cap on how many distinct
// transfers a single sender could create, each costing a real directory +
// meta.json. Shrinks maxTransfersPerSender for the test rather than
// creating a thousand real transfers.
func TestCreateTransferEnforcesSenderCap(t *testing.T) {
	old := maxTransfersPerSender
	maxTransfersPerSender = 2
	t.Cleanup(func() { maxTransfersPerSender = old })

	st, err := newStore(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	for i := 0; i < 2; i++ {
		id := "transfer-" + string(rune('a'+i))
		if err := st.createTransfer(id, "alice", "bob", 1, false); err != nil {
			t.Fatalf("transfer %d: expected success within the cap, got %v", i, err)
		}
	}
	if err := st.createTransfer("transfer-c", "alice", "bob", 1, false); err == nil {
		t.Fatalf("expected the 3rd transfer from the same sender to be rejected against a cap of 2")
	}
	// A different sender has their own independent budget.
	if err := st.createTransfer("transfer-d", "carol", "bob", 1, false); err != nil {
		t.Fatalf("expected a different sender's transfer to succeed, got %v", err)
	}
}

// TestReadMessageRejectsOversizedReassembly is file-share's counterpart to
// chat-server's identical-purpose test — see that file's comment for the
// full reasoning (a real security-review finding: no cap on total
// reassembled size across continuation frames, reachable pre-auth).
func TestReadMessageRejectsOversizedReassembly(t *testing.T) {
	old := maxMessageSize
	maxMessageSize = 100
	t.Cleanup(func() { maxMessageSize = old })

	addr := startTestServer(t)
	ws, err := dialWebSocket(addr, "/ws")
	if err != nil {
		t.Fatalf("dialWebSocket: %v", err)
	}
	defer ws.Close()

	chunk := bytes.Repeat([]byte("x"), 40)
	writeRawFrame(t, ws, opText, false, chunk)
	writeRawFrame(t, ws, opContinuation, false, chunk)
	writeRawFrame(t, ws, opContinuation, true, chunk)
	if _, _, err := ws.ReadMessage(); err == nil {
		t.Fatalf("expected ReadMessage to reject a reassembled payload over maxMessageSize, got no error")
	}
}

// writeRawFrame is a test-only helper — see chat-server/chat_test.go's
// identical helper for the full reasoning (writeFrame always sets FIN=1;
// simulating a fragmenting client needs direct frame construction).
func writeRawFrame(t *testing.T, ws *wsConn, opcode wsOpcode, fin bool, payload []byte) {
	t.Helper()
	var finBit byte
	if fin {
		finBit = 0x80
	}
	header := []byte{finBit | byte(opcode)}
	n := len(payload)
	switch {
	case n <= 125:
		header = append(header, byte(n))
	case n <= 0xFFFF:
		header = append(header, 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		header = append(header, ext[:]...)
	default:
		header = append(header, 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		header = append(header, ext[:]...)
	}
	if _, err := ws.rw.Write(header); err != nil {
		t.Fatalf("write frame header: %v", err)
	}
	if _, err := ws.rw.Write(payload); err != nil {
		t.Fatalf("write frame payload: %v", err)
	}
	if err := ws.rw.Flush(); err != nil {
		t.Fatalf("flush frame: %v", err)
	}
}

func TestAuthRejectsMissingOrFreeTierToken(t *testing.T) {
	addr := startTestServer(t)
	_, wrongPriv, _ := ed25519.GenerateKey(nil)

	cases := []struct {
		name  string
		token string
	}{
		{"missing token", ""},
		{"free-tier token", makeToken(t, testBrokerPriv, "free", time.Hour)},
		{"expired token", makeToken(t, testBrokerPriv, "paid", -time.Minute)},
		{"wrong signing key", makeToken(t, wrongPriv, "paid", time.Hour)},
		{"vpn-plan paid token", makeTokenWithPlan(t, testBrokerPriv, "paid", "vpn", time.Hour)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, _ := generateX25519Keypair()
			ws, err := dialWebSocket(addr, "/ws")
			if err != nil {
				t.Fatalf("dialWebSocket: %v", err)
			}
			defer ws.Close()

			hello, _ := json.Marshal(wsEnvelope{Type: "hello", PubKey: b64(priv.PublicKey().Bytes()), Token: tc.token})
			if err := ws.WriteMessage(hello); err != nil {
				t.Fatalf("write hello: %v", err)
			}
			raw, _, err := ws.ReadMessage()
			if err != nil {
				t.Fatalf("read auth result: %v", err)
			}
			var result wsEnvelope
			json.Unmarshal(raw, &result)
			if result.Type != "auth_error" {
				t.Fatalf("expected auth_error for %s, got %+v", tc.name, result)
			}
		})
	}
}

// TestFullPlanTokenCompletesAuth is TestAuthRejectsMissingOrFreeTierToken's
// positive counterpart for the new plan check (MONETIZATION.md §5.2): a
// paid+full token (and, separately, a paid token with no Plan claim at all —
// every token minted before this field existed) must both still complete
// the handshake exactly as before, not just avoid an explicit rejection.
func TestFullPlanTokenCompletesAuth(t *testing.T) {
	addr := startTestServer(t)

	tokens := map[string]string{
		"explicit full plan":     makeTokenWithPlan(t, testBrokerPriv, "paid", "full", time.Hour),
		"no plan claim (legacy)": makeToken(t, testBrokerPriv, "paid", time.Hour),
	}
	for name, token := range tokens {
		t.Run(name, func(t *testing.T) {
			priv, _ := generateX25519Keypair()
			ws, err := dialWebSocket(addr, "/ws")
			if err != nil {
				t.Fatalf("dialWebSocket: %v", err)
			}
			defer ws.Close()

			hello, _ := json.Marshal(wsEnvelope{Type: "hello", PubKey: b64(priv.PublicKey().Bytes()), Token: token})
			if err := ws.WriteMessage(hello); err != nil {
				t.Fatalf("write hello: %v", err)
			}
			raw, _, err := ws.ReadMessage()
			if err != nil {
				t.Fatalf("read challenge: %v", err)
			}
			var chal wsEnvelope
			if err := json.Unmarshal(raw, &chal); err != nil || chal.Type != "challenge" {
				t.Fatalf("expected challenge, got %+v (err=%v)", chal, err)
			}
			serverEphPub, err := parseX25519Public(chal.ServerEphemeralPub)
			if err != nil {
				t.Fatalf("parse server ephemeral pubkey: %v", err)
			}
			shared, err := priv.ECDH(serverEphPub)
			if err != nil {
				t.Fatalf("client ECDH: %v", err)
			}
			challenge, err := open(deriveAuthKey(shared), chal.Nonce, chal.Ciphertext)
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
				t.Fatalf("expected auth_ok, got %+v (err=%v)", authResult, err)
			}
		})
	}
}

// TestMinTierFreeAcceptsFreeTierToken mirrors chat-server's test of the
// same name: with -min-tier=free, a free-tier token must complete the full
// handshake, not just avoid an immediate auth_error.
func TestMinTierFreeAcceptsFreeTierToken(t *testing.T) {
	st, err := newStore(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	fs := &fileShareServer{store: st, brokerPub: newStaticKeySource(testBrokerPub), minTier: "free"}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", fs.handleWS)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: mux}}
	srv.Start()
	t.Cleanup(srv.Close)

	priv, _ := generateX25519Keypair()
	ws, err := dialWebSocket(ln.Addr().String(), "/ws")
	if err != nil {
		t.Fatalf("dialWebSocket: %v", err)
	}
	defer ws.Close()

	hello, _ := json.Marshal(wsEnvelope{
		Type: "hello", PubKey: b64(priv.PublicKey().Bytes()),
		Token: makeToken(t, testBrokerPriv, "free", time.Hour),
	})
	if err := ws.WriteMessage(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	raw, _, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	var chal wsEnvelope
	if err := json.Unmarshal(raw, &chal); err != nil || chal.Type != "challenge" {
		t.Fatalf("expected a challenge (free-tier token should pass with -min-tier=free), got %+v (err=%v)", chal, err)
	}
}

// linkStart is a small helper wrapping POST /link/start for the tests below.
func linkStart(t *testing.T, addr, token string, totalChunks int) linkStartResponse {
	t.Helper()
	body, _ := json.Marshal(linkStartRequest{Token: token, TotalChunks: totalChunks})
	resp, err := http.Post("http://"+addr+"/link/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /link/start: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /link/start: status %d", resp.StatusCode)
	}
	var out linkStartResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode /link/start response: %v", err)
	}
	return out
}

// TestLinkShareUploadDownloadRoundTrip covers the whole new public
// link-share surface end to end: no identity/ECDH handshake at all, just a
// paid-tier token to start, then the TransferID/ManageToken pair —
// matching the "anyone with the link, no account, no chat identity"
// design this surface exists for.
func TestLinkShareUploadDownloadRoundTrip(t *testing.T) {
	addr := startTestServer(t)
	chunks := [][]byte{[]byte("manifest-ciphertext"), []byte("chunk-zero-ciphertext"), []byte("chunk-one-ciphertext")}

	started := linkStart(t, addr, validTestToken(t), len(chunks))
	if started.TransferID == "" || started.ManageToken == "" {
		t.Fatalf("expected a transfer_id and manage_token, got %+v", started)
	}

	client := &http.Client{}
	for i, data := range chunks {
		req, _ := http.NewRequest(http.MethodPut, "http://"+addr+"/link/"+started.TransferID+"/chunk/"+strconv.Itoa(i), bytes.NewReader(data))
		req.Header.Set("X-Manage-Token", started.ManageToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("PUT chunk %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("PUT chunk %d: status %d", i, resp.StatusCode)
		}
	}

	// meta and download are both public — no manage token, no identity at all.
	metaResp, err := http.Get("http://" + addr + "/link/" + started.TransferID + "/meta")
	if err != nil {
		t.Fatalf("GET meta: %v", err)
	}
	var meta map[string]int
	json.NewDecoder(metaResp.Body).Decode(&meta)
	metaResp.Body.Close()
	if meta["total_chunks"] != len(chunks) {
		t.Fatalf("expected total_chunks=%d, got %+v", len(chunks), meta)
	}

	for i, want := range chunks {
		resp, err := http.Get("http://" + addr + "/link/" + started.TransferID + "/chunk/" + strconv.Itoa(i))
		if err != nil {
			t.Fatalf("GET chunk %d: %v", i, err)
		}
		got, _ := readAllClose(resp)
		if !bytes.Equal(got, want) {
			t.Fatalf("chunk %d: got %q, want %q", i, got, want)
		}
	}

	// Delete requires the manage token — a downloader who only has the
	// share link (TransferID + fragment key) can never delete someone
	// else's file.
	delReqNoToken, _ := http.NewRequest(http.MethodDelete, "http://"+addr+"/link/"+started.TransferID, nil)
	delResp, _ := client.Do(delReqNoToken)
	if delResp.StatusCode != http.StatusForbidden {
		t.Fatalf("delete with no manage token: expected 403, got %d", delResp.StatusCode)
	}
	delResp.Body.Close()

	delReq, _ := http.NewRequest(http.MethodDelete, "http://"+addr+"/link/"+started.TransferID, nil)
	delReq.Header.Set("X-Manage-Token", started.ManageToken)
	delResp2, err := client.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	delResp2.Body.Close()
	if delResp2.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE: expected 204, got %d", delResp2.StatusCode)
	}

	afterResp, _ := http.Get("http://" + addr + "/link/" + started.TransferID + "/meta")
	if afterResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", afterResp.StatusCode)
	}
	afterResp.Body.Close()
}

// TestLinkShareRejectsNonPaidToken covers the same tier/plan gating as the
// WS protocol (MONETIZATION §5.2) — a link-share is still a paid-tier
// feature, the only thing that changed is that no identity is needed.
func TestLinkShareRejectsNonPaidToken(t *testing.T) {
	addr := startTestServer(t)
	body, _ := json.Marshal(linkStartRequest{Token: makeToken(t, testBrokerPriv, "free", time.Hour), TotalChunks: 1})
	resp, err := http.Post("http://"+addr+"/link/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /link/start: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a free-tier token, got %d", resp.StatusCode)
	}
}

// TestLinkShareCannotTouchDirectModeTransfer is the critical cross-mode
// isolation check: the new public HTTP surface must never be able to
// read, write, or delete a transfer created through the original
// identity-to-identity WS protocol — those are meant only for their named
// recipient, not "anyone with a URL."
func TestLinkShareCannotTouchDirectModeTransfer(t *testing.T) {
	addr := startTestServer(t)

	senderPriv, _ := generateX25519Keypair()
	recipientPriv, _ := generateX25519Keypair()
	sender := dialAndAuthWithKey(t, addr, senderPriv)
	defer sender.ws.Close()

	transferID := "direct-mode-transfer-1"
	startMsg, _ := json.Marshal(wsEnvelope{Type: "start_upload", TransferID: transferID, To: b64(recipientPriv.PublicKey().Bytes()), TotalChunks: 1})
	if err := sender.ws.WriteMessage(startMsg); err != nil {
		t.Fatalf("write start_upload: %v", err)
	}
	raw, _, err := sender.ws.ReadMessage()
	if err != nil {
		t.Fatalf("read upload_ready: %v", err)
	}
	var ready wsEnvelope
	json.Unmarshal(raw, &ready)
	if ready.Type != "upload_ready" {
		t.Fatalf("expected upload_ready, got %+v", ready)
	}

	// The link-mode HTTP surface must treat this as if it doesn't exist.
	metaResp, err := http.Get("http://" + addr + "/link/" + transferID + "/meta")
	if err != nil {
		t.Fatalf("GET meta: %v", err)
	}
	metaResp.Body.Close()
	if metaResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 fetching a direct-mode transfer's meta over /link, got %d", metaResp.StatusCode)
	}

	chunkResp, err := http.Get("http://" + addr + "/link/" + transferID + "/chunk/0")
	if err != nil {
		t.Fatalf("GET chunk: %v", err)
	}
	chunkResp.Body.Close()
	if chunkResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 fetching a direct-mode transfer's chunk over /link, got %d", chunkResp.StatusCode)
	}
}

func readAllClose(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}

// linkStartOneTime is linkStart with the one_time flag set.
func linkStartOneTime(t *testing.T, addr, token string, totalChunks int) linkStartResponse {
	t.Helper()
	body, _ := json.Marshal(linkStartRequest{Token: token, TotalChunks: totalChunks, OneTime: true})
	resp, err := http.Post("http://"+addr+"/link/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /link/start: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /link/start: status %d", resp.StatusCode)
	}
	var out linkStartResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode /link/start response: %v", err)
	}
	return out
}

// uploadLinkChunks PUTs each chunk of a link-share in order — shared by the
// one-time tests below, same wire calls as TestLinkShareUploadDownloadRoundTrip.
func uploadLinkChunks(t *testing.T, addr string, started linkStartResponse, chunks [][]byte) {
	t.Helper()
	client := &http.Client{}
	for i, data := range chunks {
		req, _ := http.NewRequest(http.MethodPut, "http://"+addr+"/link/"+started.TransferID+"/chunk/"+strconv.Itoa(i), bytes.NewReader(data))
		req.Header.Set("X-Manage-Token", started.ManageToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("PUT chunk %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("PUT chunk %d: status %d", i, resp.StatusCode)
		}
	}
}

// TestOneTimeLinkShareBurnsAfterFullDownload is the burn-after-read
// contract: the first complete download (every chunk index served once)
// deletes the transfer, so the same link fetched again — by anyone — finds
// nothing. Repeat fetches of a single chunk before the set is covered must
// NOT burn (a flaky downloader retrying is not a second download).
func TestOneTimeLinkShareBurnsAfterFullDownload(t *testing.T) {
	addr := startTestServer(t)
	chunks := [][]byte{[]byte("manifest-ciphertext"), []byte("chunk-zero"), []byte("chunk-one")}
	started := linkStartOneTime(t, addr, validTestToken(t), len(chunks))
	uploadLinkChunks(t, addr, started, chunks)

	// meta advertises one_time so the download page can warn before spending it
	metaResp, err := http.Get("http://" + addr + "/link/" + started.TransferID + "/meta")
	if err != nil {
		t.Fatalf("GET meta: %v", err)
	}
	var meta struct {
		TotalChunks int  `json:"total_chunks"`
		OneTime     bool `json:"one_time"`
	}
	json.NewDecoder(metaResp.Body).Decode(&meta)
	metaResp.Body.Close()
	if meta.TotalChunks != len(chunks) || !meta.OneTime {
		t.Fatalf("expected total_chunks=%d one_time=true, got %+v", len(chunks), meta)
	}

	// retrying one chunk repeatedly must not advance the burn
	for range 3 {
		resp, err := http.Get("http://" + addr + "/link/" + started.TransferID + "/chunk/0")
		if err != nil {
			t.Fatalf("GET chunk 0: %v", err)
		}
		got, _ := readAllClose(resp)
		if resp.StatusCode != http.StatusOK || !bytes.Equal(got, chunks[0]) {
			t.Fatalf("repeat GET chunk 0: status %d body %q", resp.StatusCode, got)
		}
	}

	// complete the set — this is the first (and only) full download
	for i := 1; i < len(chunks); i++ {
		resp, err := http.Get("http://" + addr + "/link/" + started.TransferID + "/chunk/" + strconv.Itoa(i))
		if err != nil {
			t.Fatalf("GET chunk %d: %v", i, err)
		}
		got, _ := readAllClose(resp)
		if resp.StatusCode != http.StatusOK || !bytes.Equal(got, chunks[i]) {
			t.Fatalf("GET chunk %d: status %d body %q", i, resp.StatusCode, got)
		}
	}

	// burned: meta and every chunk are gone for good
	afterMeta, _ := http.Get("http://" + addr + "/link/" + started.TransferID + "/meta")
	afterMeta.Body.Close()
	if afterMeta.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 meta after burn, got %d", afterMeta.StatusCode)
	}
	afterChunk, _ := http.Get("http://" + addr + "/link/" + started.TransferID + "/chunk/0")
	afterChunk.Body.Close()
	if afterChunk.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 chunk after burn, got %d", afterChunk.StatusCode)
	}
}

// TestOneTimeLinkSharePartialDownloadSurvives proves an incomplete
// download leaves the share intact and resumable: covering all-but-one
// chunk burns nothing, and the transfer still exists afterward. Ordinary
// (non-one-time) shares are already covered against accidental burning by
// TestLinkShareUploadDownloadRoundTrip, which downloads everything and
// then expects the transfer to still exist for its delete checks.
func TestOneTimeLinkSharePartialDownloadSurvives(t *testing.T) {
	addr := startTestServer(t)
	chunks := [][]byte{[]byte("manifest-ciphertext"), []byte("chunk-zero")}
	started := linkStartOneTime(t, addr, validTestToken(t), len(chunks))
	uploadLinkChunks(t, addr, started, chunks)

	resp, err := http.Get("http://" + addr + "/link/" + started.TransferID + "/chunk/0")
	if err != nil {
		t.Fatalf("GET chunk 0: %v", err)
	}
	resp.Body.Close()

	metaResp, _ := http.Get("http://" + addr + "/link/" + started.TransferID + "/meta")
	metaResp.Body.Close()
	if metaResp.StatusCode != http.StatusOK {
		t.Fatalf("partial download must not burn: expected 200 meta, got %d", metaResp.StatusCode)
	}
}

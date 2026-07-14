package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
)

// maxLinkChunkBytes bounds one link-mode chunk body — chat-client's own
// FILE_CHUNK_SIZE (app.js) is 4MB; this leaves headroom for AES-GCM's
// 16-byte tag plus the small encrypted-manifest chunk (filename/size/mime,
// see drive.js) without opening the door to an unbounded request body.
const maxLinkChunkBytes = 5 * 1024 * 1024

// genRandomToken returns n random bytes, base64url-encoded (no padding) —
// used for both the link-share TransferID (the "read" capability, embedded
// in the share URL path) and ManageToken (the "write/delete" capability,
// kept only in the uploader's own browser). Same entropy source as every
// other unguessable-ID convention in this project (broker invite codes,
// account numbers).
func genRandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type fileShareServer struct {
	store     *store
	brokerPub *brokerKeySource // required — paid-tier only by default, same as chat-server (WHITEPAPER §7.5/§9). Either a static flat pubkey or a periodically-refreshed root+delegate chain, see delegate.go
	minTier   string           // "paid" by default; "free" for testing before payments are wired up
}

func (fs *fileShareServer) handleWS(w http.ResponseWriter, r *http.Request) {
	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		log.Printf("file-share: upgrade failed: %v", err)
		return
	}
	defer ws.Close()

	pubkey, tok, err := fs.authenticate(ws)
	if err != nil {
		log.Printf("file-share: auth failed: %v", err)
		return
	}

	// Same mid-session token-expiry enforcement as chat-server's handleWS:
	// verifyToken only runs at auth, so without this an already-connected
	// client kept uploading/downloading after its token (and the paid
	// entitlement it represents) expired, until it happened to disconnect.
	expiryTimer := time.AfterFunc(time.Until(time.Unix(tok.ExpiresAt, 0)), func() {
		msg, _ := json.Marshal(wsEnvelope{Type: "session_expired", Error: "access token expired — renew your subscription and reconnect with the new token"})
		_ = ws.WriteMessage(msg)
		_ = ws.Close()
	})
	defer expiryTimer.Stop()

	for {
		raw, opcode, err := ws.ReadMessage()
		if err != nil {
			if err != io.EOF {
				log.Printf("file-share: read: %v", err)
			}
			return
		}
		if opcode != opText {
			continue // a stray binary frame outside the chunk protocol — ignore
		}
		var env wsEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		if err := fs.dispatch(ws, pubkey, env); err != nil {
			log.Printf("file-share: %s from %s: %v", env.Type, pubkey, err)
			return
		}
	}
}

// authenticate is chat-server's ECDH-identity-proof + paid-token check,
// unchanged in substance (WHITEPAPER §9: file-share reuses chat's identity
// *and* its entitlement check, not a second gate).
func (fs *fileShareServer) authenticate(ws *wsConn) (string, clientToken, error) {
	raw, opcode, err := ws.ReadMessage()
	if err != nil {
		return "", clientToken{}, err
	}
	var hello wsEnvelope
	if opcode != opText {
		return "", clientToken{}, errors.New("expected a text hello frame")
	}
	if err := json.Unmarshal(raw, &hello); err != nil || hello.Type != "hello" || hello.PubKey == "" {
		return "", clientToken{}, errors.New("expected a hello message with a pubkey")
	}
	brokerPub, err := fs.brokerPub.current()
	if err != nil {
		errMsg, _ := json.Marshal(wsEnvelope{Type: "auth_error", Error: "access token rejected: " + err.Error()})
		_ = ws.WriteMessage(errMsg)
		return "", clientToken{}, err
	}
	tok, err := verifyToken(brokerPub, hello.Token, fs.minTier, false) // identity-based file-share: full-suite only
	if err != nil {
		errMsg, _ := json.Marshal(wsEnvelope{Type: "auth_error", Error: "access token rejected: " + err.Error()})
		_ = ws.WriteMessage(errMsg)
		return "", clientToken{}, err
	}
	clientPubRaw, err := unb64(hello.PubKey)
	if err != nil {
		return "", clientToken{}, err
	}
	clientPub, err := parseX25519Public(clientPubRaw)
	if err != nil {
		return "", clientToken{}, err
	}

	ephPriv, err := generateX25519Keypair()
	if err != nil {
		return "", clientToken{}, err
	}
	shared, err := ephPriv.ECDH(clientPub)
	if err != nil {
		return "", clientToken{}, err
	}
	authKey := deriveAuthKey(shared)

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return "", clientToken{}, err
	}
	nonce, ciphertext, err := seal(authKey, challenge)
	if err != nil {
		return "", clientToken{}, err
	}
	challengeMsg, err := json.Marshal(wsEnvelope{
		Type: "challenge", ServerEphemeralPub: ephPriv.PublicKey().Bytes(), Nonce: nonce, Ciphertext: ciphertext,
	})
	if err != nil {
		return "", clientToken{}, err
	}
	if err := ws.WriteMessage(challengeMsg); err != nil {
		return "", clientToken{}, err
	}

	raw, opcode, err = ws.ReadMessage()
	if err != nil {
		return "", clientToken{}, err
	}
	var resp wsEnvelope
	if opcode != opText {
		return "", clientToken{}, errors.New("expected a text challenge_response frame")
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.Type != "challenge_response" {
		return "", clientToken{}, errors.New("expected a challenge_response message")
	}
	if subtle.ConstantTimeCompare(resp.Response, challenge) != 1 {
		errMsg, _ := json.Marshal(wsEnvelope{Type: "auth_error", Error: "challenge mismatch"})
		_ = ws.WriteMessage(errMsg)
		return "", clientToken{}, errors.New("challenge response did not match")
	}

	okMsg, err := json.Marshal(wsEnvelope{Type: "auth_ok", OK: true})
	if err != nil {
		return "", clientToken{}, err
	}
	if err := ws.WriteMessage(okMsg); err != nil {
		return "", clientToken{}, err
	}
	return hello.PubKey, tok, nil
}

// dispatch handles one control message from an authenticated connection.
// Chunk payloads for "chunk" (upload direction) are read as the immediately
// following binary frame — WHITEPAPER §9's resumable chunked protocol.
func (fs *fileShareServer) dispatch(ws *wsConn, pubkey string, env wsEnvelope) error {
	switch env.Type {
	case "start_upload":
		if env.TransferID == "" || env.To == "" || env.TotalChunks <= 0 {
			return fs.reply(ws, wsEnvelope{Type: "error", Error: "start_upload requires transfer_id, to, total_chunks"})
		}
		if !validTransferID(env.TransferID) {
			return fs.reply(ws, wsEnvelope{Type: "error", Error: "transfer_id must be 1-128 characters, letters/digits/hyphen/underscore only"})
		}
		if err := fs.store.createTransfer(env.TransferID, pubkey, env.To, env.TotalChunks, env.Shareable); err != nil {
			return err
		}
		return fs.reply(ws, wsEnvelope{Type: "upload_ready", TransferID: env.TransferID})

	case "chunk":
		// Client is uploading: this header is immediately followed by one
		// binary frame with the chunk's ciphertext. Only the transfer's
		// original sender may write chunks to it.
		if env.TransferID == "" {
			return fs.reply(ws, wsEnvelope{Type: "error", Error: "chunk requires transfer_id"})
		}
		m, ok := fs.store.getMeta(env.TransferID)
		if !ok || m.From != pubkey {
			return fs.reply(ws, wsEnvelope{Type: "error", Error: "no such transfer for this sender"})
		}
		raw, opcode, err := ws.ReadMessage()
		if err != nil {
			return err
		}
		if opcode != opBinary {
			return errors.New("expected a binary frame immediately after a chunk header")
		}
		if err := fs.store.writeChunk(env.TransferID, env.Index, raw); err != nil {
			return fs.reply(ws, wsEnvelope{Type: "error", Error: "chunk rejected: " + err.Error()})
		}
		return fs.reply(ws, wsEnvelope{Type: "chunk_ack", TransferID: env.TransferID, Index: env.Index})

	case "status":
		if env.TransferID == "" {
			return fs.reply(ws, wsEnvelope{Type: "error", Error: "status requires transfer_id"})
		}
		m, ok := fs.store.getMeta(env.TransferID)
		if !ok || (m.From != pubkey && m.To != pubkey) {
			return fs.reply(ws, wsEnvelope{Type: "error", Error: "no such transfer for this identity"})
		}
		return fs.reply(ws, wsEnvelope{Type: "status_result", TransferID: env.TransferID, ReceivedIndices: fs.store.receivedIndices(env.TransferID)})

	case "list":
		return fs.reply(ws, wsEnvelope{Type: "list_result", Transfers: fs.store.listForRecipient(pubkey)})

	case "download":
		m, ok := fs.store.getMeta(env.TransferID)
		if !ok || m.To != pubkey {
			return fs.reply(ws, wsEnvelope{Type: "error", Error: "no such transfer for this recipient"})
		}
		for _, idx := range fs.store.receivedIndices(env.TransferID) {
			data, err := fs.store.readChunk(env.TransferID, idx)
			if err != nil {
				return err
			}
			header, _ := json.Marshal(wsEnvelope{Type: "chunk", TransferID: env.TransferID, Index: idx})
			if err := ws.WriteMessage(header); err != nil {
				return err
			}
			if err := ws.WriteBinary(data); err != nil {
				return err
			}
		}
		return fs.reply(ws, wsEnvelope{Type: "download_done", TransferID: env.TransferID})

	case "complete":
		m, ok := fs.store.getMeta(env.TransferID)
		if !ok || m.To != pubkey {
			return fs.reply(ws, wsEnvelope{Type: "error", Error: "no such transfer for this recipient"})
		}
		if m.Shareable {
			return nil // repeat redemption past first download — only the TTL sweep removes it
		}
		return fs.store.deleteTransfer(env.TransferID)

	default:
		return nil // unknown message type — ignore rather than drop the connection
	}
}

func (fs *fileShareServer) reply(ws *wsConn, env wsEnvelope) error {
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return ws.WriteMessage(b)
}

// withLinkCORS wraps a link-share HTTP handler with permissive CORS headers
// and answers the browser's preflight OPTIONS request directly. Safe to be
// wide open (Access-Control-Allow-Origin: *) specifically because this
// surface carries no cookies/session state to leak across origins — every
// request is authorized by an explicit bearer value in its own body/header
// (ManageToken) or is meant to be public by design (TransferID + a fragment
// key nobody but the browser holding the link ever sends), the same
// reasoning that makes a same-origin-only policy unnecessary here. Also
// what makes link-shares usable from something other than this exact
// website (a third-party client, a mobile app) without needing a proxy —
// same-origin nginx proxying (production's actual path today) still works
// fine regardless, this just doesn't *require* it.
func withLinkCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Manage-Token")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

// --- Link-share HTTP surface ---------------------------------------------
//
// A parallel, deliberately separate protocol from the WS handlers above:
// no client identity/ECDH handshake at all, gated only by possessing an
// unguessable TransferID (read) or ManageToken (write/delete) — see
// store.go's transferMeta.Mode doc for why. This is what makes file-share
// usable without ever touching chat's identity system, unlike the original
// WS protocol's "reuses chat's identity" design (WHITEPAPER §9's older
// rationale — still true for direct transfers, just no longer the only
// option). Every handler below checks Mode == "link" before touching a
// transfer, so this surface can never read/write/delete a direct-mode
// transfer meant only for its named recipient over the WS protocol.

type linkStartRequest struct {
	Token       string `json:"token"`
	TotalChunks int    `json:"total_chunks"`
	// OneTime makes the share burn after its first complete download —
	// see transferMeta.OneTime in store.go.
	OneTime bool `json:"one_time"`
	// SecretOnly is set by /secret (never by /drive) — it admits a
	// Plan=="vpn" token here (MONETIZATION.md pivot: secret-sharing is
	// included on the VPN-only plan/trial, unlike Drive's persistent
	// file-share, which stays full-suite-only). Self-reported, like several
	// other client-declared fields in this codebase — not a security
	// boundary, since a link-share transfer costs the same either way; it
	// only decides which tier's token this specific request accepts.
	SecretOnly bool `json:"secret_only,omitempty"`
}

type linkStartResponse struct {
	TransferID  string `json:"transfer_id"`
	ManageToken string `json:"manage_token"`
}

// handleLinkStart mints a new link-share transfer. Still gated by a valid
// paid-tier access token (MONETIZATION §5.2 — only paying accounts get
// storage), but that's the only thing checked: no identity keypair, no
// ECDH, no recipient. POST /link/start.
func (fs *fileShareServer) handleLinkStart(w http.ResponseWriter, r *http.Request) {
	var req linkStartRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.TotalChunks <= 0 {
		http.Error(w, "total_chunks must be positive", http.StatusBadRequest)
		return
	}
	brokerPub, err := fs.brokerPub.current()
	if err != nil {
		http.Error(w, "access token rejected: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	if _, err := verifyToken(brokerPub, req.Token, fs.minTier, req.SecretOnly); err != nil {
		http.Error(w, "access token rejected: "+err.Error(), http.StatusUnauthorized)
		return
	}
	transferID, err := genRandomToken(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	manageToken, err := genRandomToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := fs.store.createLinkTransfer(transferID, manageToken, req.TotalChunks, req.OneTime); err != nil {
		http.Error(w, "could not create transfer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(linkStartResponse{TransferID: transferID, ManageToken: manageToken})
}

// linkTransferForManage looks up a link-mode transfer and checks the
// caller's X-Manage-Token header against it in constant time — shared by
// every write/delete handler below.
func (fs *fileShareServer) linkTransferForManage(w http.ResponseWriter, r *http.Request) (transferMeta, bool) {
	id := r.PathValue("id")
	m, ok := fs.store.getMeta(id)
	if !ok || m.Mode != "link" {
		http.Error(w, "no such transfer", http.StatusNotFound)
		return transferMeta{}, false
	}
	got := r.Header.Get("X-Manage-Token")
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(m.ManageToken)) != 1 {
		http.Error(w, "invalid manage token", http.StatusForbidden)
		return transferMeta{}, false
	}
	return m, true
}

// handleLinkChunkUpload: PUT /link/{id}/chunk/{index}, body = raw
// ciphertext, X-Manage-Token header required.
func (fs *fileShareServer) handleLinkChunkUpload(w http.ResponseWriter, r *http.Request) {
	m, ok := fs.linkTransferForManage(w, r)
	if !ok {
		return
	}
	idx, err := strconv.Atoi(r.PathValue("index"))
	if err != nil {
		http.Error(w, "invalid chunk index", http.StatusBadRequest)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxLinkChunkBytes+1))
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}
	if len(data) > maxLinkChunkBytes {
		http.Error(w, "chunk too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err := fs.store.writeChunk(m.TransferID, idx, data); err != nil {
		http.Error(w, "chunk rejected: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleLinkMeta: GET /link/{id}/meta, public (no manage token — a
// downloader has no token, only the TransferID and the fragment key). Only
// returns total_chunks — never a filename/size, which stay inside the
// encrypted manifest chunk (drive.js), never visible to the server.
func (fs *fileShareServer) handleLinkMeta(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m, ok := fs.store.getMeta(id)
	if !ok || m.Mode != "link" {
		http.Error(w, "no such transfer", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// one_time is omitempty so ordinary shares keep the exact pre-existing
	// response shape; the download page uses it to warn the recipient the
	// link is single-use before they spend it.
	_ = json.NewEncoder(w).Encode(struct {
		TotalChunks int  `json:"total_chunks"`
		OneTime     bool `json:"one_time,omitempty"`
	}{m.TotalChunks, m.OneTime})
}

// handleLinkChunkDownload: GET /link/{id}/chunk/{index}, public.
func (fs *fileShareServer) handleLinkChunkDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m, ok := fs.store.getMeta(id)
	if !ok || m.Mode != "link" {
		http.Error(w, "no such transfer", http.StatusNotFound)
		return
	}
	idx, err := strconv.Atoi(r.PathValue("index"))
	if err != nil || idx < 0 || idx >= m.TotalChunks {
		http.Error(w, "invalid chunk index", http.StatusBadRequest)
		return
	}
	data, err := fs.store.readChunk(id, idx)
	if err != nil {
		http.Error(w, "chunk not found", http.StatusNotFound)
		return
	}
	fs.store.touchLinkTransfer(id) // an actively-downloaded share shouldn't expire mid-transfer
	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := w.Write(data); err != nil {
		// Partial write — the downloader never got this chunk, so it must
		// not count toward a one-time burn; they'll retry it.
		return
	}
	if fs.store.markLinkChunkServed(id, idx) {
		log.Printf("file-share: one-time link share %s burned after first complete download", id)
	}
}

// handleLinkDelete: DELETE /link/{id}, X-Manage-Token required — lets the
// uploader remove their own drive entry instead of waiting for the TTL sweep.
func (fs *fileShareServer) handleLinkDelete(w http.ResponseWriter, r *http.Request) {
	m, ok := fs.linkTransferForManage(w, r)
	if !ok {
		return
	}
	if err := fs.store.deleteTransfer(m.TransferID); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

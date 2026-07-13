package main

import "time"

// wsEnvelope is the JSON control message exchanged over the WebSocket
// (ws.go), the same "JSON control frame, base64 byte fields" shape as
// chat-server's. Chunk *contents* travel as separate raw binary WS frames
// immediately following a "chunk" control frame — encoding a 4MB chunk as a
// base64 JSON string would cost ~33% overhead and a full extra copy for no
// reason, so only the small header (index, nonce) is JSON.
//
// Types:
//
//	hello               (client -> server) PubKey, Token
//	challenge           (server -> client) ServerEphemeralPub, Nonce, Ciphertext
//	challenge_response  (client -> server) Response
//	auth_ok / auth_error(server -> client) OK / Error
//	start_upload        (client -> server) TransferID, To, TotalChunks, Shareable
//	upload_ready        (server -> client) TransferID
//	chunk               (either direction, header only) TransferID, Index — binary frame with ciphertext follows immediately.
//	                    Nonce here is accepted but not persisted by the server (chunks are stored exactly as received,
//	                    opaque blobs); a real client should prepend its per-chunk AEAD nonce to the ciphertext bytes
//	                    themselves (nonce || ciphertext) so it survives the round trip without the server needing to
//	                    understand anything about it — see chat-client/app.js's FileShareClient.
//	chunk_ack           (server -> client) TransferID, Index
//	status              (client -> server) TransferID
//	status_result       (server -> client) TransferID, ReceivedIndices
//	list                (client -> server) (no fields)
//	list_result         (server -> client) Transfers
//	download            (client -> server) TransferID
//	download_done       (server -> client) TransferID
//	complete            (client -> server) TransferID — deletes the transfer immediately, unless it was
//	                    created with Shareable=true, in which case complete is a no-op and the recipient
//	                    can download it again later (CHECKLIST.md Phase 9's "'Shareable' transfer flag");
//	                    a shareable transfer still only ever goes away via the normal TTL sweep, same as
//	                    one nobody ever downloaded at all — there is no separate "revoke" message.
type wsEnvelope struct {
	Type string `json:"type"`

	PubKey             string `json:"pubkey,omitempty"`
	Token              string `json:"token,omitempty"`
	ServerEphemeralPub []byte `json:"server_ephemeral_pub,omitempty"`
	Nonce              []byte `json:"nonce,omitempty"`
	Ciphertext         []byte `json:"ciphertext,omitempty"` // only used for the auth challenge; chunk payloads ride the following binary frame, not this field
	Response           []byte `json:"response,omitempty"`
	OK                 bool   `json:"ok,omitempty"`
	Error              string `json:"error,omitempty"`

	TransferID      string            `json:"transfer_id,omitempty"`
	To              string            `json:"to,omitempty"`
	TotalChunks     int               `json:"total_chunks,omitempty"`
	Shareable       bool              `json:"shareable,omitempty"` // start_upload only — see wsEnvelope's "complete" doc above
	Index           int               `json:"index"`               // deliberately no omitempty — chunk 0 is a legitimate value; a real browser test caught Go's zero-value-omits-the-field-entirely footgun dropping "index" from the wire for chunk 0, which a same-language Go test client never noticed (its own json.Unmarshal just leaves Index at its zero value either way, so "field absent" and "field present as 0" were indistinguishable there — not so for JS reading a genuinely missing key as undefined)
	ReceivedIndices []int             `json:"received_indices,omitempty"`
	Transfers       []transferSummary `json:"transfers,omitempty"`
}

// transferSummary is what a recipient sees when listing pending transfers —
// enough to decide whether to download, no content/metadata beyond that
// (WHITEPAPER §9: "no indexing of file names/types/contents").
type transferSummary struct {
	TransferID  string    `json:"transfer_id"`
	From        string    `json:"from"`
	TotalChunks int       `json:"total_chunks"`
	CreatedAt   time.Time `json:"created_at"`
	Shareable   bool      `json:"shareable"`
}

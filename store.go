package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// transferIDPattern is deliberately restrictive: TransferID is client-
// supplied (start_upload's caller picks it, normally 16 random bytes
// base64-encoded — see chat-client/app.js's uploadFile) and is used
// directly in filesystem paths (transferDir below). Unvalidated, a value
// like "../../../etc" would let an authenticated client write, and later
// recursively delete (via complete/sweep), an arbitrary path outside
// dataDir — found in this project's own security review, not theoretical.
// Same shape/reasoning as mail/admind/passwddb.go's usernamePattern.
// Letters/digits/hyphen/underscore only (covers base64url output and the
// test suite's literal IDs like "transfer-1"); no "/", ".", or other
// path-meaningful characters. createTransfer is the single point every
// other TransferID-taking operation (chunk/status/download/complete/sweep)
// transitively depends on — none of them can reach the filesystem with an
// ID that was never accepted here, since they all key off s.meta, which
// only createTransfer ever populates.
var transferIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func validTransferID(id string) bool {
	return transferIDPattern.MatchString(id)
}

// maxTransfersPerSender bounds inode/memory growth from one authenticated
// sender — a real security-review finding: start_upload had no rate limit
// and no cap on how many distinct transfers a single paid-tier client could
// create, each costing a real directory + meta.json + in-memory map entry
// that only the (default 7-day) TTL sweep would ever reclaim. var, not
// const, so tests can shrink it instead of needing thousands of real
// transfers to exercise the cap.
var maxTransfersPerSender = 1000

type transferMeta struct {
	TransferID  string    `json:"transfer_id"`
	From        string    `json:"from"`
	To          string    `json:"to"`
	TotalChunks int       `json:"total_chunks"`
	CreatedAt   time.Time `json:"created_at"`
	TouchedAt   time.Time `json:"touched_at"`
	// Shareable, if set at creation, makes "complete" a no-op instead of an
	// immediate delete — the recipient can download the same transfer more
	// than once. Still only ever expires via the normal TTL sweep, same as
	// any other transfer (CHECKLIST.md Phase 9).
	Shareable bool `json:"shareable"`
	// Mode distinguishes the original identity-to-identity WS transfer
	// protocol ("", the zero value, for compatibility with every transfer
	// created before this field existed) from "link" — a public,
	// link-shareable file with no recipient identity at all, served over a
	// separate plain-HTTP surface (see handleLink* in server.go) gated only
	// by possession of the unguessable TransferID (to read) or ManageToken
	// (to write/delete). The two modes share this same on-disk
	// chunk-storage/TTL-sweep machinery; every handler that serves the link
	// HTTP surface must check Mode == "link" before touching a transfer, so
	// a "link" endpoint can never be used to read/delete a "direct" transfer
	// meant only for its named recipient, and vice versa.
	Mode string `json:"mode,omitempty"`
	// ManageToken is a second, separate secret from TransferID — only ever
	// held by the uploader's own browser (never appears in the share link,
	// which carries TransferID plus a decryption key in the URL fragment).
	// Empty/unused for direct-mode transfers, which authorize writes via the
	// existing WS identity instead.
	ManageToken string `json:"manage_token,omitempty"`
	// OneTime, meaningful only for link-mode transfers, makes the share
	// burn-after-read: once every chunk index has been served to a
	// downloader at least once, the whole transfer is deleted (see
	// markLinkChunkServed), so a share link leaked or scraped later yields
	// nothing. A never-downloaded one-time share still expires via the
	// normal TTL sweep like everything else.
	OneTime bool `json:"one_time,omitempty"`
}

// store persists encrypted chunks to disk under dataDir/<transfer id>/ —
// chunks and a small metadata file only, never plaintext or key material
// (WHITEPAPER §9). One transfer directory holds `meta.json` plus one
// `<index>.chunk` file per received chunk, so a resumed upload only needs
// to check which files already exist, not replay the whole transfer.
type store struct {
	mu       sync.Mutex
	dataDir  string
	ttl      time.Duration
	meta     map[string]transferMeta // key: transferID
	received map[string]map[int]bool // key: transferID -> set of chunk indices on disk
	// served tracks which chunk indices of a link-mode transfer have been
	// successfully sent to a downloader — the counterpart of received, for
	// the download side, and only consulted for OneTime burn decisions.
	// Deliberately in-memory only (never in meta.json): losing it on a
	// restart just lets an interrupted first download start over, and the
	// share still burns on the next complete pass — the failure direction
	// is a retry, never an unburnable link.
	served map[string]map[int]bool // key: transferID -> set of chunk indices served
}

func newStore(dataDir string, ttl time.Duration) (*store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	s := &store{
		dataDir:  dataDir,
		ttl:      ttl,
		meta:     make(map[string]transferMeta),
		received: make(map[string]map[int]bool),
		served:   make(map[string]map[int]bool),
	}
	if err := s.loadExisting(); err != nil {
		return nil, err
	}
	return s, nil
}

// loadExisting rebuilds in-memory state from disk on startup — a restarted
// server must not forget in-flight transfers, same reasoning as broker's
// flat JSON state file.
func (s *store) loadExisting() error {
	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		transferID := e.Name()
		metaPath := filepath.Join(s.dataDir, transferID, "meta.json")
		raw, err := os.ReadFile(metaPath)
		if err != nil {
			continue // no meta.json — not a valid transfer dir, skip rather than fail startup
		}
		var m transferMeta
		if err := json.Unmarshal(raw, &m); err != nil {
			continue
		}
		s.meta[transferID] = m

		chunkEntries, err := os.ReadDir(filepath.Join(s.dataDir, transferID))
		if err != nil {
			continue
		}
		set := make(map[int]bool)
		for _, ce := range chunkEntries {
			idxStr, ok := strings.CutSuffix(ce.Name(), ".chunk")
			if !ok {
				continue
			}
			if idx, err := strconv.Atoi(idxStr); err == nil {
				set[idx] = true
			}
		}
		s.received[transferID] = set
	}
	return nil
}

func (s *store) transferDir(transferID string) string {
	return filepath.Join(s.dataDir, transferID)
}

func (s *store) writeMeta(m transferMeta) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.transferDir(m.TransferID), "meta.json.tmp")
	final := filepath.Join(s.transferDir(m.TransferID), "meta.json")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

func (s *store) createTransfer(transferID, from, to string, totalChunks int, shareable bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.meta[transferID]; exists {
		return nil // idempotent: resuming an interrupted upload re-sends start_upload with the same ID
	}
	if !validTransferID(transferID) {
		return errors.New("invalid transfer id")
	}
	senderCount := 0
	for _, m := range s.meta {
		if m.From == from {
			senderCount++
		}
	}
	if senderCount >= maxTransfersPerSender {
		return errors.New("transfer limit reached for this account")
	}
	if err := os.MkdirAll(s.transferDir(transferID), 0o700); err != nil {
		return err
	}
	now := time.Now()
	m := transferMeta{TransferID: transferID, From: from, To: to, TotalChunks: totalChunks, CreatedAt: now, TouchedAt: now, Shareable: shareable}
	if err := s.writeMeta(m); err != nil {
		return err
	}
	s.meta[transferID] = m
	s.received[transferID] = make(map[int]bool)
	return nil
}

// createLinkTransfer is createTransfer's counterpart for the public
// link-share mode: no From/To identity at all (the whole point is that
// neither the uploader nor any downloader needs one), gated instead by the
// caller-supplied transferID/manageToken pair (both generated with
// crypto/rand by the caller — see server.go's handleLinkStart — high enough
// entropy that guessing either is not a practical attack, same trust model
// as a Firefox-Send-style share link). No per-sender transfer cap
// (maxTransfersPerSender) since there's no stable sender identity to key it
// by; abuse mitigation for this endpoint is expected at the reverse-proxy
// rate-limit layer, same as account creation elsewhere in this project.
func (s *store) createLinkTransfer(transferID, manageToken string, totalChunks int, oneTime bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.meta[transferID]; exists {
		return errors.New("transfer id already exists")
	}
	if !validTransferID(transferID) {
		return errors.New("invalid transfer id")
	}
	if err := os.MkdirAll(s.transferDir(transferID), 0o700); err != nil {
		return err
	}
	now := time.Now()
	m := transferMeta{TransferID: transferID, Mode: "link", ManageToken: manageToken, TotalChunks: totalChunks, CreatedAt: now, TouchedAt: now, OneTime: oneTime}
	if err := s.writeMeta(m); err != nil {
		return err
	}
	s.meta[transferID] = m
	s.received[transferID] = make(map[int]bool)
	return nil
}

func (s *store) getMeta(transferID string) (transferMeta, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.meta[transferID]
	return m, ok
}

// touchLinkTransfer bumps TouchedAt so an actively-downloaded link-share
// doesn't get swept mid-use by the TTL sweep — same reasoning writeChunk
// already applies on the upload side.
func (s *store) touchLinkTransfer(transferID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.meta[transferID]
	if !ok {
		return
	}
	m.TouchedAt = time.Now()
	s.meta[transferID] = m
	_ = s.writeMeta(m)
}

func (s *store) writeChunk(transferID string, index int, data []byte) error {
	s.mu.Lock()
	m, ok := s.meta[transferID]
	s.mu.Unlock()
	if !ok {
		return os.ErrNotExist
	}
	if index < 0 || index >= m.TotalChunks {
		return os.ErrInvalid
	}
	path := filepath.Join(s.transferDir(transferID), strconv.Itoa(index)+".chunk")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}

	s.mu.Lock()
	m.TouchedAt = time.Now()
	s.meta[transferID] = m
	if s.received[transferID] == nil {
		s.received[transferID] = make(map[int]bool)
	}
	s.received[transferID][index] = true
	s.mu.Unlock()
	return s.writeMeta(m)
}

func (s *store) readChunk(transferID string, index int) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.transferDir(transferID), strconv.Itoa(index)+".chunk"))
}

// receivedIndices returns which chunk indices are already stored, sorted —
// this is what makes an interrupted-then-resumed upload only re-send what's
// missing (CHECKLIST.md Phase 5's resumability requirement).
func (s *store) receivedIndices(transferID string) []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.received[transferID]
	out := make([]int, 0, len(set))
	for idx := range set {
		out = append(out, idx)
	}
	sort.Ints(out)
	return out
}

// listForRecipient returns pending transfers addressed to pubkey — no file
// name/type/content, just enough to decide whether to download
// (WHITEPAPER §9).
func (s *store) listForRecipient(pubkey string) []transferSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []transferSummary
	for _, m := range s.meta {
		if m.To == pubkey {
			out = append(out, transferSummary{TransferID: m.TransferID, From: m.From, TotalChunks: m.TotalChunks, CreatedAt: m.CreatedAt, Shareable: m.Shareable})
		}
	}
	return out
}

// deleteTransfer removes a transfer's directory entirely — called once the
// recipient confirms full receipt, or by sweep() once it's past its TTL
// unclaimed (WHITEPAPER §9: "configurable short TTL purges anything never
// picked up").
func (s *store) deleteTransfer(transferID string) error {
	s.mu.Lock()
	delete(s.meta, transferID)
	delete(s.received, transferID)
	delete(s.served, transferID)
	s.mu.Unlock()
	return os.RemoveAll(s.transferDir(transferID))
}

// markLinkChunkServed records that a chunk of a link-mode transfer was
// fully written to a downloader and, for a OneTime share, burns the
// transfer once every chunk index has been served at least once —
// returning true when it did. Re-serving the same chunk (a retry) never
// advances the count, so a flaky downloader can refetch freely until the
// full set is covered. Two downloaders racing the same link can jointly
// cover the set and burn it before either holds every chunk — deliberate:
// a one-time link in two hands at once has already leaked, and burning
// early is the right failure direction for a security feature.
func (s *store) markLinkChunkServed(transferID string, index int) bool {
	s.mu.Lock()
	m, ok := s.meta[transferID]
	if !ok || m.Mode != "link" {
		s.mu.Unlock()
		return false
	}
	if s.served[transferID] == nil {
		s.served[transferID] = make(map[int]bool)
	}
	s.served[transferID][index] = true
	burn := m.OneTime && len(s.served[transferID]) >= m.TotalChunks
	s.mu.Unlock()
	if burn {
		_ = s.deleteTransfer(transferID)
	}
	return burn
}

func (s *store) sweep() {
	s.mu.Lock()
	cutoff := time.Now().Add(-s.ttl)
	var expired []string
	for id, m := range s.meta {
		if m.TouchedAt.Before(cutoff) {
			expired = append(expired, id)
		}
	}
	s.mu.Unlock()
	for _, id := range expired {
		_ = s.deleteTransfer(id)
	}
}

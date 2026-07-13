// Command file-share is Bitphase's encrypted file transfer relay
// (WHITEPAPER.md §9). It reuses chat's client identity and entitlement
// token, and — like chat-server — never sees plaintext or key material:
// chunks are opaque ciphertext blobs stored by transfer ID until picked up.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"log"
	"net/http"
	"os"
	"time"
)

// sweepOnce runs one TTL sweep with panic recovery — same reasoning as
// chat-server's identical helper (found in this project's own security
// review): an unrecovered panic in a bare goroutine crashes the entire
// process, so one bad sweep would take down file-share entirely rather
// than just skipping a purge cycle.
func sweepOnce(st *store) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("file-share: recovered panic in TTL sweep: %v", r)
		}
	}()
	st.sweep()
}

func main() {
	addr := flag.String("addr", ":9001", "listen address")
	dataDir := flag.String("data-dir", "./data", "directory for stored (encrypted) transfer chunks")
	ttl := flag.Duration("ttl", 7*24*time.Hour, "how long an undelivered transfer is kept before being purged")
	brokerPubB64 := flag.String("broker-pubkey", os.Getenv("BROKER_PUBKEY"), "base64 Ed25519 broker public key — used to verify access tokens offline (WHITEPAPER §7.5). Required unless -broker-root-pubkey is set.")
	brokerRootPubB64 := flag.String("broker-root-pubkey", os.Getenv("BROKER_ROOT_PUBKEY"), "offline root Ed25519 pubkey, base64 (broker/KEY_POLICY.md v2) — if set, verifies the broker's current delegate certificate against this root and uses the certified delegate key instead of trusting -broker-pubkey directly. Requires -broker-url.")
	brokerURL := flag.String("broker-url", os.Getenv("BROKER_URL"), "broker base URL — only needed to fetch the delegate certificate when -broker-root-pubkey is set")
	minTier := flag.String("min-tier", "paid", "minimum token tier accepted: free or paid — set to free for testing before real payments are wired up")
	flag.Parse()

	closeLogging := initLogging("file-share")
	defer closeLogging()

	if *minTier != "free" && *minTier != "paid" {
		log.Fatalf("-min-tier must be free or paid, got %q", *minTier)
	}

	var brokerKeySrc *brokerKeySource
	if *brokerRootPubB64 != "" {
		rootPubRaw, err := base64.StdEncoding.DecodeString(*brokerRootPubB64)
		if err != nil || len(rootPubRaw) != ed25519.PublicKeySize {
			log.Fatalf("-broker-root-pubkey is not a valid base64 Ed25519 public key")
		}
		if *brokerURL == "" {
			log.Fatal("-broker-url (or BROKER_URL) is required when -broker-root-pubkey is set — file-share needs it to fetch the delegate certificate")
		}
		brokerKeySrc, err = newDelegateKeySource(http.DefaultClient, *brokerURL, ed25519.PublicKey(rootPubRaw))
		if err != nil {
			log.Fatalf("resolving broker's delegate key against pinned root: %v", err)
		}
		log.Printf("verified delegate certificate against pinned root — verifying access tokens against the certified delegate key")
	} else {
		if *brokerPubB64 == "" {
			log.Fatal("-broker-pubkey (or BROKER_PUBKEY) is required — file-share needs it to verify access tokens")
		}
		brokerPubRaw, err := base64.StdEncoding.DecodeString(*brokerPubB64)
		if err != nil || len(brokerPubRaw) != ed25519.PublicKeySize {
			log.Fatalf("-broker-pubkey is not a valid base64 Ed25519 public key")
		}
		brokerKeySrc = newStaticKeySource(ed25519.PublicKey(brokerPubRaw))
	}

	st, err := newStore(*dataDir, *ttl)
	if err != nil {
		log.Fatalf("initializing store: %v", err)
	}
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			sweepOnce(st)
		}
	}()

	fs := &fileShareServer{store: st, brokerPub: brokerKeySrc, minTier: *minTier}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", fs.handleWS)
	// Link-share HTTP surface (see server.go's "Link-share HTTP surface"
	// doc) — deliberately separate from /ws's identity-based protocol, and
	// CORS-open (withLinkCORS) since it's meant to be reachable from
	// something other than this exact website too. A bare OPTIONS
	// registration per path answers the browser's preflight for the two
	// handlers that take a custom header (chunk upload, delete); GET/POST
	// requests never preflight, but wrapping them too costs nothing and
	// keeps every /link/* response carrying the same CORS headers.
	mux.HandleFunc("POST /link/start", withLinkCORS(fs.handleLinkStart))
	mux.HandleFunc("OPTIONS /link/start", withLinkCORS(fs.handleLinkStart))
	mux.HandleFunc("PUT /link/{id}/chunk/{index}", withLinkCORS(fs.handleLinkChunkUpload))
	mux.HandleFunc("OPTIONS /link/{id}/chunk/{index}", withLinkCORS(fs.handleLinkChunkUpload))
	mux.HandleFunc("GET /link/{id}/chunk/{index}", withLinkCORS(fs.handleLinkChunkDownload))
	mux.HandleFunc("GET /link/{id}/meta", withLinkCORS(fs.handleLinkMeta))
	mux.HandleFunc("DELETE /link/{id}", withLinkCORS(fs.handleLinkDelete))
	mux.HandleFunc("OPTIONS /link/{id}", withLinkCORS(fs.handleLinkDelete))

	log.Printf("file-share listening on %s (transfer TTL %s, data dir %s, min-tier %s)", *addr, *ttl, *dataDir, *minTier)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

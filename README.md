# bitphase-file-share

The end-to-end encrypted file-transfer relay for [Bitphase](https://bitphase.tech).

Reuses chat's client identity (the same X25519 keypair) and paid-tier access
token — a second WebSocket service, not a second identity or entitlement system.
The server **never sees plaintext, keys, file names, or types**: it stores opaque
encrypted chunks by transfer ID until the recipient downloads them, then deletes
them. Unopened transfers self-destruct on a TTL; a one-time (burn-after-read)
link is destroyed the instant it's first downloaded, so a link scraped later
yields nothing. The decryption key rides in a link's URL `#fragment`, which
browsers never send to the server.

**Stack: Go standard library only, zero dependencies** — AES-256-GCM, same call
as the chat relay. See the [whitepaper](https://bitphase.tech/whitepaper) §9;
`§` references in the code point there.

Like the rest of the suite, this service verifies access tokens offline against a
separate coordination broker's pinned public key (the broker is control-plane
only and not in this repo). Runnable and readable on its own; a full deployment
also needs that broker.

## Build & test

```sh
go build ./...
go vet ./...
go test ./...
```

## License

[AGPL-3.0](LICENSE) — run a modified version as a network service and you must
offer its source to that service's users.

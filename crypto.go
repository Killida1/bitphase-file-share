package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// Identical auth-handshake crypto to chat-server/crypto.go, duplicated
// rather than imported (STACK.md: independently deployable services, each
// with its own minimal go.mod) — file-share reuses chat's client identity
// (WHITEPAPER §9) and proves it the same way: an ECDH challenge, not a
// second signature scheme. Only used for the connection handshake here;
// file chunk contents are encrypted client-side and this server never
// derives a key over them.
const authKeyInfo = "bitphase-fileshare-auth-v1"
const aeadKeySize = 32 // AES-256

func b64(b []byte) string            { return base64.StdEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func generateX25519Keypair() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

func parseX25519Public(raw []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(raw)
}

func hkdf(secret []byte, info string, length int) []byte {
	salt := make([]byte, sha256.Size)
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(secret)
	prk := extractor.Sum(nil)

	out := make([]byte, 0, length)
	var prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write([]byte(info))
		mac.Write([]byte{counter})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

func deriveAuthKey(shared []byte) []byte {
	return hkdf(shared, authKeyInfo, aeadKeySize)
}

func seal(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, nil), nil
}

func open(key, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("bad nonce size")
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Hand-rolled RFC 6455 WebSocket framing — STACK.md's call instead of
// gorilla/websocket or nhooyr.io/websocket: the handshake is one hash, and
// the frame format is a page of spec, not worth a dependency for.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

const wsMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
const maxFrameSize = 6 << 20 // 6MiB — chat-server's copy of this file uses 2MiB (plenty for chat messages); file-share needs room for a full ~4MB chunk (WHITEPAPER §9) plus its small JSON header overhead
// maxMessageSize caps total reassembled size across continuation frames —
// readFrame already caps a single frame at maxFrameSize, but ReadMessage's
// reassembly loop had no cap on frame *count*, so a pre-auth client (this is
// reachable before authenticate() ever checks a token) could send an
// unbounded stream of just-under-the-cap continuation frames and grow
// payload without bound — worse here than in chat-server, since it would
// also let a "chunk" upload exceed the documented ~4MB fixed-chunk design
// (WHITEPAPER §9) by an arbitrary amount. A small multiple of maxFrameSize
// is generous for any real message this protocol sends while still
// bounding the worst case.
var maxMessageSize = 4 * maxFrameSize // var, not const, so tests can shrink it instead of sending megabytes of real data

type wsOpcode byte

const (
	opContinuation wsOpcode = 0x0
	opText         wsOpcode = 0x1
	opBinary       wsOpcode = 0x2
	opClose        wsOpcode = 0x8
	opPing         wsOpcode = 0x9
	opPong         wsOpcode = 0xA
)

type wsConn struct {
	conn         net.Conn
	rw           *bufio.ReadWriter
	maskOutgoing bool // true for a client dialing out; servers must never mask (RFC 6455 §5.1)

	// writeMu serializes writeFrame calls — mirrors chat-server's copy of
	// this file (see its comment for the concurrent-writer scenario that
	// motivates it). File-share's own server.go currently only ever writes
	// to a connection from that connection's single read loop, so this
	// isn't fixing an observed bug here, just keeping the two structurally
	// identical copies of this file in lockstep and safe if that changes.
	writeMu sync.Mutex
}

// upgradeWebSocket performs the server side of the RFC 6455 handshake and
// hijacks the connection for raw framing.
func upgradeWebSocket(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("not a websocket upgrade request")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("connection does not support hijacking")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + computeAcceptKey(key) + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return &wsConn{conn: conn, rw: rw, maskOutgoing: false}, nil
}

// dialWebSocket performs the client side of the handshake — used by the
// test suite; the real client is the browser's native WebSocket API.
func dialWebSocket(addr, path string) (*wsConn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	keyBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
		conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	statusLine, err := rw.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.Contains(statusLine, "101") {
		conn.Close()
		return nil, errors.New("handshake failed: " + strings.TrimSpace(statusLine))
	}
	var acceptGot string
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Sec-WebSocket-Accept") {
			acceptGot = strings.TrimSpace(v)
		}
	}
	if acceptGot != computeAcceptKey(key) {
		conn.Close()
		return nil, errors.New("Sec-WebSocket-Accept did not match")
	}
	return &wsConn{conn: conn, rw: rw, maskOutgoing: true}, nil
}

func computeAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte(wsMagicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ReadMessage reads one full message, reassembling continuation frames and
// transparently answering pings, returning which opcode it was. File-share
// needs this (chat-server doesn't) to tell a JSON control frame (text) apart
// from a raw chunk payload (binary) on the same connection — see server.go's
// read loop, which expects "chunk" control headers to be immediately
// followed by exactly one binary frame of ciphertext.
func (c *wsConn) ReadMessage() ([]byte, wsOpcode, error) {
	var payload []byte
	var firstOpcode wsOpcode
	haveFirst := false
	for {
		fin, opcode, data, err := c.readFrame()
		if err != nil {
			return nil, 0, err
		}
		switch opcode {
		case opPing:
			if err := c.writeFrame(opPong, data); err != nil {
				return nil, 0, err
			}
			continue
		case opPong:
			continue
		case opClose:
			return nil, 0, io.EOF
		}
		if !haveFirst {
			firstOpcode = opcode
			haveFirst = true
		}
		if len(payload)+len(data) > maxMessageSize {
			return nil, 0, errors.New("message too large")
		}
		payload = append(payload, data...)
		if fin {
			break
		}
	}
	if firstOpcode != opText && firstOpcode != opBinary {
		return nil, 0, errors.New("unsupported opcode")
	}
	return payload, firstOpcode, nil
}

// WriteMessage sends a JSON control frame (text). Use WriteBinary for chunk
// payloads.
func (c *wsConn) WriteMessage(payload []byte) error {
	return c.writeFrame(opText, payload)
}

func (c *wsConn) WriteBinary(payload []byte) error {
	return c.writeFrame(opBinary, payload)
}

func (c *wsConn) Close() error {
	_ = c.writeFrame(opClose, nil)
	return c.conn.Close()
}

func (c *wsConn) readFrame() (fin bool, opcode wsOpcode, payload []byte, err error) {
	var header [2]byte
	if _, err = io.ReadFull(c.rw, header[:]); err != nil {
		return
	}
	fin = header[0]&0x80 != 0
	opcode = wsOpcode(header[0] & 0x0F)
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.rw, ext[:]); err != nil {
			return
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.rw, ext[:]); err != nil {
			return
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > maxFrameSize {
		err = errors.New("frame too large")
		return
	}

	var maskKey [4]byte
	if masked {
		if _, err = io.ReadFull(c.rw, maskKey[:]); err != nil {
			return
		}
	}

	payload = make([]byte, length)
	if _, err = io.ReadFull(c.rw, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return fin, opcode, payload, nil
}

// writeFrame writes one unfragmented frame. Servers must never mask
// (RFC 6455 §5.1); a client-role connection (tests) always does, with a
// fresh random key per frame.
func (c *wsConn) writeFrame(opcode wsOpcode, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	header := []byte{0x80 | byte(opcode)} // FIN=1

	n := len(payload)
	maskBit := byte(0)
	if c.maskOutgoing {
		maskBit = 0x80
	}
	switch {
	case n <= 125:
		header = append(header, maskBit|byte(n))
	case n <= 0xFFFF:
		header = append(header, maskBit|126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		header = append(header, ext[:]...)
	default:
		header = append(header, maskBit|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		header = append(header, ext[:]...)
	}

	if c.maskOutgoing {
		var maskKey [4]byte
		if _, err := io.ReadFull(rand.Reader, maskKey[:]); err != nil {
			return err
		}
		header = append(header, maskKey[:]...)
		masked := make([]byte, n)
		for i, b := range payload {
			masked[i] = b ^ maskKey[i%4]
		}
		payload = masked
	}

	if _, err := c.rw.Write(header); err != nil {
		return err
	}
	if _, err := c.rw.Write(payload); err != nil {
		return err
	}
	return c.rw.Flush()
}

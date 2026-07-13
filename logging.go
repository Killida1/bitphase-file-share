package main

import (
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// rotatingFile is a minimal size-based log rotator: <path> -> <path>.1 ->
// <path>.2 ... up to maxFiles, oldest deleted once that cap is hit. Written
// by hand rather than pulling in lumberjack — this service is stdlib-only
// by design (STACK.md), and rotation itself is a small, easy-to-audit
// amount of logic, not worth a dependency for.
type rotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	maxFiles int
	f        *os.File
	size     int64
}

func newRotatingFile(path string, maxBytes int64, maxFiles int) (*rotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &rotatingFile{path: path, maxBytes: maxBytes, maxFiles: maxFiles, f: f, size: info.Size()}, nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) rotate() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	_ = os.Remove(r.path + "." + strconv.Itoa(r.maxFiles))
	for i := r.maxFiles - 1; i >= 1; i-- {
		_ = os.Rename(r.path+"."+strconv.Itoa(i), r.path+"."+strconv.Itoa(i+1))
	}
	if err := os.Rename(r.path, r.path+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	r.f = f
	r.size = 0
	return nil
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// classicLogWriter adapts the stdlib "log" package's line-oriented output
// onto a structured slog.Logger, so every existing log.Printf/log.Println
// call site in this service becomes a real JSON record (time/level/service
// fields, durable, rotated) without rewriting each call site by hand. The
// line's own text becomes the record's "msg" field as-is — a call site
// that already formats "key=value" inline keeps that text inside the
// string rather than gaining separate JSON fields, which is what this shim
// doesn't get for free. New call sites that want real structured fields
// (broker/audit.go) log through slog directly instead of the "log" package.
type classicLogWriter struct {
	logger *slog.Logger
}

func (w classicLogWriter) Write(p []byte) (int, error) {
	w.logger.Info(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// initLogging sets up JSON-structured logging for this service: stdout
// (existing docker/systemd log capture keeps working unchanged) plus,
// if LOG_DIR is set, a rotating file — durable, survives process/container
// restarts, unlike relying on `docker logs`/journald retention alone.
// LOG_DIR unset means stdout-JSON only (the right default for `go test`/
// local dev, where nothing should write to disk unasked).
//
// Every existing log.Printf/log.Fatalf call site is carried along for free
// (see classicLogWriter) — this is what turns this service's previously
// bare, unstructured, unpersisted log.Printf calls into real durable JSON
// logs without a mechanical rewrite of every call site.
func initLogging(serviceName string) func() error {
	writers := []io.Writer{os.Stdout}
	closer := func() error { return nil }

	if dir := os.Getenv("LOG_DIR"); dir != "" {
		maxMB := envInt("LOG_MAX_MB", 20)
		maxFiles := envInt("LOG_MAX_FILES", 5)
		rf, err := newRotatingFile(filepath.Join(dir, serviceName+".log"), int64(maxMB)*1024*1024, maxFiles)
		if err != nil {
			log.Printf("logging: could not open log file in %s: %v (continuing with stdout only)", dir, err)
		} else {
			writers = append(writers, rf)
			closer = rf.Close
		}
	}

	handler := slog.NewJSONHandler(io.MultiWriter(writers...), &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(handler).With("service", serviceName)
	slog.SetDefault(logger)

	log.SetFlags(0) // slog's own "time" field replaces the stdlib log package's timestamp prefix
	log.SetOutput(classicLogWriter{logger: logger})

	return closer
}

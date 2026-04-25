package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
)

// captureClientHello opens a TLS connection to a local listener and reads
// the full first TLS record (the ClientHello). Reading by record-length
// rather than a single buffered read avoids flakes when TCP fragments the
// record or when the ClientHello is larger than the buffer.
func captureClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	captured := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			captured <- nil
			return
		}
		defer c.Close()
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err != nil {
			captured <- nil
			return
		}
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		body := make([]byte, recLen)
		if _, err := io.ReadFull(c, body); err != nil {
			captured <- nil
			return
		}
		captured <- append(append([]byte(nil), hdr...), body...)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	// Handshake will fail (server speaks no TLS), but we get the ClientHello on the wire.
	_ = tc.Handshake()
	return <-captured
}

func TestPeekSNI_RealClientHello(t *testing.T) {
	cases := []string{
		"api.anthropic.com",
		"api.openai.com",
		"a.b.c.d.example.com",
		"x.test", // very short
	}
	for _, want := range cases {
		t.Run(want, func(t *testing.T) {
			ch := captureClientHello(t, want)
			if len(ch) == 0 {
				t.Skip("captured nothing — local TLS plumbing failed")
			}
			br := bufio.NewReaderSize(bytes.NewReader(ch), 16384)
			got, err := peekSNI(br)
			if err != nil {
				t.Fatalf("peekSNI: %v", err)
			}
			if got != want {
				t.Errorf("peekSNI = %q, want %q", got, want)
			}
		})
	}
}

func TestPeekSNI_PeekDoesNotConsume(t *testing.T) {
	// Critical invariant for splice correctness: peekSNI must NOT advance the
	// reader. Otherwise the upstream gets a truncated ClientHello and the
	// handshake fails.
	ch := captureClientHello(t, "api.anthropic.com")
	if len(ch) == 0 {
		t.Skip("captured nothing")
	}
	br := bufio.NewReaderSize(bytes.NewReader(ch), 16384)
	_, _ = peekSNI(br)
	// Buffered() should equal the full ClientHello length.
	if br.Buffered() < len(ch) {
		t.Errorf("peekSNI consumed bytes: Buffered=%d want >= %d", br.Buffered(), len(ch))
	}
}

func TestPeekSNI_RejectsNonTLSRecord(t *testing.T) {
	// First byte != 0x16 means not a handshake record.
	junk := []byte{0x47, 0x45, 0x54, 0x20, 0x2f, 0x20} // "GET / "
	br := bufio.NewReaderSize(bytes.NewReader(junk), 256)
	_, err := peekSNI(br)
	if err == nil {
		t.Fatal("peekSNI should reject non-TLS record")
	}
	if !strings.Contains(err.Error(), "TLS handshake") {
		t.Errorf("error message should call out non-TLS record: %v", err)
	}
}

func TestPeekSNI_RejectsTruncatedHeader(t *testing.T) {
	// Only 3 bytes — not even the TLS record header.
	br := bufio.NewReaderSize(bytes.NewReader([]byte{0x16, 0x03, 0x01}), 256)
	if _, err := peekSNI(br); err == nil {
		t.Fatal("peekSNI should reject truncated header")
	}
}

func TestPeekSNI_RejectsImplausibleLength(t *testing.T) {
	// Record header claims length = 65535, way past TLS max (16384).
	hdr := []byte{0x16, 0x03, 0x01, 0xff, 0xff}
	br := bufio.NewReaderSize(bytes.NewReader(hdr), 8192)
	if _, err := peekSNI(br); err == nil {
		t.Fatal("peekSNI should reject implausible record length")
	}
}

func TestPeekSNI_LowercasesName(t *testing.T) {
	// SNI in TLS is case-insensitive; we normalize so the allowlist comparison works.
	// Hand-craft a minimal ClientHello with mixed-case SNI by capturing then patching.
	ch := captureClientHello(t, "API.Anthropic.COM")
	if len(ch) == 0 {
		t.Skip("captured nothing")
	}
	br := bufio.NewReaderSize(bytes.NewReader(ch), 16384)
	got, err := peekSNI(br)
	if err != nil {
		t.Fatalf("peekSNI: %v", err)
	}
	if got != "api.anthropic.com" {
		t.Errorf("peekSNI = %q, want lowercased %q", got, "api.anthropic.com")
	}
}

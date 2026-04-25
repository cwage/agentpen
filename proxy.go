package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// TLS spec: TLSPlaintext.length is uint16 but bounded to 2^14. Going wider
// would require non-conformant ClientHellos.
const maxTLSRecordLen = 16384

// Max wall-clock lifetime for a single proxied connection. Bounds host-side
// resource exposure if a sandbox holds connections open without doing I/O.
// Real API calls — including long streaming responses — finish well below this.
const proxyConnMaxLifetime = 1 * time.Hour

// sniProxy listens on host loopback. For each TCP connection it peeks the
// TLS ClientHello, extracts the SNI server_name, checks it against an
// allowlist, then dials the real <sni>:443 and splices bytes between the
// two — never terminating TLS, never decrypting anything.
type sniProxy struct {
	ln      net.Listener
	allowed map[string]bool
	logf    func(string, ...any)
}

// startSNIProxy binds an ephemeral port on 127.0.0.1, starts serving in
// a goroutine, and returns a handle. Caller must Close() to shut down.
func startSNIProxy(allowedHosts []string, logf func(string, ...any)) (*sniProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("sni proxy listen: %w", err)
	}
	allowed := make(map[string]bool, len(allowedHosts))
	for _, h := range allowedHosts {
		allowed[strings.ToLower(strings.TrimSpace(h))] = true
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	p := &sniProxy{ln: ln, allowed: allowed, logf: logf}
	go p.serve()
	return p, nil
}

// Port returns the bound TCP port. The forwarder inside the sandbox
// dials gateway:Port to reach this proxy.
func (p *sniProxy) Port() int { return p.ln.Addr().(*net.TCPAddr).Port }

func (p *sniProxy) Close() error { return p.ln.Close() }

func (p *sniProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *sniProxy) handle(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

	// 5-byte record header + max record body (16384). Without the +5 a
	// max-sized ClientHello would trip ErrBufferFull in peekSNI's Peek(5+recLen).
	br := bufio.NewReaderSize(client, 5+maxTLSRecordLen)
	sni, err := peekSNI(br)
	if err != nil {
		p.logf("sni proxy: %s: peek SNI: %v", client.RemoteAddr(), err)
		return
	}
	if !p.allowed[strings.ToLower(sni)] {
		p.logf("sni proxy: %s: BLOCK sni=%s", client.RemoteAddr(), sni)
		return
	}
	p.logf("sni proxy: %s: ALLOW sni=%s", client.RemoteAddr(), sni)

	upstream, err := net.DialTimeout("tcp", sni+":443", 10*time.Second)
	if err != nil {
		p.logf("sni proxy: dial upstream %s: %v", sni, err)
		return
	}
	defer upstream.Close()

	// Replace the handshake deadline with a bounded total lifetime so an
	// idle-but-open connection can't tie up host resources indefinitely.
	deadline := time.Now().Add(proxyConnMaxLifetime)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)

	spliceConns(br, client, upstream)
}

// spliceConns shovels bytes both ways between client and upstream. When one
// direction EOFs we half-close the corresponding write side (CloseWrite) so
// the other direction can still drain any in-flight bytes — important for
// long-lived flows and graceful TLS shutdown. Returns when both directions
// finish.
func spliceConns(clientReader io.Reader, client, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, clientReader)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
	}()
	wg.Wait()
}

// closeWrite half-closes the write side of a TCP connection if possible.
// Best-effort: any non-TCP conn or already-closed conn just no-ops.
func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

// peekSNI parses just enough of a TLS ClientHello (RFC 8446 §4 / RFC 5246 §7.4)
// to extract the SNI host_name. It reads via Peek() so the bytes remain in the
// reader for the spliced upstream to receive verbatim.
func peekSNI(br *bufio.Reader) (string, error) {
	hdr, err := br.Peek(5)
	if err != nil {
		return "", fmt.Errorf("peek record header: %w", err)
	}
	if hdr[0] != 0x16 {
		return "", fmt.Errorf("not a TLS handshake record (got 0x%02x)", hdr[0])
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen < 42 || recLen > maxTLSRecordLen {
		return "", fmt.Errorf("implausible record length %d", recLen)
	}
	full, err := br.Peek(5 + recLen)
	if err != nil {
		return "", fmt.Errorf("peek record body: %w", err)
	}
	body := full[5:]

	if len(body) < 4 || body[0] != 0x01 {
		return "", errors.New("not a ClientHello")
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if 4+hsLen > len(body) {
		return "", errors.New("ClientHello truncated")
	}
	p := body[4 : 4+hsLen]

	if len(p) < 34 {
		return "", errors.New("ClientHello too short")
	}
	p = p[34:] // skip version(2) + random(32)

	// session_id
	if len(p) < 1 {
		return "", errors.New("missing session_id")
	}
	sl := int(p[0])
	p = p[1:]
	if len(p) < sl {
		return "", errors.New("session_id truncated")
	}
	p = p[sl:]

	// cipher_suites
	if len(p) < 2 {
		return "", errors.New("missing cipher_suites")
	}
	cl := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) < cl {
		return "", errors.New("cipher_suites truncated")
	}
	p = p[cl:]

	// compression_methods
	if len(p) < 1 {
		return "", errors.New("missing compression_methods")
	}
	ml := int(p[0])
	p = p[1:]
	if len(p) < ml {
		return "", errors.New("compression_methods truncated")
	}
	p = p[ml:]

	// extensions
	if len(p) < 2 {
		return "", errors.New("no extensions")
	}
	el := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) < el {
		return "", errors.New("extensions truncated")
	}
	exts := p[:el]

	for len(exts) >= 4 {
		etype := binary.BigEndian.Uint16(exts[0:2])
		elen := int(binary.BigEndian.Uint16(exts[2:4]))
		if 4+elen > len(exts) {
			return "", errors.New("extension truncated")
		}
		edata := exts[4 : 4+elen]
		exts = exts[4+elen:]

		if etype != 0x0000 {
			continue
		}
		if len(edata) < 2 {
			return "", errors.New("SNI extension malformed")
		}
		listLen := int(binary.BigEndian.Uint16(edata[:2]))
		list := edata[2:]
		if len(list) < listLen {
			return "", errors.New("SNI list truncated")
		}
		list = list[:listLen]
		for len(list) >= 3 {
			nt := list[0]
			nlen := int(binary.BigEndian.Uint16(list[1:3]))
			if 3+nlen > len(list) {
				return "", errors.New("SNI name truncated")
			}
			name := string(list[3 : 3+nlen])
			list = list[3+nlen:]
			if nt == 0 {
				return strings.ToLower(name), nil
			}
		}
		return "", errors.New("no host_name in SNI extension")
	}
	return "", errors.New("no SNI extension")
}

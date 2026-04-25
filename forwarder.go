package main

import (
	"fmt"
	"net"
	"time"
)

// forwarderDialTimeout caps how long a single inbound connection waits for
// the upstream connect. Without it, hung upstreams (SYN retries) would let
// goroutines accumulate one per inbound — easy self-DoS surface even though
// the rest of the design treats forwarder DoS as a self-DoS.
const forwarderDialTimeout = 10 * time.Second

// forwarderConnMaxLifetime bounds total wall-clock per spliced connection.
// Same role as proxyConnMaxLifetime on the host side: a sandbox process
// opening many idle conns shouldn't be able to accumulate goroutines/FDs
// indefinitely.
const forwarderConnMaxLifetime = 1 * time.Hour

// runForwarder is the in-namespace TCP splicer. It binds a low port on
// loopback (free here because we run as userns-root in pasta's userns),
// then for each connection opens a corresponding connection to upstream
// and shovels bytes between the two.
//
// Invoked as `agentpen __forwarder <listen> <upstream>` from inside the
// pasta userns. Lifetime is bounded by pasta's pid namespace — when
// pasta exits, the namespace and this process go with it.
func runForwarder(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: agentpen __forwarder <listen> <upstream>")
	}
	listenAddr, upstreamAddr := args[0], args[1]

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("forwarder listen %s: %w", listenAddr, err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("forwarder accept: %w", err)
		}
		go forwardOne(c, upstreamAddr)
	}
}

func forwardOne(client net.Conn, upstreamAddr string) {
	defer client.Close()
	upstream, err := net.DialTimeout("tcp", upstreamAddr, forwarderDialTimeout)
	if err != nil {
		return
	}
	defer upstream.Close()
	deadline := time.Now().Add(forwarderConnMaxLifetime)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	// Same half-close pattern as the SNI proxy — shovel both ways, CloseWrite
	// when one direction EOFs so the other can drain.
	spliceConns(client, client, upstream)
}

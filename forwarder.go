package main

import (
	"fmt"
	"net"
	"os"
)

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
	fmt.Fprintf(os.Stderr, "agentpen forwarder: %s -> %s\n", listenAddr, upstreamAddr)
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
	upstream, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		return
	}
	defer upstream.Close()
	// Same half-close pattern as the SNI proxy — shovel both ways, CloseWrite
	// when one direction EOFs so the other can drain.
	spliceConns(client, client, upstream)
}

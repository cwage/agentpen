package main

import (
	"encoding/binary"
	"os"

	"golang.org/x/sys/unix"
)

// buildSeccompFilter produces a BPF program that:
//   - rejects non-amd64 architectures (kills process)
//   - kills on any syscall in blockedSyscallsAmd64
//   - allows everything else
//
// bwrap consumes this via --seccomp FD. The wire format is a raw sequence of
// struct sock_filter records (8 bytes each, native byte order).
//
// amd64-only for MVP; multi-arch requires per-arch syscall tables.

const (
	// from linux/audit.h
	auditArchX86_64 uint32 = 0xC000003E

	// from linux/seccomp.h
	secRetKill  uint32 = 0x00000000
	secRetAllow uint32 = 0x7fff0000

	// from linux/filter.h
	bpfLD  uint16 = 0x00
	bpfJMP uint16 = 0x05
	bpfRET uint16 = 0x06
	bpfW   uint16 = 0x00
	bpfABS uint16 = 0x20
	bpfJEQ uint16 = 0x10
	bpfK   uint16 = 0x00

	// offsets in struct seccomp_data
	soffNr   uint32 = 0
	soffArch uint32 = 4
)

// Syscalls blocked inside the sandbox. These are kernel-touching or sandbox-breakout
// vectors rarely needed by agents. Add more as we encounter attack surface; remove
// if a legitimate agent workflow breaks.
var blockedSyscallsAmd64 = []uint32{
	unix.SYS_PTRACE,
	unix.SYS_KEYCTL,
	unix.SYS_ADD_KEY,
	unix.SYS_REQUEST_KEY,
	unix.SYS_MOUNT,
	unix.SYS_UMOUNT2,
	unix.SYS_PIVOT_ROOT,
	unix.SYS_BPF,
	unix.SYS_INIT_MODULE,
	unix.SYS_FINIT_MODULE,
	unix.SYS_DELETE_MODULE,
	unix.SYS_REBOOT,
	unix.SYS_KEXEC_LOAD,
	unix.SYS_KEXEC_FILE_LOAD,
	unix.SYS_PERF_EVENT_OPEN,
	unix.SYS_SETTIMEOFDAY,
	unix.SYS_CLOCK_SETTIME,
	unix.SYS_CLOCK_ADJTIME,
	unix.SYS_ACCT,
	unix.SYS_QUOTACTL,
	unix.SYS_SYSLOG,
}

func sfilter(code, jt, jf uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: uint8(jt), Jf: uint8(jf), K: k}
}

func buildSeccompFilter() []unix.SockFilter {
	var f []unix.SockFilter

	// arch = seccomp_data.arch
	f = append(f, sfilter(bpfLD|bpfW|bpfABS, 0, 0, soffArch))
	// if arch == AUDIT_ARCH_X86_64, skip next (continue); else fall through to KILL
	f = append(f, sfilter(bpfJMP|bpfJEQ|bpfK, 1, 0, auditArchX86_64))
	f = append(f, sfilter(bpfRET|bpfK, 0, 0, secRetKill))

	// nr = seccomp_data.nr
	f = append(f, sfilter(bpfLD|bpfW|bpfABS, 0, 0, soffNr))

	// for each blocked: if nr == syscall → next (KILL); else skip 1
	for _, s := range blockedSyscallsAmd64 {
		f = append(f, sfilter(bpfJMP|bpfJEQ|bpfK, 0, 1, uint32(s)))
		f = append(f, sfilter(bpfRET|bpfK, 0, 0, secRetKill))
	}

	// default: allow
	f = append(f, sfilter(bpfRET|bpfK, 0, 0, secRetAllow))
	return f
}

func serializeFilter(filter []unix.SockFilter) []byte {
	buf := make([]byte, 8*len(filter))
	for i, f := range filter {
		binary.NativeEndian.PutUint16(buf[8*i:], f.Code)
		buf[8*i+2] = f.Jt
		buf[8*i+3] = f.Jf
		binary.NativeEndian.PutUint32(buf[8*i+4:], f.K)
	}
	return buf
}

// writeSeccompFilter writes the BPF filter to a temp file and returns its path.
// Caller is responsible for cleanup.
func writeSeccompFilter() (string, error) {
	f, err := os.CreateTemp("", "sbx-seccomp-*.bpf")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(serializeFilter(buildSeccompFilter())); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

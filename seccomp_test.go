package main

import (
	"encoding/binary"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBlockedSyscalls_IncludeKernelTouchers(t *testing.T) {
	// The sandbox's seccomp layer is load-bearing for the threat model: a
	// malicious agent must not be able to ptrace, load BPF, mount things, or
	// fiddle with kernel keyrings. If any of these ever get removed from the
	// blocklist it must be an intentional, reviewed decision — this test
	// forces that conversation.
	mustBlock := map[string]uint32{
		"ptrace":           unix.SYS_PTRACE,
		"keyctl":           unix.SYS_KEYCTL,
		"add_key":          unix.SYS_ADD_KEY,
		"request_key":      unix.SYS_REQUEST_KEY,
		"mount":            unix.SYS_MOUNT,
		"umount2":          unix.SYS_UMOUNT2,
		"pivot_root":       unix.SYS_PIVOT_ROOT,
		"bpf":              unix.SYS_BPF,
		"init_module":      unix.SYS_INIT_MODULE,
		"finit_module":     unix.SYS_FINIT_MODULE,
		"delete_module":    unix.SYS_DELETE_MODULE,
		"reboot":           unix.SYS_REBOOT,
		"kexec_load":       unix.SYS_KEXEC_LOAD,
		"kexec_file_load":  unix.SYS_KEXEC_FILE_LOAD,
		"perf_event_open":  unix.SYS_PERF_EVENT_OPEN,
	}
	for name, want := range mustBlock {
		found := false
		for _, got := range blockedSyscallsAmd64 {
			if uint32(got) == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s (syscall %d) to be in blockedSyscallsAmd64", name, want)
		}
	}
}

func TestBlockedSyscalls_NoDuplicates(t *testing.T) {
	seen := map[uint32]bool{}
	for _, s := range blockedSyscallsAmd64 {
		if seen[uint32(s)] {
			t.Errorf("duplicate syscall in blocklist: %d", s)
		}
		seen[uint32(s)] = true
	}
}

func TestBuildSeccompFilter_ArchGuardFirst(t *testing.T) {
	// First three instructions must be: load arch, jeq x86_64 (skip 1 on match),
	// ret KILL. Anything else means the arch guard regressed and non-amd64
	// processes could slip past the blocklist.
	f := buildSeccompFilter()
	if len(f) < 3 {
		t.Fatalf("filter too short: %d instructions", len(f))
	}
	// inst 0: BPF_LD|BPF_W|BPF_ABS @ soffArch
	if f[0].Code != bpfLD|bpfW|bpfABS || f[0].K != soffArch {
		t.Errorf("inst[0] not arch load: %+v", f[0])
	}
	// inst 1: BPF_JMP|BPF_JEQ|BPF_K, jt=1, jf=0, k=AUDIT_ARCH_X86_64
	if f[1].Code != bpfJMP|bpfJEQ|bpfK || f[1].Jt != 1 || f[1].K != auditArchX86_64 {
		t.Errorf("inst[1] not arch-JEQ x86_64: %+v", f[1])
	}
	// inst 2: BPF_RET|BPF_K, k=SECCOMP_RET_KILL
	if f[2].Code != bpfRET|bpfK || f[2].K != secRetKill {
		t.Errorf("inst[2] not RET_KILL on arch mismatch: %+v", f[2])
	}
}

func TestBuildSeccompFilter_EveryBlockedHasKillBranch(t *testing.T) {
	// Every blocked syscall should produce a (JEQ, RET_KILL) pair after the
	// arch guard + nr load. Count them.
	f := buildSeccompFilter()
	pairs := 0
	for i := 0; i+1 < len(f); i++ {
		if f[i].Code == bpfJMP|bpfJEQ|bpfK && f[i+1].Code == bpfRET|bpfK && f[i+1].K == secRetKill {
			// skip the arch guard at the top (inst 1+2): its K is auditArchX86_64
			if f[i].K == auditArchX86_64 {
				continue
			}
			pairs++
		}
	}
	if pairs != len(blockedSyscallsAmd64) {
		t.Errorf("expected %d (JEQ, RET_KILL) pairs for blocked syscalls, got %d",
			len(blockedSyscallsAmd64), pairs)
	}
}

func TestBuildSeccompFilter_DefaultAllow(t *testing.T) {
	// Last instruction is the default-allow tail: BPF_RET|BPF_K with SECCOMP_RET_ALLOW.
	// Without this the filter would kill everything — catastrophic.
	f := buildSeccompFilter()
	last := f[len(f)-1]
	if last.Code != bpfRET|bpfK || last.K != secRetAllow {
		t.Errorf("last instruction not RET_ALLOW: %+v", last)
	}
}

func TestBuildSeccompFilter_ExpectedLength(t *testing.T) {
	// arch guard (3) + nr load (1) + 2 per blocked syscall + default allow (1).
	f := buildSeccompFilter()
	want := 3 + 1 + 2*len(blockedSyscallsAmd64) + 1
	if len(f) != want {
		t.Errorf("filter length = %d, want %d", len(f), want)
	}
}

func TestSerializeFilter_LengthAndRoundTrip(t *testing.T) {
	f := []unix.SockFilter{
		{Code: 0x1234, Jt: 5, Jf: 6, K: 0xCAFEBABE},
		{Code: 0x0020, Jt: 0, Jf: 0, K: 0xDEADBEEF},
	}
	buf := serializeFilter(f)
	if len(buf) != 8*len(f) {
		t.Errorf("serialized length = %d, want %d", len(buf), 8*len(f))
	}
	// Re-parse and check fields on the first filter.
	code := binary.NativeEndian.Uint16(buf[0:])
	jt := buf[2]
	jf := buf[3]
	k := binary.NativeEndian.Uint32(buf[4:])
	if code != 0x1234 || jt != 5 || jf != 6 || k != 0xCAFEBABE {
		t.Errorf("first filter round-trip mismatch: code=%x jt=%d jf=%d k=%x",
			code, jt, jf, k)
	}
}

func TestWriteSeccompFilter(t *testing.T) {
	path, err := writeSeccompFilter()
	if err != nil {
		t.Fatalf("writeSeccompFilter: %v", err)
	}
	defer os.Remove(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read filter file: %v", err)
	}
	want := serializeFilter(buildSeccompFilter())
	if len(data) != len(want) {
		t.Errorf("file size = %d, want %d", len(data), len(want))
	}
	for i := range data {
		if data[i] != want[i] {
			t.Errorf("byte %d differs: got %x, want %x", i, data[i], want[i])
			break
		}
	}
}

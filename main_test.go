package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeHosts_TrimsLowercasesDedupes(t *testing.T) {
	in := []string{
		"  api.anthropic.com  ",
		"API.Anthropic.com", // dup after lowercase
		"api.openai.com",
		"", // skipped silently
		"api.openai.com", // exact dup
	}
	got, err := normalizeHosts(in)
	if err != nil {
		t.Fatalf("normalizeHosts: %v", err)
	}
	want := []string{"api.anthropic.com", "api.openai.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNormalizeHosts_RejectsBadInput(t *testing.T) {
	cases := []string{
		"a.com b.com",         // embedded space
		"a.com\tb.com",        // tab
		"a.com\nb.com",        // newline
		"a.com\rb.com",        // CR
		"a.com\x00b.com",      // NUL
		"a.com\x7fb.com",      // DEL
	}
	for _, bad := range cases {
		t.Run(strings.ReplaceAll(bad, "\x00", "<NUL>"), func(t *testing.T) {
			_, err := normalizeHosts([]string{bad})
			if err == nil {
				t.Errorf("normalizeHosts(%q) accepted; want error", bad)
				return
			}
			if !strings.Contains(err.Error(), "invalid hostname") {
				t.Errorf("error should mention invalid hostname: %v", err)
			}
		})
	}
}

func TestNormalizeHosts_RejectsLoopbackAndIPLiterals(t *testing.T) {
	// The host-side SNI proxy lives in the host network namespace, so a value
	// in the allowlist that resolves to (or *is*) a loopback/private address
	// would let the sandbox steer the proxy into dialing host-local services.
	// normalizeHosts rejects these at config time.
	cases := []string{
		"localhost",
		"LocalHost",     // case-insensitive
		"localhost.",    // DNS-FQDN form
		"LocalHost.",    // both
		"foo.localhost",
		"foo.localhost.", // FQDN form of the .localhost suffix
		"127.0.0.1",
		"127.99.99.99",
		"::1",
		"10.0.0.5",      // IP literal — not necessarily loopback, but no SNI semantics
		"2001:db8::1",   // IPv6 literal
	}
	for _, bad := range cases {
		t.Run(bad, func(t *testing.T) {
			_, err := normalizeHosts([]string{bad})
			if err == nil {
				t.Errorf("normalizeHosts(%q) accepted; want error", bad)
				return
			}
			if !strings.Contains(err.Error(), "invalid hostname") {
				t.Errorf("error should mention invalid hostname: %v", err)
			}
		})
	}
}

func TestNormalizeHosts_PreservesOrder(t *testing.T) {
	// Order matters for /etc/hosts readability and predictability of the
	// allowlist comparison set; trim/lowercase shouldn't shuffle.
	in := []string{"c.com", "a.com", "b.com"}
	got, err := normalizeHosts(in)
	if err != nil {
		t.Fatalf("normalizeHosts: %v", err)
	}
	want := []string{"c.com", "a.com", "b.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExitError_Unwraps(t *testing.T) {
	// main() relies on errors.As to recover the exit code without
	// stringifying the error and parsing it.
	err := error(&exitError{code: 42})
	var ee *exitError
	if !errors.As(err, &ee) {
		t.Fatal("errors.As failed to extract *exitError")
	}
	if ee.code != 42 {
		t.Errorf("code = %d, want 42", ee.code)
	}
}

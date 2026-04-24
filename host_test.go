package main

import (
	"reflect"
	"testing"
)

// fakeProbe returns a pathProbe that says "yes" for the listed paths.
func fakeProbe(existing ...string) pathProbe {
	set := map[string]bool{}
	for _, p := range existing {
		set[p] = true
	}
	return func(path string) bool { return set[path] }
}

func TestDetectHostLayout_NixOS(t *testing.T) {
	// /etc/NIXOS present → full NixOS layout, Nix-store only (no /usr).
	got := detectHostLayoutWith(fakeProbe("/etc/NIXOS", "/nix/store", "/run/current-system", "/run/wrappers"))
	want := HostLayout{
		ReadOnlyBinds: []string{"/nix/store", "/run/current-system", "/run/wrappers"},
		PathEnv:       "/run/current-system/sw/bin:/run/wrappers/bin",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NixOS layout = %+v, want %+v", got, want)
	}
}

func TestDetectHostLayout_VanillaFHS(t *testing.T) {
	// Vanilla Ubuntu/Debian/etc.: no /etc/NIXOS, no /nix/store.
	got := detectHostLayoutWith(fakeProbe("/usr", "/bin"))
	want := HostLayout{
		ReadOnlyBinds: []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"},
		PathEnv:       "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FHS layout = %+v, want %+v", got, want)
	}
}

func TestDetectHostLayout_NixOnFHS(t *testing.T) {
	// Regression test for #13: Nix installer on Ubuntu creates /nix/store but
	// NOT /etc/NIXOS. Prior behavior misrouted to the NixOS branch, losing
	// /usr/bin/... access. Expected: FHS layout with /nix/store appended.
	got := detectHostLayoutWith(fakeProbe("/nix/store"))
	want := HostLayout{
		ReadOnlyBinds: []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/nix/store"},
		PathEnv:       "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Nix-on-FHS layout = %+v, want %+v", got, want)
	}
}

func TestDetectHostLayout_NixOSSentinelWins(t *testing.T) {
	// Defense in depth: even if /nix/store is also present (it always is on
	// NixOS), the /etc/NIXOS sentinel takes priority and we get the NixOS
	// layout — not a merged one.
	got := detectHostLayoutWith(fakeProbe("/etc/NIXOS", "/nix/store", "/usr", "/bin"))
	if len(got.ReadOnlyBinds) > 0 && got.ReadOnlyBinds[0] != "/nix/store" {
		t.Errorf("NixOS should take priority over FHS; got binds = %v", got.ReadOnlyBinds)
	}
	for _, b := range got.ReadOnlyBinds {
		if b == "/usr" {
			t.Errorf("NixOS layout should not include /usr; got %v", got.ReadOnlyBinds)
		}
	}
}

package main

import "os"

// HostLayout describes filesystem bind mounts needed for a given host distribution
// so that dynamic binaries inside the sandbox can resolve their libraries.
type HostLayout struct {
	ReadOnlyBinds []string
	PathEnv       string
}

// pathProbe reports whether a host path exists. Abstracted out so
// detectHostLayoutWith can be tested hermetically.
type pathProbe func(string) bool

func realPathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// detectHostLayout picks sensible defaults for NixOS vs. FHS-style distros.
// Users can override specific binds via --mount if needed.
func detectHostLayout() HostLayout {
	return detectHostLayoutWith(realPathExists)
}

// detectHostLayoutWith is the pure-logic form, taking an injected path-exists
// probe so it can be tested across host shapes (NixOS, FHS, Nix-on-FHS).
//
// Distinguishing NixOS from Nix-on-FHS: "/nix/store exists" is NOT the NixOS
// signal — the multi-user Nix installer creates /nix/store on any FHS distro.
// /etc/NIXOS is the canonical sentinel (NixOS itself creates it).
func detectHostLayoutWith(exists pathProbe) HostLayout {
	if exists("/etc/NIXOS") {
		return HostLayout{
			ReadOnlyBinds: []string{"/nix/store", "/run/current-system", "/run/wrappers"},
			PathEnv:       "/run/current-system/sw/bin:/run/wrappers/bin",
		}
	}
	// FHS default (Ubuntu, Debian, Fedora, Arch, etc.). On Nix-on-FHS the user
	// has /nix/store via the installer; append it so Nix-installed agents work
	// without manual --mount flags.
	binds := []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}
	if exists("/nix/store") {
		binds = append(binds, "/nix/store")
	}
	return HostLayout{
		ReadOnlyBinds: binds,
		PathEnv:       "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
}

package main

import "os"

// HostLayout describes filesystem bind mounts needed for a given host distribution
// so that dynamic binaries inside the sandbox can resolve their libraries.
type HostLayout struct {
	ReadOnlyBinds []string
	PathEnv       string
}

// detectHostLayout picks sensible defaults for NixOS vs. FHS-style distros.
// Users can override specific binds via --mount if needed.
func detectHostLayout() HostLayout {
	if _, err := os.Stat("/nix/store"); err == nil {
		return HostLayout{
			ReadOnlyBinds: []string{"/nix/store", "/run/current-system", "/run/wrappers"},
			PathEnv:       "/run/current-system/sw/bin:/run/wrappers/bin",
		}
	}
	// FHS default (Ubuntu, Debian, Fedora, Arch, etc.)
	return HostLayout{
		ReadOnlyBinds: []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"},
		PathEnv:       "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
}

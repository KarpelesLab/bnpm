package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// childProfile is the serialized profile data passed from parent to child.
type childProfile struct {
	Profile    Profile  `json:"profile"`
	ProjectDir string   `json:"project_dir"`
	Command    string   `json:"command"`
	Args       []string `json:"args"`
	HomeDir    string   `json:"home_dir"`
	Username   string   `json:"username"`
}

// File descriptor layout for ExtraFiles:
// fd 3 = sync read pipe (parent → child)
// fd 4 = sync write pipe (child → parent)
// fd 5 = unix socket for TAP fd passing (only in filtered mode)

// runChild is the entry point for the child process inside the new namespaces.
func runChild() {
	// Deserialize profile from environment variable
	profileJSON := os.Getenv("_BNPM_PROFILE")
	if profileJSON == "" {
		fatal("_BNPM_PROFILE not set")
	}
	os.Unsetenv("_BNPM_CHILD")
	os.Unsetenv("_BNPM_PROFILE")

	var cp childProfile
	if err := json.Unmarshal([]byte(profileJSON), &cp); err != nil {
		fatal("parsing profile: %v", err)
	}

	// Set hostname inside UTS namespace
	unix.Sethostname([]byte("bnpm"))

	// Bring up loopback interface (needed in all network modes)
	bringUpLoopback()

	// If filtered network mode, set up TAP device and send fd to parent
	if cp.Profile.Network.Mode == "filtered" {
		// fd 5 = unix socket for TAP fd passing
		sockFd := 5
		if err := childSetupNetwork(sockFd); err != nil {
			fatal("network setup: %v", err)
		}
		unix.Close(sockFd)
	}

	// Signal parent that network setup is done, wait for "ready"
	writePipe := os.NewFile(4, "sync-write")
	writePipe.Write([]byte("net-ok"))
	writePipe.Close()

	readPipe := os.NewFile(3, "sync-read")
	buf := make([]byte, 16)
	n, err := readPipe.Read(buf)
	if err != nil || string(buf[:n]) != "ready" {
		fatal("waiting for parent ready signal: %v (got %q)", err, string(buf[:n]))
	}
	readPipe.Close()

	// Set up the mount namespace
	if err := setupMounts(&cp.Profile, cp.ProjectDir, cp.HomeDir, cp.Username); err != nil {
		fatal("mount setup: %v", err)
	}

	// Change to project directory inside the sandbox
	if err := os.Chdir(cp.ProjectDir); err != nil {
		fatal("chdir to project dir: %v", err)
	}

	// Build filtered environment
	env := buildEnv(&cp.Profile)

	// Resolve target binary
	binary, err := resolveInSandbox(cp.Command)
	if err != nil {
		fatal("command not found in sandbox: %s", cp.Command)
	}

	// Apply resource limits
	if cp.Profile.Resources.MaxMemory != "" {
		memBytes, err := parseSize(cp.Profile.Resources.MaxMemory)
		if err != nil {
			fatal("invalid max_memory %q: %v", cp.Profile.Resources.MaxMemory, err)
		}
		lim := &unix.Rlimit{Cur: memBytes, Max: memBytes}
		if err := unix.Setrlimit(unix.RLIMIT_AS, lim); err != nil {
			fatal("setrlimit RLIMIT_AS: %v", err)
		}
	}

	// Replace this process with the target command
	args := append([]string{filepath.Base(cp.Command)}, cp.Args...)
	if err := unix.Exec(binary, args, env); err != nil {
		fatal("exec %s: %v", binary, err)
	}
}

// resolveInSandbox finds a binary in the sandbox's PATH.
func resolveInSandbox(command string) (string, error) {
	if filepath.IsAbs(command) {
		if pathExists(command) {
			return command, nil
		}
		return "", fmt.Errorf("not found: %s", command)
	}
	path, err := exec.LookPath(command)
	if err != nil {
		return "", err
	}
	return path, nil
}

// bringUpLoopback brings up the lo interface in the network namespace.
func bringUpLoopback() {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return
	}
	defer unix.Close(sock)

	ifreq, err := unix.NewIfreq("lo")
	if err != nil {
		return
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCGIFFLAGS, ifreq); err != nil {
		return
	}
	flags := ifreq.Uint16()
	flags |= unix.IFF_UP
	ifreq.SetUint16(flags)
	unix.IoctlIfreq(sock, unix.SIOCSIFFLAGS, ifreq)
}

// parseSize parses a human-readable size string like "512M", "4G", "1T" into bytes.
func parseSize(s string) (uint64, error) {
	if len(s) == 0 {
		return 0, fmt.Errorf("empty size")
	}
	multiplier := uint64(1)
	suffix := s[len(s)-1]
	switch suffix {
	case 'k', 'K':
		multiplier = 1024
		s = s[:len(s)-1]
	case 'm', 'M':
		multiplier = 1024 * 1024
		s = s[:len(s)-1]
	case 'g', 'G':
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	case 't', 'T':
		multiplier = 1024 * 1024 * 1024 * 1024
		s = s[:len(s)-1]
	}
	n, err := fmt.Sscanf(s, "%d", new(uint64))
	if n != 1 || err != nil {
		return 0, fmt.Errorf("invalid size: %s", s)
	}
	var val uint64
	fmt.Sscanf(s, "%d", &val)
	return val * multiplier, nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "bnpm: "+format+"\n", args...)
	os.Exit(1)
}

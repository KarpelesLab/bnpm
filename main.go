package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

var version = "dev"

func main() {
	// Detect if we're the re-exec'd child
	if os.Getenv("_BNPM_CHILD") == "1" {
		runChild()
		return
	}

	// Parent mode: parse CLI flags
	var (
		flagProfile   string
		flagNetwork   string
		flagMaxMemory string
		flagVerbose   bool
		flagDryRun    bool
		flagList      bool
		flagVersion   bool
	)

	flag.StringVar(&flagProfile, "profile", "", "force a specific profile")
	flag.StringVar(&flagNetwork, "network", "", "override network mode: none, filtered, host")
	flag.StringVar(&flagMaxMemory, "max-memory", "", "override max memory limit (e.g. 4G, 512M)")
	flag.BoolVar(&flagVerbose, "verbose", false, "print sandbox setup details")
	flag.BoolVar(&flagDryRun, "dry-run", false, "show what would be done without executing")
	flag.BoolVar(&flagList, "list-profiles", false, "list available profiles")
	flag.BoolVar(&flagVersion, "version", false, "print version")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: bnpm [options] -- <command> [args...]\n\n")
		fmt.Fprintf(os.Stderr, "Run a command inside a sandboxed environment.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  bnpm -- npm install\n")
		fmt.Fprintf(os.Stderr, "  bnpm -- npm run build\n")
		fmt.Fprintf(os.Stderr, "  bnpm -- go mod tidy\n")
		fmt.Fprintf(os.Stderr, "  bnpm --network none -- npm install\n")
	}
	flag.Parse()

	if flagVersion {
		fmt.Printf("bnpm %s\n", version)
		return
	}

	// Load config
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "bnpm: error loading config: %v\n", err)
		os.Exit(1)
	}

	if flagList {
		for _, p := range cfg.Profiles {
			fmt.Printf("%-20s network=%-10s", p.Name, p.Network.Mode)
			for _, m := range p.Matches {
				fmt.Printf("  %s %v", m.Command, m.Args)
			}
			fmt.Println()
		}
		return
	}

	// Everything after flag parsing is the command
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	command := args[0]
	cmdArgs := args[1:]

	// Match profile
	var profile *Profile
	if flagProfile != "" {
		for i := range cfg.Profiles {
			if cfg.Profiles[i].Name == flagProfile {
				profile = &cfg.Profiles[i]
				break
			}
		}
		if profile == nil {
			fmt.Fprintf(os.Stderr, "bnpm: profile %q not found\n", flagProfile)
			os.Exit(1)
		}
	} else {
		profile = matchProfile(cfg.Profiles, command, cmdArgs)
	}
	if profile == nil {
		fmt.Fprintf(os.Stderr, "bnpm: no matching profile for %q, using default deny\n", command)
		profile = &Profile{
			Name:    "default-deny",
			Network: NetworkConfig{Mode: "none"},
		}
	}

	// Network mode override
	if flagNetwork != "" {
		profile.Network.Mode = flagNetwork
	}

	// Memory limit override
	if flagMaxMemory != "" {
		profile.Resources.MaxMemory = flagMaxMemory
	}

	// Get project directory
	projectDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "bnpm: cannot get working directory: %v\n", err)
		os.Exit(1)
	}

	if flagVerbose || flagDryRun {
		fmt.Fprintf(os.Stderr, "bnpm: profile=%s network=%s command=%s args=%v\n",
			profile.Name, profile.Network.Mode, command, cmdArgs)
		fmt.Fprintf(os.Stderr, "bnpm: project=%s\n", projectDir)
		if len(profile.Filesystem.Binds) > 0 {
			fmt.Fprintf(os.Stderr, "bnpm: bind mounts:\n")
			for _, b := range profile.Filesystem.Binds {
				fmt.Fprintf(os.Stderr, "  %s -> %s (%s)\n", expandPath(b.Source), expandPath(b.Target), b.Mode)
			}
		}
		if profile.Resources.MaxMemory != "" {
			fmt.Fprintf(os.Stderr, "bnpm: max memory: %s\n", profile.Resources.MaxMemory)
		}
		if profile.Network.Mode == "filtered" {
			fmt.Fprintf(os.Stderr, "bnpm: allowed domains: %v\n", profile.Network.AllowedDomains)
		}
		if flagDryRun {
			return
		}
	}

	fmt.Fprintf(os.Stderr, "bnpm: running %q with profile %q (network=%s)\n",
		command, profile.Name, profile.Network.Mode)

	os.Exit(runParent(profile, projectDir, command, cmdArgs, flagVerbose))
}

// runParent launches the sandboxed child process and manages the namespace lifecycle.
func runParent(profile *Profile, projectDir, command string, args []string, verbose bool) int {
	// Serialize profile data for the child
	homeDir, _ := os.UserHomeDir()
	username := os.Getenv("USER")
	if username == "" {
		username = "user"
	}
	cp := childProfile{
		Profile:    *profile,
		ProjectDir: projectDir,
		Command:    command,
		Args:       args,
		HomeDir:    homeDir,
		Username:   username,
	}
	profileJSON, err := json.Marshal(cp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bnpm: marshal profile: %v\n", err)
		return 1
	}

	// Create sync pipes: parent→child and child→parent
	parentToChildR, parentToChildW, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "bnpm: creating pipe: %v\n", err)
		return 1
	}
	childToParentR, childToParentW, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "bnpm: creating pipe: %v\n", err)
		return 1
	}

	// Create Unix socketpair for TAP fd passing (filtered network mode)
	var parentSock, childSock *os.File
	if profile.Network.Mode == "filtered" {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bnpm: socketpair: %v\n", err)
			return 1
		}
		parentSock = os.NewFile(uintptr(fds[0]), "parent-sock")
		childSock = os.NewFile(uintptr(fds[1]), "child-sock")
	}

	// Determine clone flags
	cloneFlags := uintptr(
		unix.CLONE_NEWUSER |
			unix.CLONE_NEWNS |
			unix.CLONE_NEWPID |
			unix.CLONE_NEWNET |
			unix.CLONE_NEWUTS,
	)

	// If network mode is "host", skip network namespace
	if profile.Network.Mode == "host" {
		cloneFlags &^= unix.CLONE_NEWNET
	}

	// Build child environment
	childEnv := os.Environ()
	childEnv = append(childEnv,
		"_BNPM_CHILD=1",
		"_BNPM_PROFILE="+string(profileJSON),
	)

	// Set up the child process via /proc/self/exe
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "bnpm: resolving self: %v\n", err)
		return 1
	}

	uid := os.Getuid()
	gid := os.Getgid()

	attr := &syscall.SysProcAttr{
		Cloneflags: cloneFlags,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: gid, Size: 1},
		},
		Pdeathsig: syscall.SIGKILL,
	}

	// ExtraFiles: fd3=syncRead, fd4=syncWrite, fd5=tapSocket (optional)
	extraFiles := []*os.File{parentToChildR, childToParentW}
	if childSock != nil {
		extraFiles = append(extraFiles, childSock)
	}

	proc, err := os.StartProcess(exe, os.Args, &os.ProcAttr{
		Env:   childEnv,
		Files: append([]*os.File{os.Stdin, os.Stdout, os.Stderr}, extraFiles...),
		Sys:   attr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "bnpm: starting sandbox: %v\n", err)
		return 1
	}

	// Close the child's end of everything in the parent
	parentToChildR.Close()
	childToParentW.Close()
	if childSock != nil {
		childSock.Close()
	}

	// Wait for child to signal network setup done
	buf := make([]byte, 16)
	n, _ := childToParentR.Read(buf)
	if verbose && n > 0 {
		fmt.Fprintf(os.Stderr, "bnpm: child signal: %s\n", string(buf[:n]))
	}

	// Set up network proxy if needed (receive TAP fd from child)
	var proxyCleanup func()
	if profile.Network.Mode == "filtered" && parentSock != nil {
		cleanup, err := setupNetworkProxy(parentSock, profile, verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bnpm: network proxy failed: %v\n", err)
			fmt.Fprintf(os.Stderr, "bnpm: falling back to no network\n")
		} else {
			proxyCleanup = cleanup
		}
		parentSock.Close()
	}

	// Signal child to proceed with mount setup and exec
	parentToChildW.Write([]byte("ready"))
	parentToChildW.Close()
	childToParentR.Close()

	// Forward signals to child
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			proc.Signal(sig)
		}
	}()

	// Wait for child to exit
	state, err := proc.Wait()
	signal.Stop(sigCh)

	if proxyCleanup != nil {
		proxyCleanup()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "bnpm: waiting for child: %v\n", err)
		return 1
	}

	return state.ExitCode()
}

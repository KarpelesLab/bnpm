package main

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed profiles/*.toml
var embeddedProfiles embed.FS

// loadConfig loads configuration from the user config file and embedded defaults.
// User profiles take priority (matched first).
func loadConfig() (*Config, error) {
	cfg := &Config{
		Settings: Settings{
			DefaultNetwork: "none",
		},
	}

	// Load user config if it exists
	userCfg := userConfigPath()
	if userCfg != "" {
		if _, err := os.Stat(userCfg); err == nil {
			var userConfig Config
			if _, err := toml.DecodeFile(userCfg, &userConfig); err != nil {
				return nil, fmt.Errorf("parsing %s: %w", userCfg, err)
			}
			cfg.Settings = userConfig.Settings
			cfg.Profiles = append(cfg.Profiles, userConfig.Profiles...)
		}
	}

	// Load embedded default profiles
	entries, err := embeddedProfiles.ReadDir("profiles")
	if err != nil {
		return nil, fmt.Errorf("reading embedded profiles: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		data, err := embeddedProfiles.ReadFile("profiles/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("reading embedded profile %s: %w", entry.Name(), err)
		}
		var embedded Config
		if err := toml.Unmarshal(data, &embedded); err != nil {
			return nil, fmt.Errorf("parsing embedded profile %s: %w", entry.Name(), err)
		}
		cfg.Profiles = append(cfg.Profiles, embedded.Profiles...)
	}

	return cfg, nil
}

// matchProfile finds the first profile matching the given command and args.
func matchProfile(profiles []Profile, command string, args []string) *Profile {
	cmdBase := filepath.Base(command)
	for i := range profiles {
		p := &profiles[i]
		for _, m := range p.Matches {
			if m.Command != "*" && m.Command != cmdBase {
				continue
			}
			if len(m.Args) == 0 {
				return p
			}
			// Check if any arg regex matches any actual arg
			for _, pattern := range m.Args {
				re, err := regexp.Compile(pattern)
				if err != nil {
					continue
				}
				// "^$" matches empty args list
				if pattern == "^$" && len(args) == 0 {
					return p
				}
				for _, arg := range args {
					if re.MatchString(arg) {
						return p
					}
				}
			}
		}
	}
	return nil
}

// expandPath expands ~ to the user's home directory.
func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return p
		}
		return filepath.Join(home, p[2:])
	}
	return p
}

func userConfigPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "bnpm", "config.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "bnpm", "config.toml")
}

// defaultEnvPass is the default set of environment variables passed into the sandbox.
var defaultEnvPass = []string{
	"HOME", "USER", "LOGNAME", "PATH", "TERM", "LANG", "LC_ALL",
	"TZ", "NODE_ENV", "CI",
}

// buildEnv constructs the environment for the sandboxed process.
func buildEnv(profile *Profile) []string {
	passSet := make(map[string]bool)
	pass := defaultEnvPass
	if len(profile.Env.Pass) > 0 {
		pass = profile.Env.Pass
	}
	for _, k := range pass {
		passSet[k] = true
	}

	var env []string
	for _, e := range os.Environ() {
		k, _, ok := strings.Cut(e, "=")
		if ok && passSet[k] {
			env = append(env, e)
		}
	}

	// Apply explicit settings
	for k, v := range profile.Env.Set {
		env = append(env, k+"="+v)
	}

	return env
}

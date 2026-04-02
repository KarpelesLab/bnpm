package main

// Config is the top-level configuration.
type Config struct {
	Settings Settings  `toml:"settings"`
	Profiles []Profile `toml:"profile"`
}

// Settings contains global bnpm settings.
type Settings struct {
	DefaultNetwork string `toml:"default_network"` // "none" or "filtered"
	CacheDir       string `toml:"cache_dir"`
}

// Profile defines a sandbox profile for a specific command pattern.
type Profile struct {
	Name       string           `toml:"name"`
	Matches    []MatchRule      `toml:"match"`
	Network    NetworkConfig    `toml:"network"`
	Filesystem FilesystemConfig `toml:"filesystem"`
	Env        EnvConfig        `toml:"env"`
}

// MatchRule defines how to match a command invocation to a profile.
type MatchRule struct {
	Command string   `toml:"command"` // base binary name, or "*" for any
	Args    []string `toml:"args"`    // regex patterns matched against args
}

// NetworkConfig defines network sandbox rules.
type NetworkConfig struct {
	Mode           string   `toml:"mode"` // "none", "filtered", "host"
	AllowedDomains []string `toml:"allowed_domains"`
	AllowedIPs     []string `toml:"allowed_ips"`
	AllowedPorts   []int    `toml:"allowed_ports"`
}

// FilesystemConfig defines additional filesystem mounts.
type FilesystemConfig struct {
	Binds []BindMount `toml:"bind"`
}

// BindMount defines a bind mount into the sandbox.
type BindMount struct {
	Source   string `toml:"source"`
	Target   string `toml:"target"`
	Mode     string `toml:"mode"`     // "ro" or "rw"
	Create   bool   `toml:"create"`   // create source if missing
	Optional bool   `toml:"optional"` // skip if source doesn't exist
}

// EnvConfig controls environment variable filtering.
type EnvConfig struct {
	Pass []string          `toml:"pass"` // env vars to pass through
	Set  map[string]string `toml:"set"`  // env vars to set explicitly
}

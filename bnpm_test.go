package main

import (
	"testing"
)

func TestMatchProfile(t *testing.T) {
	profiles := []Profile{
		{
			Name: "npm-install",
			Matches: []MatchRule{
				{Command: "npm", Args: []string{"^install$", "^i$", "^ci$"}},
			},
		},
		{
			Name: "npm-scripts",
			Matches: []MatchRule{
				{Command: "npm", Args: []string{"^run$", "^test$", "^build$"}},
				{Command: "npx"},
			},
		},
		{
			Name: "go-build",
			Matches: []MatchRule{
				{Command: "go", Args: []string{"^build$", "^test$"}},
			},
		},
	}

	tests := []struct {
		command string
		args    []string
		want    string
	}{
		{"npm", []string{"install"}, "npm-install"},
		{"npm", []string{"i"}, "npm-install"},
		{"npm", []string{"ci"}, "npm-install"},
		{"npm", []string{"run", "build"}, "npm-scripts"},
		{"npm", []string{"test"}, "npm-scripts"},
		{"npx", []string{"something"}, "npm-scripts"},
		{"go", []string{"build", "./..."}, "go-build"},
		{"go", []string{"test", "-v"}, "go-build"},
		{"unknown", []string{}, ""},
		{"npm", []string{"publish"}, ""},
	}

	for _, tt := range tests {
		got := matchProfile(profiles, tt.command, tt.args)
		name := ""
		if got != nil {
			name = got.Name
		}
		if name != tt.want {
			t.Errorf("matchProfile(%q, %v) = %q, want %q", tt.command, tt.args, name, tt.want)
		}
	}
}

func TestIsDomainAllowed(t *testing.T) {
	al := &allowList{
		domains: []string{
			"registry.npmjs.org",
			"*.github.com",
			"exact.example.com",
		},
	}

	tests := []struct {
		domain string
		want   bool
	}{
		{"registry.npmjs.org", true},
		{"registry.npmjs.org.", true}, // trailing dot
		{"foo.github.com", true},
		{"bar.baz.github.com", true},
		{"github.com", true}, // *.github.com also matches base
		{"exact.example.com", true},
		{"other.example.com", false},
		{"evil.com", false},
		{"npmjs.org", false}, // no wildcard for npmjs.org
	}

	for _, tt := range tests {
		got := al.isDomainAllowed(tt.domain)
		if got != tt.want {
			t.Errorf("isDomainAllowed(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestExpandPath(t *testing.T) {
	got := expandPath("/usr/bin")
	if got != "/usr/bin" {
		t.Errorf("expandPath(/usr/bin) = %q", got)
	}

	got = expandPath("~/test")
	if got == "~/test" {
		t.Error("expandPath(~/test) was not expanded")
	}
}

func TestBuildEnv(t *testing.T) {
	profile := &Profile{
		Env: EnvConfig{
			Pass: []string{"HOME", "PATH"},
			Set:  map[string]string{"FOO": "bar"},
		},
	}

	env := buildEnv(profile)

	foundFoo := false
	for _, e := range env {
		if e == "FOO=bar" {
			foundFoo = true
		}
	}
	if !foundFoo {
		t.Error("buildEnv did not include FOO=bar from Set")
	}
}

func TestLoadConfig(t *testing.T) {
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error: %v", err)
	}
	if len(cfg.Profiles) == 0 {
		t.Fatal("loadConfig() returned no profiles")
	}

	// Check that we have the expected built-in profiles
	names := make(map[string]bool)
	for _, p := range cfg.Profiles {
		names[p.Name] = true
	}
	for _, want := range []string{"npm-install", "npm-scripts", "go-mod", "go-build"} {
		if !names[want] {
			t.Errorf("missing built-in profile %q", want)
		}
	}
}

func TestAllowListIsAllowed(t *testing.T) {
	profile := &Profile{
		Network: NetworkConfig{
			AllowedDomains: []string{"example.com"},
			AllowedPorts:   []int{80, 443},
		},
	}
	al := newAllowList(profile)

	// Port filtering
	if al.isPortAllowed(22) {
		t.Error("port 22 should not be allowed")
	}
	if !al.isPortAllowed(443) {
		t.Error("port 443 should be allowed")
	}
}

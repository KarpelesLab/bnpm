# bnpm - Bubble NPM

A CLI tool that sandboxes package manager commands inside Linux namespaces. It restricts filesystem access to only the project directory and required system paths, and restricts network access to only allowed registries — or no network at all for build commands.

Designed to mitigate build-time supply chain attacks by preventing malicious install scripts from exfiltrating data or accessing files outside the project.

## Features

- **Filesystem isolation** — Mount namespace with `pivot_root`. Only the project directory (read-write), system directories (read-only), and profile-specified cache paths are visible.
- **Network isolation** — Empty network namespace with only loopback. Build/test commands get zero network access.
- **Filtered network** — Userspace TAP proxy with DNS and IP filtering. Install commands can only reach allowed registries (e.g. `registry.npmjs.org`).
- **PID isolation** — Sandboxed processes cannot see host processes.
- **Profile matching** — TOML profiles auto-match command and arguments. `npm install` gets filtered network; `npm run build` gets none.
- **No root required** — Uses unprivileged user namespaces.

## Installation

```bash
go install github.com/KarpelesLab/bnpm@latest
```

Or build from source:

```bash
git clone https://github.com/KarpelesLab/bnpm.git
cd bnpm
go build .
```

## Usage

```
bnpm [options] -- <command> [args...]
```

### Examples

```bash
# Install packages (filtered network — only npmjs.org reachable)
bnpm -- npm install

# Run build (no network at all)
bnpm -- npm run build

# Go module download (filtered — only proxy.golang.org, github.com, etc.)
bnpm -- go mod tidy

# Go build (no network)
bnpm -- go build ./...

# Force no network for any command
bnpm --network none -- npm install

# See what profile would be matched
bnpm --dry-run -- npm install

# List all available profiles
bnpm --list-profiles
```

### Options

| Flag | Description |
|------|-------------|
| `--profile <name>` | Force a specific profile instead of auto-matching |
| `--network <mode>` | Override network mode: `none`, `filtered`, `host` |
| `--verbose` | Print sandbox setup details and network activity |
| `--dry-run` | Show matched profile without executing |
| `--list-profiles` | List available profiles and their match rules |
| `--version` | Print version |

## How it works

bnpm re-executes itself inside new Linux namespaces (user, mount, PID, network, UTS) and constructs a minimal rootfs:

```
/usr, /lib, /bin, /sbin  → bind mount (read-only)
/etc                     → minimal generated (resolv.conf, passwd, hosts, SSL certs)
/dev                     → bind-mounted device nodes (null, zero, urandom)
/proc                    → procfs
/tmp                     → fresh tmpfs
<project directory>      → bind mount (read-write)
~/.npm, ~/go/pkg/mod     → bind mount per profile (read-write or read-only)
```

For filtered network mode, the child creates a TAP device in its network namespace and passes the file descriptor to the parent via `SCM_RIGHTS`. The parent runs a [userspace TCP/IP stack](https://github.com/KarpelesLab/slirp) that:

1. Intercepts **DNS queries** — only resolves allowed domains, returns NXDOMAIN for everything else
2. Filters **TCP connections** — checks destination IP against the allow list (built from DNS resolutions), sends RST for blocked connections
3. Proxies **allowed traffic** — creates real connections on the host network and forwards data bidirectionally

This dual DNS + IP filtering means that even bypassing DNS with a raw IP address is blocked.

## Built-in profiles

| Profile | Commands | Network |
|---------|----------|---------|
| `npm-install` | `npm install/i/ci/add/update` | Filtered (npmjs.org, github.com) |
| `npm-scripts` | `npm run/test/build`, `npx` | None |
| `yarn-install` | `yarn install/add` | Filtered (yarnpkg.com, npmjs.org) |
| `yarn-scripts` | `yarn run/test/build` | None |
| `pnpm-install` | `pnpm install/i/add/update` | Filtered (npmjs.org) |
| `pnpm-scripts` | `pnpm run/test/build/exec` | None |
| `go-mod` | `go mod/get` | Filtered (golang.org, github.com) |
| `go-build` | `go build/test/vet/run` | None |

Unmatched commands get a default-deny profile with no network access.

## Custom profiles

Create `~/.config/bnpm/config.toml`:

```toml
[[profile]]
name = "my-app-install"

[[profile.match]]
command = "npm"
args = ["^install$"]

[profile.network]
mode = "filtered"
allowed_domains = ["registry.npmjs.org", "my-private-registry.com"]
allowed_ports = [443]

[[profile.filesystem.bind]]
source = "~/.npm"
target = "~/.npm"
mode = "rw"
create = true

[profile.env]
pass = ["HOME", "USER", "PATH", "TERM", "NPM_TOKEN"]
```

User profiles are matched before built-in profiles.

## Requirements

- Linux with unprivileged user namespace support (kernel 3.8+, enabled by default on most distributions)
- `/dev/net/tun` available for filtered network mode

If user namespaces are disabled, you may need:

```bash
sudo sysctl kernel.unprivileged_userns_clone=1
```

## License

See [LICENSE](LICENSE) file.

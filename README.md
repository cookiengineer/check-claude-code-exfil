# check-claude-code-exfil

A read-only indicator-of-compromise scanner for the Claude Code for VS Code extension compromise documented in [claude-code-vx-compromise.html](references/claude-code-vx-compromise.html).

It runs on macOS, Linux, and Windows and is built with `CGO_ENABLED=0`, producing standalone binaries with no third-party Go dependencies.

The scanner checks host artifacts, SSH keys, persistence, running processes, and live TCP connections. It does not remediate, delete files, or contact the attacker infrastructure.

## Quick Start

```bash
make build;

# Linux
sudo ./build/check-claude-code-exfil_linux_amd64;

# macOS (Apple Silicon)
sudo ./build/check-claude-code-exfil_darwin_arm64;

# Windows (from an elevated terminal)
build\check-claude-code-exfil_windows_amd64.exe;
```

Running as root/administrator is recommended because it allows the scanner to inspect all user homes, processes, and network sockets.
Without elevated privileges, the scanner reports anything it could not inspect as an incomplete scan.

## Indicators Checked

### Extension Compromise

| Indicator | Location | Verification |
|---|---|---|
| Vulnerable extension version | `~/.<ide>/extensions/` | Flags installed `anthropic.claude-code` version `2.1.313`, including platform-specific directory names such as `anthropic.claude-code-2.1.313-win32-x64`. Also validates `package.json` metadata. |
| Backdoored `extension.js` | IDE extension directories | Computes the SHA-256 of `extension.js` files and compares against the documented bundle hash. |

Known bundle SHA-256:

```text
ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15
```

The scanner checks the known VS Code, Cursor, VS Code Server, Cursor Server, Windsurf, VSCodium, Positron, Trae, and Kiro extension roots. It also discovers additional `~/.<ide>/extensions` directories under each scanned home.

### SSH Backdoor Keys

| Indicator | Location | Verification |
|---|---|---|
| Victim-login public key | `~/.ssh/authorized_keys` | Parses the SSH public-key blob, computes the OpenSSH-style SHA-256 fingerprint, and compares it with the documented fingerprint. |
| Victim key comment | `~/.ssh/authorized_keys` | Detects the `svc-telemetry` comment. This is reported separately from the fingerprint match because comments can be spoofed. |
| Tunnel private key | `.stk_*`, `.smtk`, `smtk`, `.smt`, `smt.cmd` | Parses unencrypted OpenSSH private keys, extracts the public-key blob, and compares its SHA-256 fingerprint with the documented tunnel-key fingerprint. |
| Tunnel key comment | Key and persistence files | Detects `svc-telemetry-tun` in file contents. |
| Attacker tunnel server | Key and persistence files | Detects references to `134.209.82.225`. |

Documented key fingerprints:

```text
Victim-login: SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk
Tunnel key:  SHA256:KOAU57+ZG6u3MG4WwzPzPX2O5YEe9qdOC1Bl+6MVyDQ
```

SSH fingerprints are calculated the same way OpenSSH does: SHA-256 over the SSH wire-format public-key blob, base64-encoded without padding, prefixed with `SHA256:`.

### Host Artifacts

| Artifact | Platform | Verification |
|---|---|---|
| `~/.config/.smt` | macOS, Linux | Hidden persistence script used to recreate the tunnel key and restart the tunnel. |
| `~/.config/.smtk` | macOS, Linux | Recreated tunnel private key. |
| `~/.config/smt.cmd` | Windows | Windows persistence script. |
| `~/.config/smtk` | Windows | Windows tunnel private key. |
| `<TMP>/.stk_<10 hex>` | All | Initial tunnel private key in the OS temporary directory. The scanner requires the documented `.stk_` prefix plus exactly ten hexadecimal characters. |
| `$TMPDIR/.stk_*` | macOS | Checks the current user's temp directory. When running as root, also scans per-user `/var/folders/*/*/T` directories. |
| `%TEMP%\.stk_*` | Windows | Checks the current user's temp directory and per-profile `AppData\Local\Temp` directories for all scanned profiles. |
| `/tmp`, `/var/tmp`, `/private/tmp` | Linux, macOS | Additional common temporary directories. |

For `.smt`, `.smtk`, `smtk`, and `smt.cmd`, the scanner checks both existence and contents. Content checks look for the attacker public-key fingerprint, tunnel-key fingerprint, key comments, attacker IP, and related file references.

### Persistence

| Mechanism | Platform | Verification |
|---|---|---|
| LaunchAgent | macOS | Detects `~/Library/LaunchAgents/com.apple.sysmond.plist`, scans all user LaunchAgent plists for the `com.apple.sysmond` label or hidden `.smt` references, and checks `launchctl list` for the loaded label. |
| User crontab | Linux, macOS | Reads user crontabs from the platform spool paths and falls back to `crontab -l` for the current user. Flags lines referencing `.config/.smt`, `.smtk`, `svc-telemetry`, `134.209.82.225`, or other documented artifacts. |
| Scheduled task `SysMon` | Windows | Queries `schtasks /Query /TN SysMon /XML`. Also enumerates scheduled tasks in CSV form and flags renamed tasks whose actions reference malware artifacts. |
| Startup folder script | Windows | Detects `sysmon.cmd` in the user Startup folder and in the all-users Startup folder. Also scans Startup-folder file contents for documented artifacts. |

### Live Process Activity

The scanner inspects running process command lines and flags processes referencing:

- `134.209.82.225`
- `.stk_`
- `.config/.smt` or `.config\.smt`
- `.smtk` or `smtk`
- `smt.cmd` or `sysmon.cmd`
- `svc-telemetry` or `svc-telemetry-tun`
- The reverse-forward pattern `*:0:localhost:22`

This catches detached `/bin/sh` retry loops, `ssh`/`autossh` tunnels using stolen identities, and Windows persistence scripts.

Implementation by platform:

- Linux: reads `/proc/<pid>/cmdline` and `/proc/<pid>/status`.
- macOS: uses the built-in `ps` command.
- Windows: uses PowerShell `Get-CimInstance Win32_Process`, with `wmic` and `tasklist` fallbacks.

### Live Network Activity

The scanner flags TCP connections where the remote endpoint is:

- `134.209.82.225` on any port, primarily ports `22` and `8099`
- A loopback address on port `8099`, corresponding to the local beacon destination `127.0.0.1:8099`

The loopback-port finding is reported as a warning because another local service could legitimately use port `8099`.

Implementation by platform:

- Linux: reads `/proc/net/tcp` and `/proc/net/tcp6`, then maps socket inodes to processes through `/proc/<pid>/fd`.
- macOS: uses built-in `lsof` with a `netstat` fallback.
- Windows: uses `netstat -ano`.

### Deliberately Not Flagged as Standalone IOCs

The malware queries `ifconfig.me` and `api.ipify.org` to discover the public IP address. Both are legitimate services, so using them is not treated as evidence of compromise by itself.

## Usage

```text
check-claude-code-exfil [flags]
```

| Flag | Description |
|---|---|
| `--home <path>` | Scan a specific home directory or Windows profile. Repeatable. |
| `--all-users` | Scan every local user home/profile. On Unix, running as root enables this automatically. |
| `--json` | Write a JSON report instead of human-readable text. |
| `--verbose` | Show warnings and additional scan details. |
| `--no-process` | Skip live process inspection. |
| `--no-network` | Skip live network inspection. |
| `--version` | Print the version and exit. |

### Scan Scope

- Default: the current user's home directory.
- Linux/macOS when run as root: all local user homes are scanned automatically.
- Windows: the current user profile is scanned by default; use `--all-users` to enumerate `C:\Users\*`.
- `--home` can be used to inspect a mounted forensic image or a non-standard profile location.

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | No indicators found. |
| `1` | One or more indicators were found. |
| `2` | No indicators found, but part of the scan was incomplete, or the scan failed. |

Permission-denied files, unavailable live-inspection commands, and other conditions that prevent a complete scan are reported as warnings. The tool never treats an incomplete check as proof that the system is clean.

## Building

```bash
make
```

The default target builds all supported targets into `./build/`:

```text
build/check-claude-code-exfil_linux_amd64
build/check-claude-code-exfil_linux_arm64
build/check-claude-code-exfil_darwin_amd64
build/check-claude-code-exfil_darwin_arm64
build/check-claude-code-exfil_windows_amd64.exe
build/check-claude-code-exfil_windows_arm64.exe
```

Available Make targets:

| Target | Description |
|---|---|
| `make` / `make build` | Build all platform binaries. |
| `make test` | Run the Go test suite. |
| `make vet` | Run `go vet`. |
| `make fmt` | Format all Go source files. |
| `make check` | Run `vet` and tests. |
| `make clean` | Remove the `build/` directory. |

To build one target directly:

```bash
cd source
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ../build/check-claude-code-exfil_linux_amd64 ./cmds/check-claude-code-exfil
```

## Safety and Limitations

- Detection only. The scanner does not remove keys, files, cron entries, LaunchAgents, scheduled tasks, or processes.
- The scanner makes no outbound network connections. It only inspects local state and invokes local OS utilities.
- SSH private-key contents are never printed. Findings include paths, fingerprints, comments, and matched IOC tokens.
- Live process and network inspection is limited by privileges. Run with elevation for complete results.
- Windows live checks depend on built-in PowerShell, `schtasks`, and `netstat`. If these are blocked or unavailable, the affected check is reported as incomplete.
- Custom extension installation paths outside `~/.<ide>/extensions` are not discovered automatically. Use `--home` to scan a different home/profile root.
- A matching file name or comment is suspicious but should be verified against the documented fingerprint or hash where possible.

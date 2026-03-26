# sprobe

Zero-trust Python package scanner. Detects malicious behavior before it reaches your machine.

**sprobe never installs anything.** It downloads, analyzes, reports, and cleans up. You decide what to install.

**Zero runtime dependencies.** sprobe uses only Python 3.11+ stdlib. The only thing it trusts is Python itself.

![sprobe cover](https://raw.githubusercontent.com/pyautoml/sprobe/main/media/sprobe-library-cover.png)

## The problem

Supply chain attacks on PyPI are getting worse. The LiteLLM incident showed that even popular packages can be compromised. A single `pip install` can silently steal your API keys, SSH keys, and credentials.

Tools like pip-audit and Safety only catch **known CVEs**. They miss **new** malicious packages and **compromised updates** entirely.

sprobe catches what they miss: **runtime behavior**, **code patterns**, and **supply chain signals**, before you install.

## Who watches the watchmen?

Libraries like `httpx`, `requests`, `typer`, `rich`, and `pyyaml` are themselves potential attack vectors. A security tool that depends on third-party packages contradicts its own premise.

sprobe uses **zero external dependencies**. Everything is built on Python's stdlib:
- `urllib.request` instead of `httpx`/`requests`
- `argparse` instead of `typer`
- `tomllib` instead of `pyyaml`
- ANSI escape codes instead of `rich`
- `logging` instead of `loguru`

Python's stdlib could theoretically be compromised too (trojanized interpreter, modified stdlib modules). But at that point the entire machine is already owned. The language runtime is the most reasonable trust boundary. Verifying Python itself is the OS's job (package manager signatures, checksums).

## What it does

sprobe runs three analysis layers on every package:

| Layer | What it catches | How |
|---|---|---|
| **Static analysis** | Suspicious code patterns in source | Regex + AST scanning against extensible TOML patterns |
| **Metadata analysis** | Supply chain risk signals | Package age, typosquatting, missing author, no project URLs |
| **Sandbox execution** | Runtime malicious behavior | bubblewrap isolation + strace + honeypot credential files |

![sprobe high-level flow](https://raw.githubusercontent.com/pyautoml/sprobe/main/media/1_sprobe-high-level-flow-pyautoml.png)

## Quick start

```bash
pip install sprobe

# Check a package before installing it
sprobe check requests flask numpy

# Scan a local package directory
sprobe scan /path/to/unpacked/package
```

Or run from source:

```bash
git clone https://github.com/pyautoml/sprobe.git
cd sprobe

python3 -m sprobe check requests flask numpy

# Run threat playbooks to verify detection
python3 -m sprobe test-playbooks
```

### System requirements

- Python 3.11+
- Linux (bubblewrap and strace for sandbox layer)

```bash
# Install sandbox dependencies (Debian/Ubuntu)
sudo apt install bubblewrap strace
```

Static analysis and metadata analysis work without bwrap/strace. The sandbox layer is automatically skipped if they are not installed.

## Examples

### Safe package

```bash
$ sprobe check requests
```

```
============================================================
  sprobe scan | requests==2.33.0  SAFE
============================================================
  No suspicious behaviors detected.
------------------------------------------------------------
  Risk Score: 0/100
  No suspicious behavior detected
============================================================
```

### Malicious package (credential theft + exfiltration)

```bash
$ sprobe scan ./threat_playbooks/steals_ssh_key --name steals_ssh_key
```

```
============================================================
  sprobe scan | steals_ssh_key==unknown  BLOCKED
============================================================

  [CRITICAL] file_access
    Package attempts to read SSH private keys
    steals_ssh_key/__init__.py:28
    ssh_key_path = os.path.expanduser("~/.ssh/id_rsa")

  [CRITICAL] network
    Package makes outbound HTTP POST requests, common for data exfiltration
    steals_ssh_key/__init__.py:39
    urllib.request.urlopen(request)

  [CRITICAL] credential_theft
    Package accessed honeypot file at runtime: /home/user/.ssh/id_rsa
    sandbox
    openat: /home/user/.ssh/id_rsa

------------------------------------------------------------
  Risk Score: 100/100
  BLOCKED: 3 suspicious behaviors detected (3 critical). Do not install.
  Do not install this package.
============================================================
```

Three layers caught it: static analysis found the SSH key read and HTTP POST, the sandbox confirmed the file was actually accessed at runtime.

![sprobe risk example](https://raw.githubusercontent.com/pyautoml/sprobe/main/media/2_risk-example.png)

### CI/CD gate

```bash
sprobe check my-dependency || exit 1
```

Exit code 0 for SAFE/CAUTION, 1 for DANGER/BLOCKED.

### Batch check

```bash
$ sprobe check requests flask boto3 numpy
```

Packages are analyzed concurrently. The exit code reflects the worst verdict across all packages.

## Usage

### Check packages from PyPI

```bash
# Single package
sprobe check requests

# Multiple packages (analyzed concurrently)
sprobe check requests flask boto3 numpy

# Specific version
sprobe check flask==3.0.0

# Verbose output (shows all analysis steps)
sprobe check requests --verbose

# Large packages (default limit is 50 MB)
sprobe check unsloth --max-size 200
```

sprobe downloads each package to a temporary directory, verifies SHA256 against PyPI's published hash, runs all three analysis layers, reports the verdict, then deletes the downloaded files. Non-existent packages are skipped with a warning.

### Scan local source

```bash
sprobe scan ./my-package --name my-package --version 1.0.0
```

### Exit codes

- `0` - SAFE or CAUTION (no significant risk)
- `1` - DANGER or BLOCKED (risk detected)

This makes sprobe usable in CI/CD pipelines:

```bash
sprobe check my-dependency || exit 1
```

## How detection works

### Layer 1: Static analysis

Scans Python source files against extensible detection patterns defined as TOML files:

- **Regex patterns** - match suspicious strings (credential paths, network calls, subprocess usage)
- **AST patterns** - detect code structures regex cannot catch (`exec(base64.b64decode(...))`)
- **File scope** - patterns like `setup_py_exec` only fire on `setup.py`, preventing false positives

Patterns are grouped by category:

```
patterns/
  file_access/       # SSH keys, AWS creds, .env, git credentials
  network/           # HTTP POST, DNS exfiltration
  obfuscation/       # base64+exec, eval with dynamic args
  code_execution/    # subprocess, os.system, ctypes
  install_hooks/     # malicious setup.py
```

Each pattern carries an `expected_for` list of packages where that behavior is legitimate. When sprobe scans `paramiko`, it sees SSH key access and recognizes that as expected for an SSH library, not a threat. sprobe itself does not depend on or install any of those packages.

### Layer 2: Metadata analysis

Queries the PyPI JSON API and checks:

- **Typosquatting** - Levenshtein distance against 100+ popular packages (`requets` vs `requests`)
- **Package age** - brand new packages flagged (most attacks use fresh uploads)
- **Missing identity** - no author, no maintainer email
- **No project URLs** - no homepage, no repository link
- **Empty description** - placeholder or missing summary

### Layer 3: Sandbox execution

Runs the package import inside an isolated [bubblewrap](https://github.com/containers/bubblewrap) sandbox:

- **Network disabled** (`--unshare-net`) - package cannot exfiltrate data, but connection attempts are logged
- **PID namespace isolated** (`--unshare-pid`) - cannot see or signal host processes
- **Honeypot credentials injected** - fake SSH keys, AWS credentials, `.env`, git tokens
- **Syscall tracing via strace** - monitors `openat`, `connect`, `sendto`, `execve`

If the package touches a honeypot file, it is flagged as CRITICAL. No legitimate package reads another application's SSH keys on import.

## Adding custom patterns

Drop a `.toml` file into `~/.sprobe/patterns/` and sprobe picks it up automatically:

```toml
id = "my_company_secrets"
category = "file_access"
severity = "critical"
description = "Package attempts to read internal company credentials"
tags = ["custom", "internal"]
expected_for = ["our-internal-tool"]

[detection]
type = "regex"
target = "source"

[[detection.rules]]
pattern = 'INTERNAL_API_KEY'

[[detection.rules]]
pattern = '\.company/credentials'
```

## Threat playbooks

`sprobe` ships with test packages that simulate real attack patterns. Playbooks are available when running from a source checkout:

| Playbook | Attack type | Expected verdict |
|---|---|---|
| `steals_ssh_key` | Reads SSH keys + exfiltrates via HTTP | BLOCKED |
| `exfiltrates_env` | Steals env vars (API keys, tokens) | DANGER+ |
| `obfuscated_exec` | base64 + exec hidden payload | DANGER+ |
| `honeypot_trigger` | Reads all common credential paths | BLOCKED |
| `delayed_payload` | threading.Timer delayed subprocess | DANGER+ |
| `setup_py_backdoor` | Malicious code in setup.py | BLOCKED |
| `clean_package` | Harmless package (control group) | SAFE |

```bash
python3 -m sprobe test-playbooks
```

All 7 playbooks must pass. If any fails, sprobe's detection has regressed.

## Architecture

sprobe follows hexagonal architecture (ports & adapters):

```
sprobe/
  domain/           # Core types: PackageInfo, ScanFinding, RiskVerdict
  ports/            # Protocol definitions (interfaces)
  static_analysis/  # Regex + AST scanners
  metadata/         # PyPI metadata + typosquatting detector
  sandbox/          # bwrap runner + strace parser + honeypots
  scoring/          # Risk scoring engine
  reporting/        # Terminal output (ANSI)
  fetching/         # PyPI downloader with SHA256 verification
  patterns/         # Pattern loader (TOML) + built-in detection rules
```

Every external integration is behind a Protocol. Swap the PyPI fetcher for a private registry adapter by changing one line.

## Security posture

- **Zero runtime dependencies** - attack surface is Python stdlib only
- **SHA256 verification** - every download checked against PyPI's published hash
- **Path traversal protection** - archive unpacking rejects `../` paths
- **Network isolation** - sandbox blocks all outbound connections
- **Honeypot canaries** - unique per session, unpredictable tokens
- **No installation** - sprobe never runs `pip install`, only analyzes source
- **Size limits** - rejects downloads over 50 MB (zip bomb protection)

## Known false positives

sprobe uses static analysis, which means it flags code patterns without understanding intent. Some legitimate packages trigger findings because they use the same techniques that malware does.

Tested against 22 popular packages:

| Verdict | Packages |
|---|---|
| SAFE | requests, httpx, beautifulsoup4, boto3 |
| CAUTION | click, rich |
| DANGER | flask, django, fastapi, celery, pydantic, pytest, pandas, sqlalchemy, matplotlib, scipy, isort, typer, openai |
| BLOCKED | black, pillow, numpy |

The three BLOCKED packages have legitimate code that matches CRITICAL patterns:

- **black** - `scripts/diff_shades_gha_helper.py` references git credentials for CI automation. The parser (`blib2to3`) uses `eval()` for grammar conversion.
- **pillow** - `ImageMath.py` uses `eval()` to execute image math expressions. This is the intended API surface.
- **numpy** - `_utils_impl.py` references SSH paths in documentation utilities. Build tools (`f2py`, vendored meson) use `eval()` and `exec()` for code generation.

These are not security threats. Static analysis alone cannot distinguish `eval()` in a math library from `eval()` in a payload decoder. The sandbox layer resolves most of these, as legitimate packages do not access honeypot credentials or make network connections on import.

BLOCKED without CRITICAL findings is not possible. sprobe caps non-critical findings at DANGER (score 60). Only patterns like credential file access, obfuscated exec chains, and honeypot triggers push a package into BLOCKED.

## License

[PyAutoML Non-Commercial License v1.0](LICENSE)

Free for personal and educational use. Commercial use requires written permission.

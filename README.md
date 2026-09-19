# ReconRaptorAI

[![License: MIT](https://img.shields.io/badge/license-MIT-22C55E.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-bash-0F172A.svg)](reconraptor.sh)
[![AI](https://img.shields.io/badge/AI-Ollama%20%7C%20OpenAI%20%7C%20DeepSeek%20%7C%20Rules-22D3EE.svg)](#ai-triage-optional)
[![Website](https://img.shields.io/badge/site-GitHub%20Pages-D946EF.svg)](https://zuri09.github.io/ReconRaptor/)
[![Use](https://img.shields.io/badge/use-authorized%20testing%20only-FDE68A.svg)](#responsible-use)

**ReconRaptorAI is a one-command recon tool for bug bounty and authorized security testing.**
You give it a domain; it finds the target's assets, collects URLs, digs through JavaScript for
secrets, confirms the most promising leads, and hands you tidy reports instead of one giant pile
of raw output.

![ReconRaptorAI CLI preview](docs/assets/reconraptor-cli-hero.png)

```text
domain ─▶ subdomains ─▶ live hosts ─▶ URLs ─▶ JavaScript ─▶ validators ─▶ (AI triage) ─▶ reports
```

---

## Table of contents

- [The 60-second version](#the-60-second-version)
- [What it actually does](#what-it-actually-does)
- [Install](#install)
- [Your first scan (walkthrough)](#your-first-scan-walkthrough)
- [Reading the results](#reading-the-results)
- [AI triage (optional)](#ai-triage-optional)
- [Command reference](#command-reference)
- [Tuning & advanced options](#tuning--advanced-options)
- [How findings are confirmed](#how-findings-are-confirmed)
- [Privacy & data handling](#privacy--data-handling)
- [Responsible use](#responsible-use)
- [FAQ / troubleshooting](#faq--troubleshooting)

---

## The 60-second version

```bash
# 1. Get it
git clone https://github.com/Zuri09/ReconRaptor.git
cd ReconRaptor
chmod +x install.sh reconraptor.sh

# 2. Install the tools it needs (one time)
./install.sh

# 3. Scan a domain you are allowed to test
./reconraptor.sh -d example.com
```

When it finishes, open **`recon_example.com/START_HERE.md`** — that file tells you exactly which
report to look at first.

> ⚠️ Only scan domains you own or are **explicitly authorized** to test. See [Responsible use](#responsible-use).

---

## What it actually does

Think of it as an assembly line. Each stage feeds the next, and every stage writes its output to
its own folder so nothing gets lost.

| Stage | In plain English | Tools used |
| --- | --- | --- |
| **1. Find assets** | Discover the target's subdomains and figure out which ones are actually online. | `subfinder`, `dnsx`, `httpx` |
| **2. Collect URLs** | Pull historical URLs from web archives and crawl the live sites. | `waybackurls`, `gau`*, `katana` |
| **3. Analyze JavaScript** | Download live `.js` files and search them for leaked API keys, tokens, and risky code. | `gitleaks` + built-in regex checks |
| **4. Scan URLs** | Flag URLs that look like exposed files, secrets, admin panels, or open redirects. | built-in filters |
| **5. Run scanners** | Run curated `nuclei` templates and collect TLS certificate metadata. | `nuclei`, `tlsx` |
| **6. Confirm leads** | Actively verify the best leads (exposed files, CORS, GraphQL, buckets, takeovers) so you get real findings, not guesses. | built-in validators, `subzy` |
| **7. Triage (optional)** | Rank everything by severity and write a readable summary — locally or with an AI model. | rules / Ollama / OpenAI / DeepSeek |
| **8. Organize** | Sort everything into clean folders and generate `START_HERE.md`. | — |

*`gau` is optional — used automatically if it's installed.

---

## Install

You need **Go** and a Unix-like shell (macOS or Linux). The installer handles everything else.

```bash
./install.sh
```

This installs Go (if missing) and the full recon toolkit:

| Tool | What it's for |
| --- | --- |
| `subfinder` | Find subdomains |
| `dnsx` | Resolve DNS |
| `httpx` | Check which hosts are alive |
| `katana` | Crawl live sites |
| `nuclei` | Template-based vulnerability checks |
| `tlsx` | Read TLS/SSL certificate data |
| `subzy` | Detect subdomain takeovers |
| `waybackurls` | Fetch archived URLs |
| `gau` | Fetch more archived URLs (extra coverage) |
| `gitleaks` | Scan files for secrets |

**Installer options:**

```bash
./install.sh --skip-nuclei-templates      # don't download/update nuclei templates (offline use)
./install.sh --with-ollama                # also set up local AI (Ollama)
./install.sh --with-ollama --ollama-model llama3.1   # pick the local model
```

> **"command not found" after installing?** Go puts binaries in `$(go env GOPATH)/bin`. Add it to
> your shell profile and restart your terminal:
> ```bash
> export PATH="$PATH:$(go env GOPATH)/bin"
> ```

---

## Your first scan (walkthrough)

```bash
./reconraptor.sh -d example.com
```

You'll see progress printed section by section (subdomains → URLs → JavaScript → validators → summary).
When it's done, you get a folder named `recon_example.com/`. Start here:

```text
recon_example.com/
└── START_HERE.md   ←  open this first
```

`START_HERE.md` contains:
- a **counts table** (how many hosts, URLs, findings, etc.), and
- a **guide** telling you which folder to open for what.

From there, the file you'll care about most is:

```text
recon_example.com/reports/findings/confirmed_findings.json   ←  the high-signal stuff
```

These are leads ReconRaptor **actively verified**, so they're the best place to spend your time.

---

## Reading the results

Everything lives under `recon_<domain>/`. Here's the map:

```text
recon_example.com/
├── START_HERE.md              # read me first
├── raw/                       # discovery data (subdomains, live hosts, URLs, JS/JSON lists)
├── reports/
│   ├── findings/              # ★ confirmed / high-confidence findings
│   ├── ai/                    # AI-ranked triage + sanitized model context (if --ai used)
│   ├── urls/                  # URLs that look sensitive (files, secrets, admin, redirects)
│   ├── js/                    # secrets & risky code found in JavaScript
│   ├── pd/                    # nuclei findings + TLS metadata
│   └── candidates/            # the raw lists the validators tested
└── evidence/                  # downloaded JS (raw HTTP evidence pruned by default)
```

**Which folder do I open?**

| I want to see… | Open |
| --- | --- |
| The best, verified findings | `reports/findings/confirmed_findings.json` |
| A ranked summary of everything | `reports/ai/ai_summary.md` (needs `--ai`) |
| Exposed files / secrets in URLs | `reports/urls/` |
| Secrets leaked in JavaScript | `reports/js/genuine_leaks.json` |
| Nuclei & TLS results | `reports/pd/` |
| The full raw discovery data | `raw/` |

---

## AI triage (optional)

AI mode is **off by default**. Add `--ai` to get a ranked, readable summary of your findings.
You choose *who* does the ranking with `--ai-provider`:

| Provider | What it does | Data leaves your machine? |
| --- | --- | --- |
| `rules` | Scores findings with built-in offline logic | **No** — fully local |
| `ollama` | Uses a local model via [Ollama](https://ollama.com) | **No** — fully local |
| `openai` | Uses the OpenAI API | Yes — sanitized context is sent |
| `deepseek` | Uses the DeepSeek API (or any OpenAI-compatible endpoint) | Yes — sanitized context is sent |
| `auto` *(default with `--ai`)* | Picks OpenAI → DeepSeek → Ollama → rules, based on what's configured | Depends on what it picks |

### Examples

```bash
# Fully local, no internet, no API key:
./reconraptor.sh -d example.com --ai --ai-provider rules

# Local AI model with Ollama:
./install.sh --with-ollama
./reconraptor.sh -d example.com --ai --ai-provider ollama

# OpenAI:
OPENAI_API_KEY="sk-..." ./reconraptor.sh -d example.com --ai --ai-provider openai

# DeepSeek (any DeepSeek model via --ai-model):
DEEPSEEK_API_KEY="sk-..." ./reconraptor.sh -d example.com --ai --ai-provider deepseek --ai-model deepseek-chat
```

### Using DeepSeek (or any OpenAI-compatible API)

DeepSeek speaks the standard OpenAI `chat/completions` format, so ReconRaptor can talk to it — and
to any other compatible provider — with the same code.

1. Get an API key from [platform.deepseek.com](https://platform.deepseek.com).
2. Export it and run:
   ```bash
   export DEEPSEEK_API_KEY="sk-..."
   ./reconraptor.sh -d example.com --ai --ai-provider deepseek --ai-model deepseek-reasoner
   ```
3. To point at a **different** OpenAI-compatible endpoint, override the base URL:
   ```bash
   DEEPSEEK_API_KEY="..." DEEPSEEK_BASE_URL="https://your-provider.example/v1" \
     ./reconraptor.sh -d example.com --ai --ai-provider deepseek --ai-model your-model
   ```

### AI output files

| File | What it is |
| --- | --- |
| `reports/ai/ai_summary.md` | The human-readable triage report |
| `reports/ai/ai_findings.json` | Findings ranked by severity/confidence |
| `reports/ai/ai_context.json` | The **sanitized** data given to the model |

> **Nothing secret is sent to a cloud model.** Before building `ai_context.json`, ReconRaptor strips
> secret-like values, raw request/response bodies, downloaded JS, and long text. See
> [Privacy & data handling](#privacy--data-handling).

---

## Command reference

```text
./reconraptor.sh -d <domain> [options]
```

| Option | Description |
| --- | --- |
| `-d, --domain <domain>` | Target domain to scan **(required)** |
| `-w, --webhook <url>` | Zip the results and upload them to a Discord webhook |
| `--ai` | Enable AI triage |
| `--ai-provider <mode>` | `auto`, `openai`, `deepseek`, `ollama`, or `rules` |
| `--ai-model <model>` | Model name for OpenAI, DeepSeek, or Ollama |
| `--exclude-file <file>` | Drop subdomains matching these regex patterns (keep scans in-scope) |
| `--keep-evidence` | Keep raw validator HTTP responses under `evidence/` (off by default) |
| `-h, --help` | Show the help screen |

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `OPENAI_API_KEY` | *(unset)* | Required for `--ai-provider openai` |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible endpoint |
| `DEEPSEEK_API_KEY` | *(unset)* | Required for `--ai-provider deepseek` |
| `DEEPSEEK_MODEL` | `deepseek-chat` | DeepSeek model |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | DeepSeek/compatible endpoint |
| `OLLAMA_MODEL` | `llama3.2:3b` | Local Ollama model |
| `AI_MAX_FINDINGS` | `60` | Max findings included in AI context |

---

## Tuning & advanced options

### Scope control (stay in-scope)

Create a file of regex patterns for subdomains you must **not** touch, then pass it in. Matching
hosts are dropped before any probing happens.

```bash
cat > out-of-scope.txt <<'EOF'
^admin\.
\.internal\.example\.com$
staging
EOF

./reconraptor.sh -d example.com --exclude-file out-of-scope.txt
```

### Scan speed / aggressiveness

| Variable | Default | Effect |
| --- | --- | --- |
| `MAX_VALIDATION_TARGETS` | `300` | Max candidates each validator tests |
| `VALIDATOR_PARALLELISM` | `12` | How many validation checks run at once |
| `CURL_TIMEOUT` | `12` | Per-request timeout (seconds) |

```bash
MAX_VALIDATION_TARGETS=500 VALIDATOR_PARALLELISM=20 CURL_TIMEOUT=10 ./reconraptor.sh -d example.com
```

### Nuclei profile

ReconRaptor ships a curated Nuclei tag profile focused on recon-relevant issues and excludes noisy
or unsafe templates. Override as needed:

```bash
# Focus on known-exploited + specific tags:
NUCLEI_TEMPLATE_TAGS="exposure,misconfig,kev,vkev,cve" ./reconraptor.sh -d example.com

# Turn off the slower automatic technology-mapped scan:
NUCLEI_AUTOMATIC_SCAN=false ./reconraptor.sh -d example.com
```

| Variable | Default |
| --- | --- |
| `NUCLEI_TEMPLATE_TAGS` | `exposure, config, misconfig, default-login, unauth, takeover, graphql, cors, redirect, swagger, openapi, panel, s3, bucket, aws, azure, google, gstorage, token, secret, kev, vkev, cve` |
| `NUCLEI_EXCLUDE_TAGS` | `intrusive, dos, fuzzing, creds-stuffing, login-check` |
| `NUCLEI_CONCURRENCY` | `25` |
| `NUCLEI_RATE_LIMIT` | `100` |
| `NUCLEI_AUTOMATIC_SCAN` | `true` |

---

## How findings are confirmed

`reports/findings/confirmed_findings.json` is the payoff. Unlike raw scanner output, these leads are
**actively re-tested** before being reported:

| Finding | How it's confirmed |
| --- | --- |
| **Exposed sensitive file** | HTTP 200 on a sensitive path, plus config/credential-like content in the body |
| **Open redirect** | A controlled external URL actually appears in the `Location` header (checked via HEAD, then GET) |
| **CORS misconfiguration** | Server reflects an arbitrary origin, trusts `null`, or returns a wildcard — flagged higher when credentials are allowed |
| **GraphQL exposure** | Introspection returns a schema, or an interactive console is reachable |
| **Public cloud storage** | A bucket listing or object is publicly readable |
| **Subdomain takeover** | `subzy` marks the host vulnerable (Nuclei results kept separately too) |

Everything here is still a **lead**. Reproduce it manually before reporting.

---

## Privacy & data handling

ReconRaptor is built to avoid leaking the very secrets it finds:

- **Secrets in reports are redacted.** Extracted API keys, tokens, and passwords are stored as a
  short prefix + length + SHA-256 hash — never the full value. Sensitive query-string values in URLs
  are masked too (e.g. `?token=[redacted]`), while the URL stays usable as a locator.
- **AI context is sanitized.** `ai_context.json` (the only thing sent to a cloud model) has secret-like
  values, raw bodies, and downloaded JS stripped out first.
- **Raw HTTP evidence is discarded by default.** Validator response bodies are deleted at the end of a
  run unless you pass `--keep-evidence`.

Even so, scan output can still contain sensitive information. Store it carefully, and don't share raw
results unless a program specifically asks for them. The `-w/--webhook` upload warns you before sending.

---

## Responsible use

Use ReconRaptorAI **only** on systems you own or are explicitly authorized to test (a bug bounty
program's scope, a signed engagement, your own lab).

Scanner and AI output are **leads, not proof**. Reproduce findings manually, confirm they're in scope,
and report through the target's approved disclosure channel.

---

## FAQ / troubleshooting

**"Zero live hosts" even though the site is up.**
That was an old bug (now fixed) where hosts behind Cloudflare/WAFs or hosts that redirect were dropped.
ReconRaptor now treats `3xx`, `401`, and `403` responses as live and uses a browser User-Agent.

**A tool "is not installed" error.**
Run `./install.sh`, then make sure Go's bin directory is on your `PATH` (see [Install](#install)).

**AI triage says it failed.**
Check that the right key is set (`OPENAI_API_KEY` / `DEEPSEEK_API_KEY`) or that Ollama is running.
If a provider fails, ReconRaptor falls back to the local rules summary instead of crashing.

**It's slow on a big target.**
Lower `MAX_VALIDATION_TARGETS`, raise `VALIDATOR_PARALLELISM`, set `NUCLEI_AUTOMATIC_SCAN=false`, and
use `--exclude-file` to trim out-of-scope hosts.

**Where do results go?**
Into `recon_<domain>/`. That folder is gitignored, so scans never get committed by accident.

### Keeping tools updated

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/PentestPad/subzy@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/zricethezav/gitleaks/v8@latest
nuclei -update-templates
```

---

## License

Released under the [MIT License](LICENSE).

## Author

Created by [Zuri09](https://github.com/Zuri09).

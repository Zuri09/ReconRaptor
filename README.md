# ReconRaptor AI

[![License: MIT](https://img.shields.io/badge/license-MIT-7C3AED.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-bash-0F172A.svg)](reconraptor.sh)
[![AI](https://img.shields.io/badge/AI-Ollama%20%7C%20OpenAI-6366F1.svg)](#ai-powered-triage)
[![Website](https://img.shields.io/badge/site-GitHub%20Pages-22C55E.svg)](https://zuri09.github.io/ReconRaptor/)
[![Security](https://img.shields.io/badge/use-authorized%20testing-DC2626.svg)](#responsible-use)

ReconRaptor AI is an AI-powered reconnaissance and triage tool for bug bounty and authorized security testing. It discovers assets, collects URLs, validates high-signal exposures, scans JavaScript, runs ProjectDiscovery checks, and turns the output into ranked reports with local or cloud AI.

The goal is simple: fewer noisy files, more confirmed leads, and a faster path from recon to report-ready evidence.

```text
ReconRaptor AI
subdomains -> URLs -> JS analysis -> confirmed validators -> AI triage -> reports
```

## What it does

- Discovers subdomains with `subfinder`
- Resolves and probes hosts with `dnsx` and `httpx`
- Collects historical and crawled URLs with `waybackurls` and `katana`
- Filters URLs for sensitive files, risky paths, cloud storage, redirects, GraphQL, and token-like parameters
- Downloads live JavaScript and scans it with Gitleaks plus built-in regex checks
- Validates confirmed findings for exposed files, open redirects, CORS, GraphQL introspection, public cloud storage, and takeover signals
- Runs focused `nuclei` checks and TLS collection with `tlsx`
- Creates AI triage reports with local Ollama, OpenAI, or offline scoring rules
- Keeps raw data, reports, and evidence in separate folders
- Optionally uploads zipped results to Discord

## Quick start

```bash
git clone https://github.com/Zuri09/ReconRaptor.git
cd ReconRaptor
chmod +x install.sh reconraptor.sh
./install.sh
./reconraptor.sh -d example.com
```

Run with local AI triage:

```bash
./install.sh --with-ollama
./reconraptor.sh -d example.com --ai --ai-provider ollama
```

Run with OpenAI triage:

```bash
OPENAI_API_KEY="your_api_key" ./reconraptor.sh -d example.com --ai --ai-provider openai
```

Send results to Discord:

```bash
./reconraptor.sh -d example.com -w "https://discord.com/api/webhooks/..."
```

## Installation

The default installer checks for Go and installs the recon stack:

```bash
./install.sh
```

Installed tools:

| Tool | Purpose |
| --- | --- |
| `subfinder` | Subdomain discovery |
| `dnsx` | DNS resolution |
| `httpx` | Live host and file validation |
| `katana` | Live crawling |
| `nuclei` | Template-based vulnerability checks |
| `tlsx` | TLS metadata |
| `subzy` | Subdomain takeover checks |
| `waybackurls` | Historical URL collection |
| `gitleaks` | Secret scanning |

Optional local AI setup:

```bash
./install.sh --with-ollama
```

Use a different Ollama model:

```bash
./install.sh --with-ollama --ollama-model llama3.1
```

If a Go-installed tool is not found after restarting your terminal, add this to your shell profile:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Usage

Standard scan:

```bash
./reconraptor.sh -d example.com
```

AI-powered scan with automatic provider selection:

```bash
./reconraptor.sh -d example.com --ai
```

Private local AI triage:

```bash
./reconraptor.sh -d example.com --ai --ai-provider ollama
```

Cloud AI triage:

```bash
OPENAI_API_KEY="your_api_key" ./reconraptor.sh -d example.com --ai --ai-provider openai
```

Offline rule-based triage:

```bash
./reconraptor.sh -d example.com --ai --ai-provider rules
```

Custom model:

```bash
./reconraptor.sh -d example.com --ai --ai-provider ollama --ai-model llama3.2:3b
```

## AI-powered triage

AI triage is optional. When you pass `--ai`, ReconRaptor AI builds a sanitized context file and creates:

| File | Purpose |
| --- | --- |
| `reports/ai/ai_context.json` | Sanitized context passed to AI or local scoring |
| `reports/ai/ai_findings.json` | Ranked findings with score, severity, confidence, and next step |
| `reports/ai/ai_summary.md` | Human-readable triage report |
| `reports/ai/ai_ollama_response.json` | Raw Ollama response when using local AI |
| `reports/ai/ai_openai_response.json` | Raw OpenAI response when using OpenAI |

Provider modes:

| Provider | Behavior |
| --- | --- |
| `auto` | Uses OpenAI if `OPENAI_API_KEY` is set, then Ollama if available, then local rules |
| `ollama` | Sends sanitized context to the local Ollama API |
| `openai` | Sends sanitized context to the OpenAI Responses API |
| `rules` | Uses local scoring only and sends nothing outside the machine |

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `OPENAI_API_KEY` | unset | Required for OpenAI mode |
| `OPENAI_MODEL` | `gpt-5.6-luna` | OpenAI model for cloud triage |
| `OLLAMA_MODEL` | `llama3.2:3b` | Ollama model for local triage |
| `AI_MAX_FINDINGS` | `60` | Max findings included in AI context |

ReconRaptor AI strips secret-like query values, raw request/response content, downloaded JavaScript bodies, and long text before building `reports/ai/ai_context.json`. Treat all scan output as sensitive anyway.

## Output structure

Each scan creates a target directory:

```text
recon_example.com/
|-- START_HERE.md
|-- raw/
|   |-- subdomains.txt
|   |-- resolved_subdomains.txt
|   |-- authsubs.txt
|   |-- unauthsubs.txt
|   |-- urls.txt
|   |-- js_files.txt
|   |-- json_files.txt
|   |-- authjs_files.txt
|   `-- authjson_files.txt
|-- reports/
|   |-- findings/
|   |   |-- confirmed_findings.json
|   |   |-- confirmed_findings_summary.txt
|   |   `-- subdomain_takeover_findings.json
|   |-- ai/
|   |   |-- ai_context.json
|   |   |-- ai_findings.json
|   |   `-- ai_summary.md
|   |-- urls/
|   |   |-- url_info_disclosure.txt
|   |   |-- smart_sensitive_files.json
|   |   `-- smart_secret_urls.json
|   |-- js/
|   |   |-- generic_api_keys.json
|   |   |-- genuine_leaks.json
|   |   |-- gitleaks_report.json
|   |   `-- js_vulnerability_findings.json
|   |-- pd/
|   |   |-- nuclei_findings.jsonl
|   |   |-- nuclei_potential_url_findings.jsonl
|   |   `-- tls_findings.jsonl
|   `-- candidates/
|       |-- sensitive_file_candidates.txt
|       |-- open_redirect_candidates.txt
|       |-- cors_candidates.txt
|       |-- graphql_candidates.txt
|       `-- potential_vuln_urls.txt
`-- evidence/
    |-- downloaded_js/
    |-- downloaded_js_map.txt
    `-- validator_tmp/
```

Open `START_HERE.md` first. It contains counts, the shortest path to the important reports, and a folder guide for the scan.

| Folder | Best for |
| --- | --- |
| `reports/findings/` | Confirmed or high-confidence issues |
| `reports/ai/` | AI-ranked triage and the sanitized model context |
| `reports/urls/` | URL-based disclosure leads and sensitive file matches |
| `reports/js/` | JavaScript secrets, Gitleaks output, and client-side indicators |
| `reports/pd/` | Nuclei and TLS output |
| `reports/candidates/` | Raw candidates checked by validators |
| `raw/` | Discovery data such as subdomains, live hosts, URLs, JS, and JSON |
| `evidence/` | Downloaded JavaScript and validator evidence |

## Confirmed validators

`reports/findings/confirmed_findings.json` is the main high-signal report. These checks make live requests and only write findings with concrete evidence.

| Validator | Confirmation logic |
| --- | --- |
| Exposed sensitive files | HTTP 200 plus sensitive path or config-like content |
| Open redirects | Controlled external URL appears in the `Location` header |
| CORS | Wildcard origin or reflected arbitrary origin with credentials |
| GraphQL | Introspection response or exposed GraphQL console |
| Cloud storage | Public readable object or bucket-like listing |
| Subdomain takeover | `subzy` vulnerable result, with Nuclei output retained separately |

Tune validation speed:

```bash
MAX_VALIDATION_TARGETS=500 VALIDATOR_PARALLELISM=20 CURL_TIMEOUT=10 ./reconraptor.sh -d example.com
```

## JavaScript analysis

ReconRaptor AI downloads live JavaScript files and scans them for:

- High-confidence secret patterns
- Generic API key candidates
- Cloud and SaaS indicators
- Source maps
- DOM XSS sinks and sources
- Client-side redirect indicators
- Sensitive browser storage usage
- Internal host references
- Admin, debug, API, and GraphQL paths

Main reports:

| Report | Purpose |
| --- | --- |
| `reports/js/generic_api_keys.json` | Broad API key and token candidates |
| `reports/js/genuine_leaks.json` | Higher-confidence built-in leak matches |
| `reports/js/gitleaks_report.json` | Gitleaks JSON output |
| `reports/js/js_vulnerability_findings.json` | Client-side vulnerability indicators |
| `reports/js/js_secret_summary.txt` | Summary counts and references |

## ProjectDiscovery checks

ReconRaptor AI runs additional focused checks after URL and JavaScript analysis:

| Report | Source |
| --- | --- |
| `reports/pd/nuclei_findings.jsonl` | Nuclei scan against live hosts |
| `reports/pd/nuclei_potential_url_findings.jsonl` | Nuclei scan against high-signal URLs |
| `reports/pd/tls_findings.jsonl` | TLS metadata from `tlsx` |

Nuclei runs with raw request and response output omitted.

## Updating tools

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/PentestPad/subzy@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/zricethezav/gitleaks/v8@latest
```

Update the default local AI model:

```bash
ollama pull llama3.2:3b
```

## Responsible use

Use ReconRaptor AI only on systems you own or are explicitly authorized to test. Scanner output and AI triage are leads, not proof by themselves. Reproduce findings manually, confirm scope, and report issues through the target's approved disclosure channel.

Scan output can contain sensitive data. Store reports carefully and avoid sharing raw results unless the program asks for them.

## License

ReconRaptor AI is released under the [MIT License](LICENSE).

## Author

Created by [Zuri09](https://github.com/Zuri09).

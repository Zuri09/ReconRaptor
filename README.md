# ReconRaptor AI

ReconRaptor AI is an AI-powered reconnaissance and triage tool for bug bounty and authorized security testing. It collects subdomains, validates live hosts, gathers archived URLs, extracts JavaScript and JSON assets, confirms high-signal issues, and turns scan output into ranked AI-assisted reports.

The tool is designed to produce practical files you can review quickly after a scan: raw evidence stays organized, confirmed findings are separated, and optional local or cloud AI helps prioritize what is worth reporting.

## Features

- AI-powered finding triage with local Ollama, OpenAI, or offline rules
- Subdomain discovery with `subfinder`
- DNS resolution with `dnsx`
- Live and non-live host classification with `httpx`
- Historical URL collection with `waybackurls`
- Live URL crawling with `katana`
- Vulnerability checks with `nuclei`
- TLS metadata collection with `tlsx`
- Subdomain takeover checks with `subzy` when installed
- JavaScript and JSON URL extraction, including URLs with query strings
- URL-based information-disclosure checks
- Smart URL filtering for sensitive files and secret-looking URL patterns
- Confirmed validators for exposed files, open redirects, CORS, GraphQL, public cloud storage, and subdomain takeover
- AI-generated summaries for severity ranking, false-positive review, duplicate grouping, and report-ready wording
- JavaScript download and analysis
- Separate reports for generic API key candidates, higher-confidence leaks, Gitleaks findings, and JS vulnerability indicators
- Tuned concurrency for faster scans while keeping validation focused
- Optional Discord webhook upload for zipped results
- AI-branded CLI output with scan sections and a final summary

## Installation

Run the installer:

```bash
chmod +x install.sh
./install.sh
```

Install the normal recon tools plus local Ollama AI triage:

```bash
./install.sh --with-ollama
```

Use a different local model:

```bash
./install.sh --with-ollama --ollama-model llama3.1
```

The installer checks for Go and installs:

- `subfinder`
- `dnsx`
- `httpx`
- `katana`
- `nuclei`
- `tlsx`
- `subzy`
- `waybackurls`
- `gitleaks`

If any installed Go tool is not found after restarting your terminal, add this to your shell profile:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Usage

Run a standard recon scan:

```bash
./reconraptor.sh -d example.com
```

Run an AI-powered scan:

```bash
./reconraptor.sh -d example.com --ai
```

Use cloud AI triage with OpenAI:

```bash
OPENAI_API_KEY="your_api_key" ./reconraptor.sh -d example.com --ai --ai-provider openai
```

Use private local AI triage with Ollama:

```bash
./reconraptor.sh -d example.com --ai --ai-provider ollama
```

Send results to a Discord webhook:

```bash
./reconraptor.sh -d example.com -w "https://discord.com/api/webhooks/..."
```

When `-w` is provided, ReconRaptor AI compresses `recon_<domain>/` into `results_<domain>.zip` and uploads that zip file to the webhook.

## Output Structure

ReconRaptor AI creates a target-specific directory:

```text
recon_example.com/
├── raw/
│   ├── subdomains.txt
│   ├── resolved_subdomains.txt
│   ├── authsubs.txt
│   ├── unauthsubs.txt
│   ├── urls.txt
│   ├── js_files.txt
│   ├── json_files.txt
│   ├── authjs_files.txt
│   └── authjson_files.txt
├── reports/
│   ├── url_info_disclosure.txt
│   ├── url_regex_dictionary.txt
│   ├── smart_sensitive_files.json
│   ├── smart_secret_urls.json
│   ├── smart_url_filter_dictionary.txt
│   ├── confirmed_findings.json
│   ├── confirmed_findings.jsonl
│   ├── confirmed_findings_summary.txt
│   ├── ai_context.json
│   ├── ai_findings.json
│   ├── ai_summary.md
│   ├── subdomain_takeover_findings.json
│   ├── sensitive_file_candidates.txt
│   ├── open_redirect_candidates.txt
│   ├── cors_candidates.txt
│   ├── graphql_candidates.txt
│   ├── bucket_candidates.txt
│   ├── potential_vuln_urls.txt
│   ├── generic_api_keys.json
│   ├── genuine_leaks.json
│   ├── gitleaks_report.json
│   ├── js_vulnerability_findings.json
│   ├── nuclei_findings.jsonl
│   ├── nuclei_potential_url_findings.jsonl
│   ├── tls_findings.jsonl
│   ├── js_regex_dictionary.txt
│   └── js_secret_summary.txt
└── evidence/
    ├── downloaded_js/
    ├── downloaded_js_map.txt
    └── validator_tmp/
```

## URL Exposure Analysis

`url_info_disclosure.txt` flags possible findings directly from collected URLs, including:

- Environment and configuration files
- Backup, archive, and database dump files
- Credentials or tokens in query strings
- Private keys and certificate files
- Source maps
- Logs, debug paths, profiler paths, and server status pages
- Swagger, OpenAPI, GraphQL, and API documentation endpoints
- Admin, internal, dev, staging, and test paths
- Possible open redirect parameters
- Export, download, and document paths
- Version-control and dependency metadata

`smart_sensitive_files.json` and `smart_secret_urls.json` apply a higher-signal URL filter inspired by common bug bounty workflows. They combine sensitive file extensions, risky path names, cloud/SaaS keywords, and secret-looking query parameters so large URL lists become easier to review.

`smart_secret_urls.json` stores the matched URL fragment so query-string evidence can be reviewed directly from the report.

`potential_vuln_urls.txt` deduplicates URLs matched by the smart filter. ReconRaptor AI uses this list for a focused Nuclei pass.

## Confirmed Validators

`confirmed_findings.json` is the main high-signal report. It is built from checks that make a live request and require evidence before writing a finding.

Current validators include:

- Exposed sensitive files: confirms HTTP 200 and looks for config, credential, or sensitive-file evidence.
- Open redirects: replaces redirect-like parameters with a controlled external URL and confirms the `Location` header.
- CORS issues: checks wildcard origins and reflected arbitrary origins with credentials.
- GraphQL exposure: checks introspection and exposed interactive GraphQL consoles.
- Public cloud storage: checks S3, Google Cloud Storage, Azure Blob, Firebase, and similar URLs for readable objects or listings.
- Subdomain takeover: uses `subzy` when available and also keeps Nuclei takeover output in the normal Nuclei reports.

The validator layer uses a per-category cap and concurrent requests so large URL lists stay manageable. You can tune it per run:

```bash
MAX_VALIDATION_TARGETS=500 VALIDATOR_PARALLELISM=20 ./reconraptor.sh -d example.com
```

The default values are conservative enough for bug bounty use:

- `MAX_VALIDATION_TARGETS=300`
- `VALIDATOR_PARALLELISM=12`
- `CURL_TIMEOUT=12`

## AI-Powered Triage

AI triage is optional and disabled by default. When enabled with `--ai`, ReconRaptor AI creates:

- `reports/ai_context.json`: sanitized scan context used for AI analysis
- `reports/ai_findings.json`: locally ranked findings with severity, score, confidence, and next steps
- `reports/ai_summary.md`: a concise triage summary for review and reporting

The AI context omits raw secret-like values, raw request/response bodies, and downloaded JavaScript content. It keeps metadata such as finding type, URL, confidence, status, evidence summaries, hashes, and counts.

Provider modes:

- `--ai-provider auto`: uses OpenAI when `OPENAI_API_KEY` is set, otherwise tries Ollama, otherwise keeps the local rule-based summary.
- `--ai-provider openai`: sends the sanitized context to the OpenAI Responses API.
- `--ai-provider ollama`: sends the sanitized context to a local Ollama server.
- `--ai-provider rules`: never sends data anywhere; uses local scoring and templates only.

Useful environment variables:

- `OPENAI_API_KEY`: required for OpenAI mode
- `OPENAI_MODEL`: OpenAI model, default `gpt-5.6-luna`
- `OLLAMA_MODEL`: local Ollama model, default `llama3.2:3b`
- `AI_MAX_FINDINGS`: maximum findings included in AI context, default `60`

## JavaScript Analysis

ReconRaptor AI downloads live JavaScript files into `downloaded_js/` and analyzes them with Gitleaks when available. It also runs built-in regex checks.

Reports are separated by confidence and purpose:

- `generic_api_keys.json`: broad API key and token candidates with redacted match snippets
- `genuine_leaks.json`: higher-confidence built-in leak matches with redacted match snippets
- `gitleaks_report.json`: Gitleaks JSON output
- `js_vulnerability_findings.json`: client-side vulnerability indicators with compact metadata
- `js_regex_dictionary.txt`: regex patterns used by the JS scanner
- `js_secret_summary.txt`: summary counts and report references

Built-in JS findings are written as compact JSON objects with `type`, `source_url`, `file`, `line`, `match_length`, `match_sha256`, and redacted `match` fields. To keep reports safe to share and review, raw secret values are not written to disk. To keep minified bundles usable, each rule records a capped set of representative matches instead of dumping whole JavaScript lines.

The JS vulnerability scan looks for indicators such as DOM XSS sinks and sources, client-side redirects, sensitive browser storage, source map references, exposed API/admin/debug paths, prototype pollution clues, insecure transport, and internal host references.

## ProjectDiscovery Checks

ReconRaptor AI runs two additional ProjectDiscovery checks after URL and JavaScript analysis:

- `nuclei_findings.jsonl`: Nuclei findings for low, medium, high, and critical severity templates, with raw request/response output omitted.
- `nuclei_potential_url_findings.jsonl`: Nuclei findings from the focused scan against `potential_vuln_urls.txt`.
- `tls_findings.jsonl`: TLS metadata from `tlsx` for live hosts.

These checks are intended to surface likely vulnerabilities and useful attack-surface metadata, similar to the validation phase in larger recon frameworks. Always review findings manually before reporting.

## Updating Tools

To update dependencies manually:

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

## Responsible Use

Use ReconRaptor AI only on targets you own or are explicitly authorized to test. Findings from regex-based scanners and AI triage are indicators and should be manually validated before reporting.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Author

Created by [Zuri](https://github.com/Zuri09).

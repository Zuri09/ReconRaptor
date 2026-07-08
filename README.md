# ReconRaptor

ReconRaptor is a Bash-based reconnaissance helper for bug bounty and authorized security testing. It collects subdomains, validates live hosts, gathers archived URLs, extracts JavaScript and JSON assets, and highlights possible secrets or information-disclosure indicators.

The tool is designed to produce practical files you can review quickly after a scan instead of leaving everything mixed together in one large output.

## Features

- Subdomain discovery with `subfinder`
- DNS resolution with `dnsx`
- Live and non-live host classification with `httpx`
- Historical URL collection with `waybackurls`
- Live URL crawling with `katana`
- Vulnerability checks with `nuclei`
- TLS metadata collection with `tlsx`
- JavaScript and JSON URL extraction, including URLs with query strings
- URL-based information-disclosure checks
- Smart URL filtering for sensitive files and secret-looking URL patterns
- JavaScript download and analysis
- Separate reports for generic API key candidates, higher-confidence leaks, Gitleaks findings, and JS vulnerability indicators
- Optional Discord webhook upload for zipped results
- Cleaner CLI output with scan sections and a final summary

## Installation

Run the installer:

```bash
chmod +x install.sh
./install.sh
```

The installer checks for Go and installs:

- `subfinder`
- `dnsx`
- `httpx`
- `katana`
- `nuclei`
- `tlsx`
- `waybackurls`
- `gitleaks`

If any installed Go tool is not found after restarting your terminal, add this to your shell profile:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Usage

Run a scan:

```bash
./reconraptor.sh -d example.com
```

Send results to a Discord webhook:

```bash
./reconraptor.sh -d example.com -w "https://discord.com/api/webhooks/..."
```

When `-w` is provided, ReconRaptor compresses `recon_<domain>/` into `results_<domain>.zip` and uploads that zip file to the webhook.

## Output Structure

ReconRaptor creates a target-specific directory:

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
    └── downloaded_js_map.txt
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

`potential_vuln_urls.txt` deduplicates URLs matched by the smart filter. ReconRaptor uses this list for a focused Nuclei pass.

## JavaScript Analysis

ReconRaptor downloads live JavaScript files into `downloaded_js/` and analyzes them with Gitleaks when available. It also runs built-in regex checks.

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

ReconRaptor runs two additional ProjectDiscovery checks after URL and JavaScript analysis:

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
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/zricethezav/gitleaks/v8@latest
```

## Responsible Use

Use ReconRaptor only on targets you own or are explicitly authorized to test. Findings from regex-based scanners are indicators and should be manually validated before reporting.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Author

Created by [Zuri](https://github.com/Zuri09).

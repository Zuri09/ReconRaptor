# ReconRaptor

ReconRaptor is a Bash-based reconnaissance helper for bug bounty and authorized security testing. It collects subdomains, validates live hosts, gathers archived URLs, extracts JavaScript and JSON assets, and highlights possible secrets or information-disclosure indicators.

The tool is designed to produce practical files you can review quickly after a scan instead of leaving everything mixed together in one large output.

## Features

- Subdomain discovery with `subfinder`
- Live and non-live host classification with `httpx`
- Historical URL collection with `waybackurls`
- JavaScript and JSON URL extraction, including URLs with query strings
- URL-based information-disclosure checks
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
- `httpx`
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

## Output Structure

ReconRaptor creates a target-specific directory:

```text
recon_example.com/
├── subdomains.txt
├── authsubs.txt
├── unauthsubs.txt
├── urls.txt
├── js_files.txt
├── json_files.txt
├── authjs_files.txt
├── authjson_files.txt
├── url_info_disclosure.txt
├── url_regex_dictionary.txt
├── downloaded_js/
├── downloaded_js_map.txt
├── generic_api_keys.txt
├── genuine_leaks.txt
├── gitleaks_report.json
├── js_vulnerability_findings.txt
├── js_regex_dictionary.txt
└── js_secret_summary.txt
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

## JavaScript Analysis

ReconRaptor downloads live JavaScript files into `downloaded_js/` and analyzes them with Gitleaks when available. It also runs built-in regex checks.

Reports are separated by confidence and purpose:

- `generic_api_keys.txt`: broad API key and token candidates
- `genuine_leaks.txt`: higher-confidence built-in leak matches
- `gitleaks_report.json`: Gitleaks JSON output
- `js_vulnerability_findings.txt`: client-side vulnerability indicators
- `js_regex_dictionary.txt`: regex patterns used by the JS scanner
- `js_secret_summary.txt`: summary counts and report references

The JS vulnerability scan looks for indicators such as DOM XSS sinks and sources, client-side redirects, sensitive browser storage, source map references, exposed API/admin/debug paths, prototype pollution clues, insecure transport, and internal host references.

## Updating Tools

To update dependencies manually:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/zricethezav/gitleaks/v8@latest
```

## Responsible Use

Use ReconRaptor only on targets you own or are explicitly authorized to test. Findings from regex-based scanners are indicators and should be manually validated before reporting.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Author

Created by [Zuri](https://github.com/Zuri09).

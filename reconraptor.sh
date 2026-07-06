#!/bin/bash

# Colors. Use printf-friendly ANSI escapes so shells do not print "\e[32m" literally.
ESC=$(printf '\033')
RED="${ESC}[31m"
GREEN="${ESC}[32m"
CYAN="${ESC}[36m"
YELLOW="${ESC}[33m"
BLUE="${ESC}[34m"
BOLD="${ESC}[1m"
DIM="${ESC}[2m"
RESET="${ESC}[0m"

info() {
    printf '%b%s%b\n' "$1" "$2" "$RESET"
}

line() {
    printf '%b%s%b\n' "$DIM" "------------------------------------------------------------" "$RESET"
}

section() {
    printf '\n'
    line
    printf '%b%s%b %b%s%b\n' "$CYAN" ">>" "$RESET" "$BOLD" "$1" "$RESET"
    line
}

step() {
    printf '%b[%s]%b %s\n' "$BLUE" ".." "$RESET" "$1"
}

success() {
    printf '%b[%s]%b %s\n' "$GREEN" "OK" "$RESET" "$1"
}

warn() {
    printf '%b[%s]%b %s\n' "$YELLOW" "!!" "$RESET" "$1"
}

fail() {
    printf '%b[%s]%b %s\n' "$RED" "NO" "$RESET" "$1"
}

stat_line() {
    printf '  %b%-22s%b %s\n' "$DIM" "$1" "$RESET" "$2"
}

banner() {
printf '%b' "$CYAN"
cat << "EOF"

    ____                        ____              __
   / __ \___  _________  ____  / __ \____ _____  / /_____  _____
  / /_/ / _ \/ ___/ __ \/ __ \/ /_/ / __ `/ __ \/ __/ __ \/ ___/
 / _, _/  __/ /__/ /_/ / / / / _, _/ /_/ / /_/ / /_/ /_/ / /
/_/ |_|\___/\___/\____/_/ /_/_/ |_|\__,_/ .___/\__/\____/_/
                                        /_/

EOF
printf '%b' "$RESET"
printf '%b%s%b\n' "$DIM" "  Subdomains | URLs | JS secrets | Discord reports" "$RESET"
}

# Requirements check
check_installed() {
    for tool in subfinder httpx waybackurls curl; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            fail "$tool is not installed. Please run ./install.sh"
            exit 1
        fi
    done
}

download_js_files() {
    js_list="$1"
    out_dir="downloaded_js"
    map_file="downloaded_js_map.txt"

    mkdir -p "$out_dir"
    : > "$map_file"

    if [ ! -s "$js_list" ]; then
        warn "No live JS files found to download."
        return
    fi

    step "Downloading live JS files for secret analysis"
    while IFS= read -r js_url; do
        [ -z "$js_url" ] && continue

        file_id=$(printf '%s' "$js_url" | cksum | awk '{print $1}')
        js_file="$out_dir/${file_id}.js"

        if curl -ksL --max-time 20 --retry 1 "$js_url" -o "$js_file"; then
            printf '%s %s\n' "$js_file" "$js_url" >> "$map_file"
        else
            rm -f "$js_file"
        fi
    done < "$js_list"
}

scan_js_secrets() {
    out_dir="downloaded_js"
    generic_file="generic_api_keys.txt"
    genuine_file="genuine_leaks.txt"
    gitleaks_file="gitleaks_report.json"
    vuln_file="js_vulnerability_findings.txt"
    dictionary_file="js_regex_dictionary.txt"
    summary_file="js_secret_summary.txt"

    : > "$generic_file"
    : > "$genuine_file"
    : > "$gitleaks_file"
    : > "$vuln_file"
    : > "$summary_file"
    write_js_regex_dictionary "$dictionary_file"

    if [ ! -d "$out_dir" ] || ! find "$out_dir" -type f -name '*.js' | grep -q .; then
        warn "No downloaded JS files available for secret analysis."
        return
    fi

    step "Analyzing downloaded JS files for secrets"

    if command -v gitleaks >/dev/null 2>&1; then
        step "Using gitleaks for secret scanning"
        if gitleaks dir --no-banner --no-color --redact --report-format json --report-path "$gitleaks_file" "$out_dir" >/dev/null 2>&1; then
            printf 'Gitleaks scan complete. Review %s for tool findings.\n' "$gitleaks_file" > "$summary_file"
        else
            printf 'Gitleaks completed with findings or warnings. Review %s.\n' "$gitleaks_file" > "$summary_file"
        fi
    else
        warn "gitleaks not installed. Using high-confidence built-in checks."
    fi

    while read -r js_file js_url; do
        [ -f "$js_file" ] || continue

        scan_pattern "$genuine_file" "$js_file" "$js_url" "HIGH: AWS access key" 'AKIA[0-9A-Z]{16}'
        scan_pattern "$genuine_file" "$js_file" "$js_url" "HIGH: Google API key" 'AIza[0-9A-Za-z_-]{35}'
        scan_pattern "$genuine_file" "$js_file" "$js_url" "HIGH: GitHub token" 'gh[pousr]_[0-9A-Za-z_]{36,255}'
        scan_pattern "$genuine_file" "$js_file" "$js_url" "HIGH: Slack token" 'xox[baprs]-[0-9A-Za-z-]{10,255}'
        scan_pattern "$genuine_file" "$js_file" "$js_url" "HIGH: Stripe live secret key" 'sk_live_[0-9A-Za-z]{20,255}'
        scan_pattern "$genuine_file" "$js_file" "$js_url" "HIGH: JWT token" 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        scan_pattern "$genuine_file" "$js_file" "$js_url" "HIGH: private key marker" '-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----'
        scan_pattern "$genuine_file" "$js_file" "$js_url" "HIGH: bearer token assignment" '[Bb]earer[[:space:]]+[A-Za-z0-9._~+/=-]{20,}'
        scan_pattern "$genuine_file" "$js_file" "$js_url" "HIGH: password/secret assignment" '(password|passwd|pwd|client[_-]?secret|app[_-]?secret|private[_-]?key)[[:space:]]*[:=][[:space:]]*["'\''`][^"'\''`]{8,}["'\''`]'

        scan_pattern "$generic_file" "$js_file" "$js_url" "GENERIC: possible API key" '(api[_-]?key|apikey|apiKey|access[_-]?key|accessKey|secret[_-]?key|secretKey|token|auth[_-]?token|authorization)[[:space:]]*[:=][[:space:]]*["'\''`][A-Za-z0-9_./+=:@%{}$!?,~#&-]{8,}["'\''`]'
        scan_pattern "$generic_file" "$js_file" "$js_url" "GENERIC: Firebase config" '(firebase|apiKey|authDomain|projectId|storageBucket|messagingSenderId|appId)[[:space:]]*[:=]'
        scan_pattern "$generic_file" "$js_file" "$js_url" "GENERIC: cloud/storage URL" '(s3\.amazonaws\.com|amazonaws\.com|storage\.googleapis\.com|firebaseio\.com|supabase\.co|blob\.core\.windows\.net)'
        scan_pattern "$generic_file" "$js_file" "$js_url" "GENERIC: third-party credential keyword" '(stripe|paypal|sendgrid|mailgun|twilio|discord|slack|github|gitlab|sentry|datadog|newrelic)[A-Za-z0-9_.-]{0,40}(key|token|secret|dsn)'

        scan_pattern "$vuln_file" "$js_file" "$js_url" "DOM XSS sink/source indicator" '(document\.write|innerHTML|outerHTML|insertAdjacentHTML|eval\(|new Function\(|setTimeout\(["'\''`]|setInterval\(["'\''`]|location\.(hash|search|href)|document\.(URL|documentURI|referrer)|window\.name)'
        scan_pattern "$vuln_file" "$js_file" "$js_url" "Client-side redirect indicator" '(location\.(href|assign|replace)|window\.open)[[:space:]]*\('
        scan_pattern "$vuln_file" "$js_file" "$js_url" "Sensitive browser storage indicator" '(localStorage|sessionStorage|indexedDB).*(token|jwt|secret|password|auth|session)'
        scan_pattern "$vuln_file" "$js_file" "$js_url" "Source map disclosure" 'sourceMappingURL=.*\.map'
        scan_pattern "$vuln_file" "$js_file" "$js_url" "API/admin/debug endpoint exposure" '(/api/|/graphql|/swagger|/openapi|/admin|/debug|/internal|/private|/dev|/staging|/test)'
        scan_pattern "$vuln_file" "$js_file" "$js_url" "Prototype pollution indicator" '(__proto__|constructor\.prototype|prototypepollution|mergeDeep|deepMerge)'
        scan_pattern "$vuln_file" "$js_file" "$js_url" "Insecure transport indicator" '(http://|ws://)'
        scan_pattern "$vuln_file" "$js_file" "$js_url" "SSRF/internal host indicator" '(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+)'
    done < downloaded_js_map.txt

    {
        printf 'Generic API key candidates: %s\n' "$(count_lines "$generic_file")"
        printf 'High-confidence leaks: %s\n' "$(count_lines "$genuine_file")"
        printf 'Gitleaks JSON report: %s\n' "$gitleaks_file"
        printf 'JS vulnerability indicators: %s\n' "$(count_lines "$vuln_file")"
        printf 'Regex dictionary: %s\n' "$dictionary_file"
    } >> "$summary_file"

    success "Generic API key candidates saved to $generic_file"
    success "High-confidence leaks saved to $genuine_file"
    success "JS vulnerability indicators saved to $vuln_file"
}

scan_pattern() {
    output_file="$1"
    js_file="$2"
    js_url="$3"
    label="$4"
    pattern="$5"

    grep -Eain "$pattern" "$js_file" | while IFS= read -r match_line; do
        printf '[%s] %s | %s:%s\n' "$label" "$js_url" "$js_file" "$match_line" >> "$output_file"
    done
}

write_js_regex_dictionary() {
    dictionary_file="$1"

    cat > "$dictionary_file" << "EOF"
HIGH: AWS access key | AKIA[0-9A-Z]{16}
HIGH: Google API key | AIza[0-9A-Za-z_-]{35}
HIGH: GitHub token | gh[pousr]_[0-9A-Za-z_]{36,255}
HIGH: Slack token | xox[baprs]-[0-9A-Za-z-]{10,255}
HIGH: Stripe live secret key | sk_live_[0-9A-Za-z]{20,255}
HIGH: JWT token | eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+
HIGH: private key marker | -----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----
HIGH: bearer token assignment | [Bb]earer[[:space:]]+[A-Za-z0-9._~+/=-]{20,}
HIGH: password/secret assignment | (password|passwd|pwd|client[_-]?secret|app[_-]?secret|private[_-]?key)[[:space:]]*[:=][[:space:]]*["'`][^"'`]{8,}["'`]
GENERIC: possible API key | (api[_-]?key|apikey|apiKey|access[_-]?key|accessKey|secret[_-]?key|secretKey|token|auth[_-]?token|authorization)[[:space:]]*[:=][[:space:]]*["'`][A-Za-z0-9_./+=:@%{}$!?,~#&-]{8,}["'`]
GENERIC: Firebase config | (firebase|apiKey|authDomain|projectId|storageBucket|messagingSenderId|appId)[[:space:]]*[:=]
GENERIC: cloud/storage URL | (s3\.amazonaws\.com|amazonaws\.com|storage\.googleapis\.com|firebaseio\.com|supabase\.co|blob\.core\.windows\.net)
GENERIC: third-party credential keyword | (stripe|paypal|sendgrid|mailgun|twilio|discord|slack|github|gitlab|sentry|datadog|newrelic)[A-Za-z0-9_.-]{0,40}(key|token|secret|dsn)
VULN: DOM XSS sink/source indicator | (document\.write|innerHTML|outerHTML|insertAdjacentHTML|eval\(|new Function\(|setTimeout\(["'`]|setInterval\(["'`]|location\.(hash|search|href)|document\.(URL|documentURI|referrer)|window\.name)
VULN: Client-side redirect indicator | (location\.(href|assign|replace)|window\.open)[[:space:]]*\(
VULN: Sensitive browser storage indicator | (localStorage|sessionStorage|indexedDB).*(token|jwt|secret|password|auth|session)
VULN: Source map disclosure | sourceMappingURL=.*\.map
VULN: API/admin/debug endpoint exposure | (/api/|/graphql|/swagger|/openapi|/admin|/debug|/internal|/private|/dev|/staging|/test)
VULN: Prototype pollution indicator | (__proto__|constructor\.prototype|prototypepollution|mergeDeep|deepMerge)
VULN: Insecure transport indicator | (http://|ws://)
VULN: SSRF/internal host indicator | (localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+)
EOF
}

scan_url_info_disclosure() {
    urls_file="$1"
    report_file="url_info_disclosure.txt"
    dictionary_file="url_regex_dictionary.txt"

    : > "$report_file"
    write_url_regex_dictionary "$dictionary_file"

    if [ ! -s "$urls_file" ]; then
        warn "No URLs available for info-disclosure analysis."
        return
    fi

    step "Scanning URLs for info-disclosure indicators"
    while IFS= read -r url; do
        [ -z "$url" ] && continue

        scan_url_pattern "$report_file" "$url" "HIGH: environment/config file" '(\.env($|[?#])|/\.env($|[?#])|/config\.(json|ya?ml|xml|ini|php|bak|old)($|[?#])|/settings\.(json|ya?ml|xml|ini)($|[?#]))'
        scan_url_pattern "$report_file" "$url" "HIGH: backup/archive/database dump" '(\.bak($|[?#])|\.backup($|[?#])|\.old($|[?#])|\.orig($|[?#])|\.save($|[?#])|\.swp($|[?#])|\.zip($|[?#])|\.tar($|[?#])|\.tar\.gz($|[?#])|\.tgz($|[?#])|\.7z($|[?#])|\.rar($|[?#])|\.sql($|[?#])|\.db($|[?#])|\.sqlite($|[?#]))'
        scan_url_pattern "$report_file" "$url" "HIGH: credential/token in URL" '([?&](api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|secret|client[_-]?secret|password|passwd|pwd|jwt|session|sid)=([^&#]{8,}))'
        scan_url_pattern "$report_file" "$url" "HIGH: private key/certificate path" '(\.pem($|[?#])|\.key($|[?#])|\.p12($|[?#])|\.pfx($|[?#])|id_rsa($|[?#])|id_dsa($|[?#]))'
        scan_url_pattern "$report_file" "$url" "MEDIUM: source map disclosure" '(\.map($|[?#])|sourceMappingURL=)'
        scan_url_pattern "$report_file" "$url" "MEDIUM: logs/debug/trace" '(/logs?/|\.log($|[?#])|/debug($|[/?#])|/trace($|[/?#])|/profiler($|[/?#])|/phpinfo\.php($|[?#])|/server-status($|[/?#])|/actuator($|[/?#]))'
        scan_url_pattern "$report_file" "$url" "MEDIUM: API docs/schema exposure" '(/swagger($|[/?#])|/swagger-ui($|[/?#])|/api-docs($|[/?#])|/openapi\.(json|ya?ml)($|[?#])|/graphql($|[/?#])|/graphiql($|[/?#]))'
        scan_url_pattern "$report_file" "$url" "MEDIUM: admin/internal/dev endpoint" '(/admin($|[/?#])|/internal($|[/?#])|/private($|[/?#])|/dev($|[/?#])|/staging($|[/?#])|/test($|[/?#])|/qa($|[/?#])|/beta($|[/?#]))'
        scan_url_pattern "$report_file" "$url" "MEDIUM: possible open redirect parameter" '([?&](next|url|redirect|redirect_uri|redirect_url|return|returnUrl|return_url|callback|continue|dest|destination)=https?%3A%2F%2F|[?&](next|url|redirect|redirect_uri|redirect_url|return|returnUrl|return_url|callback|continue|dest|destination)=https?://)'
        scan_url_pattern "$report_file" "$url" "LOW: interesting document/export" '(\.csv($|[?#])|\.xlsx?($|[?#])|\.docx?($|[?#])|\.pdf($|[?#])|/export($|[/?#])|/download($|[/?#])|/dump($|[/?#]))'
        scan_url_pattern "$report_file" "$url" "LOW: version/control metadata" '(/\.git($|/)|/\.svn($|/)|/\.hg($|/)|/composer\.(json|lock)($|[?#])|/package-lock\.json($|[?#])|/yarn\.lock($|[?#])|/go\.sum($|[?#]))'
    done < "$urls_file"

    if [ -s "$report_file" ]; then
        success "URL info-disclosure indicators saved to $report_file"
    else
        success "No URL info-disclosure indicators found."
    fi
}

scan_url_pattern() {
    output_file="$1"
    url="$2"
    label="$3"
    pattern="$4"

    printf '%s\n' "$url" | grep -Eiq "$pattern" && printf '[%s] %s\n' "$label" "$url" >> "$output_file"
}

write_url_regex_dictionary() {
    dictionary_file="$1"

    cat > "$dictionary_file" << "EOF"
HIGH: environment/config file | (\.env($|[?#])|/\.env($|[?#])|/config\.(json|ya?ml|xml|ini|php|bak|old)($|[?#])|/settings\.(json|ya?ml|xml|ini)($|[?#]))
HIGH: backup/archive/database dump | (\.bak($|[?#])|\.backup($|[?#])|\.old($|[?#])|\.orig($|[?#])|\.save($|[?#])|\.swp($|[?#])|\.zip($|[?#])|\.tar($|[?#])|\.tar\.gz($|[?#])|\.tgz($|[?#])|\.7z($|[?#])|\.rar($|[?#])|\.sql($|[?#])|\.db($|[?#])|\.sqlite($|[?#]))
HIGH: credential/token in URL | ([?&](api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|secret|client[_-]?secret|password|passwd|pwd|jwt|session|sid)=([^&#]{8,}))
HIGH: private key/certificate path | (\.pem($|[?#])|\.key($|[?#])|\.p12($|[?#])|\.pfx($|[?#])|id_rsa($|[?#])|id_dsa($|[?#]))
MEDIUM: source map disclosure | (\.map($|[?#])|sourceMappingURL=)
MEDIUM: logs/debug/trace | (/logs?/|\.log($|[?#])|/debug($|[/?#])|/trace($|[/?#])|/profiler($|[/?#])|/phpinfo\.php($|[?#])|/server-status($|[/?#])|/actuator($|[/?#]))
MEDIUM: API docs/schema exposure | (/swagger($|[/?#])|/swagger-ui($|[/?#])|/api-docs($|[/?#])|/openapi\.(json|ya?ml)($|[?#])|/graphql($|[/?#])|/graphiql($|[/?#]))
MEDIUM: admin/internal/dev endpoint | (/admin($|[/?#])|/internal($|[/?#])|/private($|[/?#])|/dev($|[/?#])|/staging($|[/?#])|/test($|[/?#])|/qa($|[/?#])|/beta($|[/?#]))
MEDIUM: possible open redirect parameter | ([?&](next|url|redirect|redirect_uri|redirect_url|return|returnUrl|return_url|callback|continue|dest|destination)=https?%3A%2F%2F|[?&](next|url|redirect|redirect_uri|redirect_url|return|returnUrl|return_url|callback|continue|dest|destination)=https?://)
LOW: interesting document/export | (\.csv($|[?#])|\.xlsx?($|[?#])|\.docx?($|[?#])|\.pdf($|[?#])|/export($|[/?#])|/download($|[/?#])|/dump($|[/?#]))
LOW: version/control metadata | (/\.git($|/)|/\.svn($|/)|/\.hg($|/)|/composer\.(json|lock)($|[?#])|/package-lock\.json($|[?#])|/yarn\.lock($|[?#])|/go\.sum($|[?#]))
EOF
}

count_lines() {
    if [ -f "$1" ]; then
        wc -l < "$1" | tr -d ' '
    else
        printf '0'
    fi
}

print_summary() {
    domain="$1"

    section "Scan Summary"
    stat_line "Target" "$domain"
    stat_line "Subdomains" "$(count_lines subdomains.txt)"
    stat_line "Live hosts" "$(count_lines authsubs.txt)"
    stat_line "Non-live hosts" "$(count_lines unauthsubs.txt)"
    stat_line "URLs collected" "$(count_lines urls.txt)"
    stat_line "URL disclosures" "$(count_lines url_info_disclosure.txt)"
    stat_line "Live JS files" "$(count_lines authjs_files.txt)"
    stat_line "Live JSON files" "$(count_lines authjson_files.txt)"
    stat_line "Generic API keys" "$(count_lines generic_api_keys.txt)"
    stat_line "Genuine leaks" "$(count_lines genuine_leaks.txt)"
    stat_line "JS vuln indicators" "$(count_lines js_vulnerability_findings.txt)"

    printf '\n%b%s%b\n' "$BOLD" "Result files" "$RESET"
    stat_line "Directory" "recon_$domain"
    stat_line "URL disclosures" "url_info_disclosure.txt"
    stat_line "URL dictionary" "url_regex_dictionary.txt"
    stat_line "Generic keys" "generic_api_keys.txt"
    stat_line "Genuine leaks" "genuine_leaks.txt"
    stat_line "Gitleaks JSON" "gitleaks_report.json"
    stat_line "JS vulns" "js_vulnerability_findings.txt"
    stat_line "Regex dictionary" "js_regex_dictionary.txt"
    stat_line "JS map" "downloaded_js_map.txt"
    stat_line "Summary" "js_secret_summary.txt"
}

# Recon start
recon() {
    section "Target: $1"
    mkdir -p "recon_$1"
    cd "recon_$1" || exit 1

    section "Subdomain Discovery"
    step "Finding subdomains"
    subfinder -d "$1" -silent > subdomains.txt
    success "Saved $(count_lines subdomains.txt) subdomains to subdomains.txt"

    step "Checking live domains"
    cat subdomains.txt | httpx -silent -mc 200 > authsubs.txt
    success "Saved $(count_lines authsubs.txt) live domains to authsubs.txt"

    step "Checking non-live domains"
    cat subdomains.txt | httpx -silent -mc 400,401,402,403,404 > unauthsubs.txt
    success "Saved $(count_lines unauthsubs.txt) non-live domains to unauthsubs.txt"
    
    LINE_COUNT=$(wc -l < "authsubs.txt")
    if [ "$LINE_COUNT" -gt 20 ]; then
        warn "$1 has many live subdomains, so URL collection can take time."
    else
        success "$1 has fewer live subdomains, so this should be quick."
    fi

    section "Historical URLs"
    step "Fetching wayback URLs from live domains"
    cat authsubs.txt | waybackurls > urls.txt

    LINE_COUNT=$(wc -l < "unauthsubs.txt")
    if [ "$LINE_COUNT" -gt 20 ]; then
        warn "$1 has many non-live domains; archived URL collection can take time."
    else
        success "$1 has fewer non-live domains."
    fi

    step "Fetching wayback URLs from non-live domains"
    cat unauthsubs.txt | waybackurls >> urls.txt
    success "Saved $(count_lines urls.txt) URLs to urls.txt"

    section "URL Exposure Analysis"
    scan_url_info_disclosure "urls.txt"

    section "Asset Extraction"
    step "Extracting JS and JSON URLs"
    grep -Ei "\.js([?#].*)?$" urls.txt | sort -u > js_files.txt
    grep -Ei "\.json([?#].*)?$" urls.txt | sort -u > json_files.txt
    success "Saved $(count_lines js_files.txt) JS URLs and $(count_lines json_files.txt) JSON URLs"

    step "Validating live JS and JSON files"
    cat js_files.txt | httpx -silent -mc 200 > authjs_files.txt
    cat json_files.txt | httpx -silent -mc 200 > authjson_files.txt
    success "Validated $(count_lines authjs_files.txt) live JS files and $(count_lines authjson_files.txt) live JSON files"

    section "Secret Analysis"
    download_js_files "authjs_files.txt"
    scan_js_secrets

    print_summary "$1"
    printf '\n'
    success "Recon complete."
}

# Discord Upload
upload_discord() {
    section "Discord Upload"
    step "Uploading results to Discord"
    zip -r "results_$1.zip" "recon_$1/"
    curl -X POST -F "file=@results_$1.zip" -F "payload_json={\"content\":\"ReconRaptor Scan Report for *$1*\"}" "$2"
}

# Args parsing
domain=""
webhook=""
while getopts ":d:w:" opt; do
  case $opt in
    d) domain="$OPTARG"
    ;;
    w) webhook="$OPTARG"
    ;;
    \?) echo "Usage: $0 -d <domain> [-w <discord_webhook>]"; exit 1
    ;;
  esac
done

if [ -z "$domain" ]; then
    fail "Please provide a domain using -d option."
    exit 1
fi

if [ -t 1 ]; then
    clear
fi
banner
check_installed
recon "$domain"

if [ -n "$webhook" ]; then
    upload_discord "$domain" "$webhook"
fi

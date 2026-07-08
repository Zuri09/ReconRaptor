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
MAX_MATCHES_PER_PATTERN=50

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
printf '%b%s%b\n' "$DIM" "  Subdomains | URLs | JS secrets | Vuln checks | Discord reports" "$RESET"
}

# Requirements check
check_installed() {
    for tool in subfinder dnsx httpx waybackurls katana nuclei tlsx curl; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            fail "$tool is not installed. Please run ./install.sh"
            exit 1
        fi
    done
}

run_projectdiscovery_checks() {
    nuclei_file="nuclei_findings.jsonl"
    nuclei_potential_file="nuclei_potential_url_findings.jsonl"
    tls_file="tls_findings.jsonl"

    : > "$nuclei_file"
    : > "$nuclei_potential_file"
    : > "$tls_file"

    if [ ! -s "authsubs.txt" ]; then
        warn "No live hosts available for ProjectDiscovery checks."
        return
    fi

    step "Running nuclei safe vulnerability checks"
    nuclei -l authsubs.txt \
        -severity low,medium,high,critical \
        -jsonl \
        -omit-raw \
        -silent \
        -o "$nuclei_file" >/dev/null 2>&1 || warn "nuclei completed with findings or warnings."

    if [ -s "potential_vuln_urls.txt" ]; then
        step "Running nuclei checks against high-signal URLs"
        nuclei -l potential_vuln_urls.txt \
            -severity low,medium,high,critical \
            -jsonl \
            -omit-raw \
            -silent \
            -o "$nuclei_potential_file" >/dev/null 2>&1 || warn "nuclei potential URL scan completed with findings or warnings."
    fi

    step "Collecting TLS metadata with tlsx"
    sed 's#^https\?://##' authsubs.txt | tlsx -json -silent > "$tls_file" 2>/dev/null || warn "tlsx completed with warnings."

    success "ProjectDiscovery checks saved to $nuclei_file and $tls_file"
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
    generic_file="generic_api_keys.json"
    genuine_file="genuine_leaks.json"
    gitleaks_file="gitleaks_report.json"
    vuln_file="js_vulnerability_findings.json"
    dictionary_file="js_regex_dictionary.txt"
    summary_file="js_secret_summary.txt"

    init_json_report "$generic_file"
    init_json_report "$genuine_file"
    : > "$gitleaks_file"
    init_json_report "$vuln_file"
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

    close_json_report "$generic_file"
    close_json_report "$genuine_file"
    close_json_report "$vuln_file"

    {
        printf 'Generic API key candidates: %s\n' "$(count_json_findings "$generic_file")"
        printf 'High-confidence leaks: %s\n' "$(count_json_findings "$genuine_file")"
        printf 'Gitleaks JSON report: %s\n' "$gitleaks_file"
        printf 'JS vulnerability indicators: %s\n' "$(count_json_findings "$vuln_file")"
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

    grep -Eaino -- "$pattern" "$js_file" | head -n "$MAX_MATCHES_PER_PATTERN" | while IFS= read -r match_line; do
        line_no="${match_line%%:*}"
        match_value="${match_line#*:}"
        append_json_finding "$output_file" "$label" "$js_url" "$js_file" "$line_no" "$match_value"
    done
}

init_json_report() {
    printf '[\n' > "$1"
}

close_json_report() {
    printf '\n]\n' >> "$1"
}

append_json_finding() {
    output_file="$1"
    finding_type="$2"
    source_url="$3"
    local_file="$4"
    line_no="$5"
    match_value="$6"
    redacted_match="$match_value"
    match_length=$(printf '%s' "$match_value" | wc -c | tr -d ' ')
    match_hash=$(hash_match "$match_value")

    if [ "$(wc -c < "$output_file" | tr -d ' ')" -gt 2 ]; then
        printf ',\n' >> "$output_file"
    fi

    printf '  {\n' >> "$output_file"
    printf '    "type": "%s",\n' "$(json_escape "$finding_type")" >> "$output_file"
    printf '    "source_url": "%s",\n' "$(json_escape "$source_url")" >> "$output_file"
    printf '    "file": "%s",\n' "$(json_escape "$local_file")" >> "$output_file"
    printf '    "line": %s,\n' "$line_no" >> "$output_file"
    printf '    "match_length": %s,\n' "$match_length" >> "$output_file"
    printf '    "match_sha256": "%s",\n' "$match_hash" >> "$output_file"
    printf '    "match": "%s"\n' "$(json_escape "$redacted_match")" >> "$output_file"
    printf '  }' >> "$output_file"
}

hash_match() {
    if command -v shasum >/dev/null 2>&1; then
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    else
        printf '%s' "$1" | cksum | awk '{print $1}'
    fi
}

redact_match() {
    awk '
    {
        if (length($0) <= 16) {
            print "$0"
        } else {
            print "$0"
        }
    }' << EOF
$1
EOF
}

json_escape() {
    awk '
    {
        gsub(/\\/,"\\\\")
        gsub(/"/,"\\\"")
        gsub(/\t/,"\\t")
        gsub(/\r/,"\\r")
        gsub(/\n/,"\\n")
        printf "%s", $0
    }' << EOF
$1
EOF
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

scan_smart_url_findings() {
    urls_file="$1"
    sensitive_file="smart_sensitive_files.json"
    secret_file="smart_secret_urls.json"
    potential_file="potential_vuln_urls.txt"
    dictionary_file="smart_url_filter_dictionary.txt"

    init_json_report "$sensitive_file"
    init_json_report "$secret_file"
    : > "$potential_file"
    write_smart_url_filter_dictionary "$dictionary_file"

    if [ ! -s "$urls_file" ]; then
        warn "No URLs available for smart URL filtering."
        close_json_report "$sensitive_file"
        close_json_report "$secret_file"
        return
    fi

    step "Running smart URL filter for sensitive files and secret patterns"
    while IFS= read -r url; do
        [ -z "$url" ] && continue

        scan_smart_url_pattern "$sensitive_file" "$url" "Sensitive file extension" '\.(zip|rar|tar|gz|tgz|7z|config|conf|ini|log|bak|backup|old|orig|save|swp|java|xlsx?|json|pdf|docx?|pptx|csv|htaccess|env|sql|db|sqlite|pem|key|p12|pfx)([?#].*)?$'
        scan_smart_url_pattern "$sensitive_file" "$url" "Sensitive path keyword" '/(backup|backups|dump|dumps|export|exports|download|downloads|logs?|debug|config|configs|private|internal|admin|staging|dev|test|qa)(/|$|[?#])'

        scan_smart_url_pattern "$secret_file" "$url" "Secret keyword in URL" '(access[_-]?key|access[_-]?token|admin[_-]?(pass|user)|algolia[_-]?(admin[_-]?key|api[_-]?key)|api[_-]?(key|secret)|apikey|apiSecret|app[_-]?(debug|id|key|secret)|auth[_-]?(token|secret)|authorizationToken|aws[_-]?(access|access[_-]?key[_-]?id|bucket|key|secret|secret[_-]?key|token)|AWSSecretKey|client[_-]?secret|cloudflare[_-]?(api[_-]?key|auth[_-]?key)|cloudinary[_-]?api[_-]?secret|connectionstring|consumer[_-]?(key|secret)|credentials|database[_-]?(password|username)|db[_-]?(password|passwd|user|username)|deploy[_-]?password|docker[_-]?(key|pass|passwd|password)|encryption[_-]?(key|password)|firebase|googlemaps|AIza|jwt|private[_-]?key|secret|token)'
        scan_smart_url_pattern "$secret_file" "$url" "Secret value in query string" '([?&](access[_-]?key|access[_-]?token|api[_-]?key|apikey|apiSecret|api[_-]?secret|app[_-]?key|app[_-]?secret|auth[_-]?token|client[_-]?secret|password|passwd|pwd|secret|token|jwt|session|sid)=([^&#]{8,}))'
        scan_smart_url_pattern "$secret_file" "$url" "Cloud or SaaS secret indicator" '(amazonaws|appspot|cloudfront|firebaseio|storage\.googleapis\.com|supabase\.co|blob\.core\.windows\.net|s3\.amazonaws\.com|cloudinary|sendgrid|mailgun|twilio|stripe|slack|discord|github|gitlab|datadog|newrelic|sentry)'
    done < "$urls_file"

    close_json_report "$sensitive_file"
    close_json_report "$secret_file"
    sort -u "$potential_file" -o "$potential_file"

    success "Smart sensitive file URLs saved to $sensitive_file"
    success "Smart secret URL patterns saved to $secret_file"
    success "Potential vulnerability URLs saved to $potential_file"
}

scan_smart_url_pattern() {
    output_file="$1"
    url="$2"
    label="$3"
    pattern="$4"

    printf '%s\n' "$url" | grep -Eio -- "$pattern" | head -n "$MAX_MATCHES_PER_PATTERN" | while IFS= read -r match_value; do
        printf '%s\n' "$url" >> potential_vuln_urls.txt
        append_url_json_finding "$output_file" "$label" "$url" "$match_value"
    done
}

append_url_json_finding() {
    output_file="$1"
    finding_type="$2"
    source_url="$3"
    match_value="$4"
    match_length=$(printf '%s' "$match_value" | wc -c | tr -d ' ')
    match_hash=$(hash_match "$match_value")

    if [ "$(wc -c < "$output_file" | tr -d ' ')" -gt 2 ]; then
        printf ',\n' >> "$output_file"
    fi

    printf '  {\n' >> "$output_file"
    printf '    "type": "%s",\n' "$(json_escape "$finding_type")" >> "$output_file"
    printf '    "source_url": "%s",\n' "$(json_escape "$source_url")" >> "$output_file"
    printf '    "match_length": %s,\n' "$match_length" >> "$output_file"
    printf '    "match_sha256": "%s",\n' "$match_hash" >> "$output_file"
    printf '    "match": "%s"\n' "$(json_escape "$match_value")" >> "$output_file"
    printf '  }' >> "$output_file"
}

write_smart_url_filter_dictionary() {
    dictionary_file="$1"

    cat > "$dictionary_file" << "EOF"
Sensitive file extension | \.(zip|rar|tar|gz|tgz|7z|config|conf|ini|log|bak|backup|old|orig|save|swp|java|xlsx?|json|pdf|docx?|pptx|csv|htaccess|env|sql|db|sqlite|pem|key|p12|pfx)([?#].*)?$
Sensitive path keyword | /(backup|backups|dump|dumps|export|exports|download|downloads|logs?|debug|config|configs|private|internal|admin|staging|dev|test|qa)(/|$|[?#])
Secret keyword in URL | access_key, access_token, admin_pass, api_key, api_secret, app_secret, auth_token, aws_secret_key, client_secret, cloudflare_api_key, database_password, db_password, encryption_key, private_key, token, jwt, and related real-world names
Secret value in query string | [?&](access_key|access_token|api_key|apikey|apiSecret|api_secret|app_key|app_secret|auth_token|client_secret|password|passwd|pwd|secret|token|jwt|session|sid)=value
Cloud or SaaS secret indicator | amazonaws, appspot, cloudfront, firebaseio, storage.googleapis.com, supabase.co, Azure Blob, Cloudinary, SendGrid, Mailgun, Twilio, Stripe, Slack, Discord, GitHub, GitLab, Datadog, New Relic, Sentry
EOF
}

scan_url_pattern() {
    output_file="$1"
    url="$2"
    label="$3"
    pattern="$4"

    printf '%s\n' "$url" | grep -Eiq -- "$pattern" && printf '[%s] %s\n' "$label" "$url" >> "$output_file"
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

count_json_findings() {
    if [ -f "$1" ]; then
        grep -c '"type":' "$1"
    else
        printf '0'
    fi
}

count_jsonl_findings() {
    count_lines "$1"
}

organize_output() {
    mkdir -p raw reports evidence

    for file in subdomains.txt resolved_subdomains.txt authsubs.txt unauthsubs.txt urls.txt js_files.txt json_files.txt authjs_files.txt authjson_files.txt; do
        [ -f "$file" ] && mv -f "$file" "raw/$file"
    done

    for file in \
        url_info_disclosure.txt \
        url_regex_dictionary.txt \
        smart_sensitive_files.json \
        smart_secret_urls.json \
        smart_url_filter_dictionary.txt \
        generic_api_keys.json \
        genuine_leaks.json \
        gitleaks_report.json \
        js_vulnerability_findings.json \
        js_regex_dictionary.txt \
        js_secret_summary.txt \
        nuclei_findings.jsonl \
        nuclei_potential_url_findings.jsonl \
        potential_vuln_urls.txt \
        tls_findings.jsonl; do
        [ -f "$file" ] && mv -f "$file" "reports/$file"
    done

    [ -f downloaded_js_map.txt ] && mv -f downloaded_js_map.txt evidence/downloaded_js_map.txt
    [ -d downloaded_js ] && mv -f downloaded_js evidence/downloaded_js
}

print_summary() {
    domain="$1"

    section "Scan Summary"
    stat_line "Target" "$domain"
    stat_line "Subdomains" "$(count_lines raw/subdomains.txt)"
    stat_line "Resolved domains" "$(count_lines raw/resolved_subdomains.txt)"
    stat_line "Live hosts" "$(count_lines raw/authsubs.txt)"
    stat_line "Non-live hosts" "$(count_lines raw/unauthsubs.txt)"
    stat_line "URLs collected" "$(count_lines raw/urls.txt)"
    stat_line "URL disclosures" "$(count_lines reports/url_info_disclosure.txt)"
    stat_line "Smart files" "$(count_json_findings reports/smart_sensitive_files.json)"
    stat_line "Smart URL secrets" "$(count_json_findings reports/smart_secret_urls.json)"
    stat_line "Live JS files" "$(count_lines raw/authjs_files.txt)"
    stat_line "Live JSON files" "$(count_lines raw/authjson_files.txt)"
    stat_line "Generic API keys" "$(count_json_findings reports/generic_api_keys.json)"
    stat_line "Genuine leaks" "$(count_json_findings reports/genuine_leaks.json)"
    stat_line "JS vuln indicators" "$(count_json_findings reports/js_vulnerability_findings.json)"
    stat_line "Nuclei findings" "$(count_jsonl_findings reports/nuclei_findings.jsonl)"
    stat_line "Potential URL vulns" "$(count_jsonl_findings reports/nuclei_potential_url_findings.jsonl)"
    stat_line "TLS records" "$(count_jsonl_findings reports/tls_findings.jsonl)"

    printf '\n%b%s%b\n' "$BOLD" "Result files" "$RESET"
    stat_line "Directory" "recon_$domain"
    stat_line "Raw data" "raw/"
    stat_line "Reports" "reports/"
    stat_line "Evidence" "evidence/"
    stat_line "Smart files" "reports/smart_sensitive_files.json"
    stat_line "Smart URL secrets" "reports/smart_secret_urls.json"
    stat_line "Nuclei" "reports/nuclei_findings.jsonl"
    stat_line "Potential nuclei" "reports/nuclei_potential_url_findings.jsonl"
    stat_line "Potential URLs" "reports/potential_vuln_urls.txt"
    stat_line "TLS" "reports/tls_findings.jsonl"
    stat_line "JS leaks" "reports/genuine_leaks.json"
    stat_line "JS map" "evidence/downloaded_js_map.txt"
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

    step "Resolving subdomains with dnsx"
    dnsx -l subdomains.txt -silent > resolved_subdomains.txt
    if [ ! -s resolved_subdomains.txt ]; then
        warn "dnsx found no resolved subdomains; falling back to raw subdomain list."
        cp subdomains.txt resolved_subdomains.txt
    fi
    success "Saved $(count_lines resolved_subdomains.txt) resolved subdomains to resolved_subdomains.txt"

    step "Checking live domains"
    cat resolved_subdomains.txt | httpx -silent -mc 200 > authsubs.txt
    success "Saved $(count_lines authsubs.txt) live domains to authsubs.txt"

    step "Checking non-live domains"
    cat resolved_subdomains.txt | httpx -silent -mc 400,401,402,403,404 > unauthsubs.txt
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

    step "Crawling live domains with katana"
    katana -list authsubs.txt -silent >> urls.txt

    LINE_COUNT=$(wc -l < "unauthsubs.txt")
    if [ "$LINE_COUNT" -gt 20 ]; then
        warn "$1 has many non-live domains; archived URL collection can take time."
    else
        success "$1 has fewer non-live domains."
    fi

    step "Fetching wayback URLs from non-live domains"
    cat unauthsubs.txt | waybackurls >> urls.txt
    sort -u urls.txt -o urls.txt
    success "Saved $(count_lines urls.txt) unique URLs to urls.txt"

    section "URL Exposure Analysis"
    scan_url_info_disclosure "urls.txt"
    scan_smart_url_findings "urls.txt"

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

    section "ProjectDiscovery Checks"
    run_projectdiscovery_checks

    organize_output
    print_summary "$1"
    printf '\n'
    success "Recon complete."
}

# Discord Upload
upload_discord() {
    result_dir="recon_$1"
    zip_file="results_$1.zip"

    section "Discord Upload"
    if [ ! -d "$result_dir" ]; then
        fail "Result directory $result_dir was not found. Discord upload skipped."
        return 1
    fi

    step "Compressing $result_dir"
    zip -qr "$zip_file" "$result_dir"

    step "Uploading $zip_file to Discord"
    if curl -fsS -X POST \
        -F "file=@$zip_file;type=application/zip" \
        -F "payload_json={\"content\":\"ReconRaptor scan report for $1\"}" \
        "$2" >/dev/null; then
        success "Discord upload complete."
    else
        fail "Discord upload failed. Check the webhook URL and network connection."
        return 1
    fi
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
start_dir=$(pwd)
recon "$domain"
cd "$start_dir" || exit 1

if [ -n "$webhook" ]; then
    upload_discord "$domain" "$webhook"
fi

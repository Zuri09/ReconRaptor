#!/bin/bash

# Terminal UI. Use printf-friendly ANSI escapes so shells do not print "\e[32m" literally.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    ESC=$(printf '\033')
    RED="${ESC}[31m"
    GREEN="${ESC}[32m"
    CYAN="${ESC}[36m"
    YELLOW="${ESC}[33m"
    BLUE="${ESC}[34m"
    MAGENTA="${ESC}[35m"
    WHITE="${ESC}[97m"
    BRIGHT_CYAN="${ESC}[96m"
    BRIGHT_GREEN="${ESC}[92m"
    BOLD="${ESC}[1m"
    DIM="${ESC}[2m"
    RESET="${ESC}[0m"
else
    RED=""
    GREEN=""
    CYAN=""
    YELLOW=""
    BLUE=""
    MAGENTA=""
    WHITE=""
    BRIGHT_CYAN=""
    BRIGHT_GREEN=""
    BOLD=""
    DIM=""
    RESET=""
fi

SECTION_INDEX=0
MAX_MATCHES_PER_PATTERN=50
MAX_VALIDATION_TARGETS="${MAX_VALIDATION_TARGETS:-300}"
VALIDATOR_PARALLELISM="${VALIDATOR_PARALLELISM:-12}"
CURL_TIMEOUT="${CURL_TIMEOUT:-12}"
AI_ENABLED="${AI_ENABLED:-false}"
AI_PROVIDER="${AI_PROVIDER:-auto}"
OPENAI_MODEL="${OPENAI_MODEL:-gpt-5.6-luna}"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.2:3b}"
AI_MAX_FINDINGS="${AI_MAX_FINDINGS:-60}"

info() {
    printf '%b%s%b\n' "$1" "$2" "$RESET"
}

terminal_width() {
    cols=$(tput cols 2>/dev/null || printf '80')
    [ "$cols" -gt 96 ] && cols=96
    [ "$cols" -lt 60 ] && cols=60
    printf '%s' "$cols"
}

repeat_char() {
    char="$1"
    count="$2"
    i=0
    while [ "$i" -lt "$count" ]; do
        printf '%s' "$char"
        i=$((i + 1))
    done
}

line() {
    printf '%b' "$DIM"
    repeat_char "-" "$(terminal_width)"
    printf '%b\n' "$RESET"
}

section() {
    SECTION_INDEX=$((SECTION_INDEX + 1))
    printf '\n'
    line
    printf '%b[%02d]%b %b%s%b\n' "$CYAN" "$SECTION_INDEX" "$RESET" "$BOLD" "$1" "$RESET"
    line
}

step() {
    printf '  %b[RUN ]%b %s\n' "$BLUE" "$RESET" "$1"
}

success() {
    printf '  %b[DONE]%b %s\n' "$GREEN" "$RESET" "$1"
}

warn() {
    printf '  %b[WARN]%b %s\n' "$YELLOW" "$RESET" "$1"
}

fail() {
    printf '  %b[FAIL]%b %s\n' "$RED" "$RESET" "$1"
}

stat_line() {
    printf '  %b%-26s%b %s\n' "$DIM" "$1" "$RESET" "$2"
}

summary_group() {
    printf '\n  %b%s%b\n' "$CYAN" "$1" "$RESET"
}

summary_row() {
    label="$1"
    value="$2"
    printf '    %-28s %b%8s%b\n' "$label" "$BOLD" "$value" "$RESET"
}

summary_path() {
    label="$1"
    path="$2"
    printf '    %-18s %b%s%b\n' "$label" "$BOLD" "$path" "$RESET"
}

banner() {
    line
    printf '%b' "$BRIGHT_CYAN"
    cat << "EOF"

    ____  ______ ______ ____  _   __ ____  ___    ____  ______ ____   ____
   / __ \/ ____// ____// __ \/ | / // __ \/   |  / __ \/_  __// __ \ / __ \
  / /_/ / __/  / /    / / / /  |/ // /_/ / /| | / /_/ / / /  / / / // /_/ /
 / _, _/ /___ / /___ / /_/ / /|  // _, _/ ___ |/ ____/ / /  / /_/ // _, _/
/_/ |_/_____/ \____/ \____/_/ |_//_/ |_/_/  |_/_/     /_/   \____//_/ |_|

EOF
    printf '%b' "$RESET"
    printf '  %b%s%b %b%s%b\n' "$BOLD$WHITE" "ReconRaptor AI" "$RESET" "$MAGENTA" "authorized recon command center" "$RESET"
    printf '  %b%s%b\n' "$BRIGHT_GREEN" "AI-powered triage for subdomains, URLs, JavaScript, validators, Nuclei, and reports" "$RESET"
    printf '  %bProfile%b %s  %bOutput%b %s  %bMode%b %s\n' \
        "$DIM" "$RESET" "fast + evidence-focused" \
        "$DIM" "$RESET" "START_HERE.md" \
        "$DIM" "$RESET" "authorized testing only"
    line
}

print_run_profile() {
    domain="$1"
    printf '  %bRun profile%b\n' "$CYAN" "$RESET"
    stat_line "Target" "$domain"
    stat_line "Output directory" "recon_$domain"
    stat_line "AI mode" "$AI_ENABLED"
    if [ "$AI_ENABLED" = "true" ]; then
        stat_line "AI provider" "$AI_PROVIDER"
        stat_line "AI model" "$OLLAMA_MODEL / $OPENAI_MODEL"
    fi
    stat_line "Validator parallelism" "$VALIDATOR_PARALLELISM"
    stat_line "Candidate cap" "$MAX_VALIDATION_TARGETS"
}

# Requirements check
check_installed() {
    for tool in subfinder dnsx httpx waybackurls katana nuclei tlsx curl; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            fail "$tool is not installed. Please run ./install.sh"
            exit 1
        fi
    done

    if ! command -v subzy >/dev/null 2>&1; then
        warn "subzy is not installed. Subdomain takeover checks will use nuclei only."
    fi
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
        -c 25 \
        -rl 100 \
        -silent \
        -o "$nuclei_file" >/dev/null 2>&1 || warn "nuclei completed with findings or warnings."

    if [ -s "potential_vuln_urls.txt" ]; then
        step "Running nuclei checks against high-signal URLs"
        nuclei -l potential_vuln_urls.txt \
            -severity low,medium,high,critical \
            -jsonl \
            -omit-raw \
            -c 25 \
            -rl 100 \
            -silent \
            -o "$nuclei_potential_file" >/dev/null 2>&1 || warn "nuclei potential URL scan completed with findings or warnings."
    fi

    step "Collecting TLS metadata with tlsx"
    sed 's#^https\?://##' authsubs.txt | tlsx -json -silent > "$tls_file" 2>/dev/null || warn "tlsx completed with warnings."

    success "ProjectDiscovery checks saved to $nuclei_file and $tls_file"
}

run_confirmed_validators() {
    domain="$1"
    confirmed_jsonl="confirmed_findings.jsonl"
    confirmed_json="confirmed_findings.json"
    validator_summary="confirmed_findings_summary.txt"
    takeover_file="subdomain_takeover_findings.json"
    validator_tmp="validator_tmp"

    : > "$confirmed_jsonl"
    : > "$validator_summary"
    init_json_report "$takeover_file"
    mkdir -p "$validator_tmp"

    prepare_validator_candidates

    step "Validating exposed files, redirects, CORS, GraphQL, buckets, and takeovers"
    run_parallel_file_checks sensitive_file_candidates.txt validate_sensitive_url "$validator_tmp/sensitive"
    run_parallel_file_checks open_redirect_candidates.txt validate_open_redirect_url "$validator_tmp/redirect"
    run_parallel_file_checks cors_candidates.txt validate_cors_target "$validator_tmp/cors"
    run_parallel_file_checks graphql_candidates.txt validate_graphql_url "$validator_tmp/graphql"
    run_parallel_file_checks bucket_candidates.txt validate_bucket_url "$validator_tmp/bucket"

    find "$validator_tmp" -type f -name '*.jsonl' -exec cat {} \; >> "$confirmed_jsonl" 2>/dev/null

    run_takeover_checks "$takeover_file" "$confirmed_jsonl"
    jsonl_to_json_array "$confirmed_jsonl" "$confirmed_json"

    {
        printf 'Confirmed/high-confidence findings: %s\n' "$(count_json_findings "$confirmed_json")"
        printf 'Sensitive file candidates checked: %s\n' "$(count_lines sensitive_file_candidates.txt)"
        printf 'Open redirect candidates checked: %s\n' "$(count_lines open_redirect_candidates.txt)"
        printf 'CORS candidates checked: %s\n' "$(count_lines cors_candidates.txt)"
        printf 'GraphQL candidates checked: %s\n' "$(count_lines graphql_candidates.txt)"
        printf 'Cloud bucket candidates checked: %s\n' "$(count_lines bucket_candidates.txt)"
        printf 'Parallelism: %s\n' "$VALIDATOR_PARALLELISM"
        printf 'Candidate cap per validator: %s\n' "$MAX_VALIDATION_TARGETS"
    } > "$validator_summary"

    success "Confirmed findings saved to $confirmed_json"
}

prepare_validator_candidates() {
    : > sensitive_file_candidates.txt
    : > open_redirect_candidates.txt
    : > cors_candidates.txt
    : > graphql_candidates.txt
    : > bucket_candidates.txt

    if [ -s potential_vuln_urls.txt ]; then
        grep -Ei '\.(env|config|conf|ini|ya?ml|xml|json|log|bak|backup|old|orig|save|swp|zip|tar|tgz|tar\.gz|7z|rar|sql|db|sqlite|pem|key|p12|pfx)([?#].*)?$|/(\.env|backup|backups|dump|dumps|exports?|downloads?|logs?|debug|configs?|private|internal)(/|$|[?#])' potential_vuln_urls.txt >> sensitive_file_candidates.txt
        grep -Ei '([?&](next|url|redirect|redirect_uri|redirect_url|return|returnUrl|return_url|callback|continue|dest|destination)=)' potential_vuln_urls.txt >> open_redirect_candidates.txt
        grep -Ei '(/graphql($|[/?#])|/graphiql($|[/?#]))' potential_vuln_urls.txt >> graphql_candidates.txt
        grep -Ei '(s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|firebaseio\.com|supabase\.co)' potential_vuln_urls.txt >> bucket_candidates.txt
    fi

    if [ -s urls.txt ]; then
        grep -Ei '\.(env|config|conf|ini|ya?ml|xml|json|log|bak|backup|old|orig|save|swp|zip|tar|tgz|tar\.gz|7z|rar|sql|db|sqlite|pem|key|p12|pfx)([?#].*)?$|/(\.env|backup|backups|dump|dumps|exports?|downloads?|logs?|debug|configs?|private|internal)(/|$|[?#])' urls.txt >> sensitive_file_candidates.txt
        grep -Ei '([?&](next|url|redirect|redirect_uri|redirect_url|return|returnUrl|return_url|callback|continue|dest|destination)=)' urls.txt >> open_redirect_candidates.txt
        grep -Ei '(/graphql($|[/?#])|/graphiql($|[/?#]))' urls.txt >> graphql_candidates.txt
        grep -Ei '(s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|firebaseio\.com|supabase\.co)' urls.txt >> bucket_candidates.txt
    fi

    if [ -s authsubs.txt ]; then
        cat authsubs.txt >> cors_candidates.txt
    fi

    if [ -s urls.txt ]; then
        grep -Ei '/(api|graphql|v[0-9]|rest|ajax)(/|$|[?#])' urls.txt >> cors_candidates.txt
    fi

    cap_unique_file sensitive_file_candidates.txt
    cap_unique_file open_redirect_candidates.txt
    cap_unique_file cors_candidates.txt
    cap_unique_file graphql_candidates.txt
    cap_unique_file bucket_candidates.txt
}

cap_unique_file() {
    file="$1"
    [ -f "$file" ] || return
    sort -u "$file" | head -n "$MAX_VALIDATION_TARGETS" > "$file.tmp"
    mv -f "$file.tmp" "$file"
}

run_parallel_file_checks() {
    input_file="$1"
    validator="$2"
    out_prefix="$3"

    [ -s "$input_file" ] || return

    job_count=0
    while IFS= read -r target; do
        [ -z "$target" ] && continue
        job_id=$(printf '%s' "$target" | cksum | awk '{print $1}')
        "$validator" "$target" > "${out_prefix}_${job_id}.jsonl" &
        job_count=$((job_count + 1))

        if [ "$job_count" -ge "$VALIDATOR_PARALLELISM" ]; then
            wait
            job_count=0
        fi
    done < "$input_file"
    wait
}

validate_sensitive_url() {
    url="$1"
    work_id=$(printf '%s' "$url" | cksum | awk '{print $1}')
    header_file="validator_tmp/${work_id}_sensitive_headers.txt"
    body_file="validator_tmp/${work_id}_sensitive_body.txt"

    status=$(curl -ksL --range 0-8191 --connect-timeout 5 --max-time "$CURL_TIMEOUT" -D "$header_file" -o "$body_file" -w '%{http_code}' "$url" 2>/dev/null)
    [ "$status" = "200" ] || return
    [ -s "$body_file" ] || return

    content_type=$(grep -i '^content-type:' "$header_file" | head -n 1 | sed 's/^[Cc]ontent-[Tt]ype:[[:space:]]*//;s/\r//')
    evidence=""
    confidence="high"

    if grep -Eiq '(DB_HOST|DB_PASSWORD|APP_KEY|APP_SECRET|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|PRIVATE KEY|BEGIN RSA|password[[:space:]]*=|api[_-]?key[[:space:]]*=|secret[[:space:]]*=)' "$body_file"; then
        evidence="status 200 with configuration or credential keywords"
        confidence="confirmed"
    elif printf '%s\n' "$url" | grep -Eiq '\.(zip|tar|tgz|tar\.gz|7z|rar|sql|db|sqlite|bak|backup|old|log|json|ya?ml|ini|xml|pem|key)([?#].*)?$'; then
        evidence="status 200 for sensitive file path; content-type: $content_type"
    else
        return
    fi

    emit_jsonl_finding "exposed_sensitive_file" "$url" "$confidence" "$status" "$evidence"
}

validate_open_redirect_url() {
    url="$1"
    test_url=$(printf '%s' "$url" | sed -E 's#([?&](next|url|redirect|redirect_uri|redirect_url|return|returnUrl|return_url|callback|continue|dest|destination)=)[^&#]*#\1https%3A%2F%2Fexample.com%2F#')
    [ "$test_url" != "$url" ] || return

    header_file="validator_tmp/$(printf '%s' "$url" | cksum | awk '{print $1}')_redirect_headers.txt"
    status=$(curl -ksI --connect-timeout 5 --max-time "$CURL_TIMEOUT" --max-redirs 0 -D "$header_file" -o /dev/null -w '%{http_code}' "$test_url" 2>/dev/null)
    location=$(grep -i '^location:' "$header_file" | head -n 1 | sed 's/^[Ll]ocation:[[:space:]]*//;s/\r//')

    if printf '%s\n' "$location" | grep -Eiq '^https?://example\.com/?'; then
        emit_jsonl_finding "open_redirect" "$test_url" "confirmed" "$status" "Location header redirects to controlled external host"
    fi
}

validate_cors_target() {
    url="$1"
    header_file="validator_tmp/$(printf '%s' "$url" | cksum | awk '{print $1}')_cors_headers.txt"
    status=$(curl -ksI --connect-timeout 5 --max-time "$CURL_TIMEOUT" -H 'Origin: https://evil.example' -D "$header_file" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)
    allow_origin=$(grep -i '^access-control-allow-origin:' "$header_file" | head -n 1 | sed 's/^[Aa]ccess-[Cc]ontrol-[Aa]llow-[Oo]rigin:[[:space:]]*//;s/\r//')
    allow_credentials=$(grep -i '^access-control-allow-credentials:' "$header_file" | head -n 1 | sed 's/^[Aa]ccess-[Cc]ontrol-[Aa]llow-[Cc]redentials:[[:space:]]*//;s/\r//')

    if [ "$allow_origin" = "https://evil.example" ] && printf '%s\n' "$allow_credentials" | grep -Eiq '^true$'; then
        emit_jsonl_finding "cors_origin_reflection_with_credentials" "$url" "confirmed" "$status" "Reflected arbitrary Origin with credentials enabled"
    elif [ "$allow_origin" = "*" ]; then
        emit_jsonl_finding "cors_wildcard_origin" "$url" "high" "$status" "Wildcard Access-Control-Allow-Origin observed"
    fi
}

validate_graphql_url() {
    url="$1"
    work_id=$(printf '%s' "$url" | cksum | awk '{print $1}')
    body_file="validator_tmp/${work_id}_graphql_body.txt"
    payload='{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name } } }"}'

    status=$(curl -ks --connect-timeout 5 --max-time "$CURL_TIMEOUT" -H 'Content-Type: application/json' --data "$payload" -o "$body_file" -w '%{http_code}' "$url" 2>/dev/null)
    if [ "$status" = "200" ] && grep -Eq '"__schema"|"queryType"|"types"' "$body_file"; then
        emit_jsonl_finding "graphql_introspection_enabled" "$url" "confirmed" "$status" "GraphQL introspection response contains schema fields"
        return
    fi

    status=$(curl -ksL --connect-timeout 5 --max-time "$CURL_TIMEOUT" -o "$body_file" -w '%{http_code}' "$url" 2>/dev/null)
    if [ "$status" = "200" ] && grep -Eiq '(GraphiQL|GraphQL Playground|Apollo Sandbox|__schema)' "$body_file"; then
        emit_jsonl_finding "graphql_playground_exposed" "$url" "high" "$status" "GraphQL interactive UI or schema marker is reachable"
    fi
}

validate_bucket_url() {
    url="$1"
    work_id=$(printf '%s' "$url" | cksum | awk '{print $1}')
    body_file="validator_tmp/${work_id}_bucket_body.txt"
    status=$(curl -ksL --range 0-8191 --connect-timeout 5 --max-time "$CURL_TIMEOUT" -o "$body_file" -w '%{http_code}' "$url" 2>/dev/null)

    if [ "$status" = "200" ] && grep -Eiq '(<ListBucketResult|<Contents>|<Key>|<Name>|Blob|firebaseio|storage.googleapis.com)' "$body_file"; then
        emit_jsonl_finding "public_cloud_bucket_listing" "$url" "confirmed" "$status" "Cloud storage listing or object metadata is publicly readable"
    elif [ "$status" = "200" ] && printf '%s\n' "$url" | grep -Eiq '(s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|firebaseio\.com)'; then
        emit_jsonl_finding "public_cloud_storage_object" "$url" "high" "$status" "Cloud storage URL returned HTTP 200"
    fi
}

run_takeover_checks() {
    takeover_file="$1"
    confirmed_jsonl="$2"

    if [ ! -s resolved_subdomains.txt ]; then
        close_json_report "$takeover_file"
        return
    fi

    if command -v subzy >/dev/null 2>&1; then
        step "Checking subdomain takeovers with subzy"
        subzy run \
            --targets resolved_subdomains.txt \
            --hide_fails \
            --vuln \
            --concurrency "$VALIDATOR_PARALLELISM" \
            --timeout "$CURL_TIMEOUT" \
            --output "$takeover_file" >/dev/null 2>&1 || warn "subzy completed with findings or warnings."
        parse_subzy_vulnerable_targets "$takeover_file" | while IFS= read -r target; do
            [ -n "$target" ] && emit_jsonl_finding "subdomain_takeover" "$target" "confirmed" "n/a" "subzy marked the host vulnerable" >> "$confirmed_jsonl"
        done
    else
        close_json_report "$takeover_file"
    fi
}

parse_subzy_vulnerable_targets() {
    awk '
        /{/ {
            subdomain = ""
            status = ""
            vulnerable = ""
        }
        /"subdomain"[[:space:]]*:/ {
            line = $0
            sub(/.*"subdomain"[[:space:]]*:[[:space:]]*"/, "", line)
            sub(/".*/, "", line)
            subdomain = line
        }
        /"status"[[:space:]]*:/ {
            line = $0
            sub(/.*"status"[[:space:]]*:[[:space:]]*"/, "", line)
            sub(/".*/, "", line)
            status = line
        }
        /"vulnerable"[[:space:]]*:/ {
            line = $0
            sub(/.*"vulnerable"[[:space:]]*:[[:space:]]*/, "", line)
            sub(/,.*/, "", line)
            vulnerable = line
        }
        /}/ {
            if (subdomain != "" && (status == "vulnerable" || vulnerable == "true")) {
                print subdomain
            }
        }
    ' "$1"
}

emit_jsonl_finding() {
    finding_type="$1"
    source_url="$2"
    confidence="$3"
    status="$4"
    evidence="$5"

    printf '{"type":"%s","source_url":"%s","confidence":"%s","status":"%s","evidence":"%s"}\n' \
        "$(json_escape "$finding_type")" \
        "$(json_escape "$source_url")" \
        "$(json_escape "$confidence")" \
        "$(json_escape "$status")" \
        "$(json_escape "$evidence")"
}

jsonl_to_json_array() {
    input_file="$1"
    output_file="$2"

    printf '[\n' > "$output_file"
    if [ -s "$input_file" ]; then
        awk 'NF { if (seen[$0]++) next; if (count++ > 0) printf ",\n"; printf "  %s", $0 } END { if (count > 0) printf "\n" }' "$input_file" >> "$output_file"
    fi
    printf ']\n' >> "$output_file"
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
    if [ ! -f "$1" ]; then
        printf '0'
        return
    fi

    python3 - "$1" << 'PY' 2>/dev/null || grep -c '"type":' "$1"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8", errors="ignore") as handle:
    data = json.load(handle)

if isinstance(data, list):
    print(len(data))
elif isinstance(data, dict):
    for key in ("findings", "results", "matches", "items"):
        if isinstance(data.get(key), list):
            print(len(data[key]))
            break
    else:
        print(1 if data else 0)
else:
    print(0)
PY
}

count_jsonl_findings() {
    count_lines "$1"
}

run_ai_triage() {
    domain="$1"

    if [ "$AI_ENABLED" != "true" ]; then
        return
    fi

    section "AI-Powered Triage"

    if ! command -v python3 >/dev/null 2>&1; then
        warn "python3 is required for AI triage context generation."
        return
    fi

    mkdir -p reports/ai
    create_ai_context "$domain" "$AI_MAX_FINDINGS" "reports/ai/ai_context.json"
    create_rule_based_ai_reports "$domain" "reports/ai/ai_context.json" "reports/ai/ai_findings.json" "reports/ai/ai_summary.md"

    case "$AI_PROVIDER" in
        openai)
            run_openai_triage "$domain" || warn "OpenAI triage failed; kept local AI summary."
            ;;
        ollama|local)
            run_ollama_triage "$domain" || warn "Ollama triage failed; kept local AI summary."
            ;;
        auto)
            if [ -n "$OPENAI_API_KEY" ]; then
                run_openai_triage "$domain" || warn "OpenAI triage failed; kept local AI summary."
            elif command -v ollama >/dev/null 2>&1; then
                run_ollama_triage "$domain" || warn "Ollama triage failed; kept local AI summary."
            else
                success "Local AI-style triage saved to reports/ai/ai_summary.md"
            fi
            ;;
        rules|rule|offline)
            success "Local AI-style triage saved to reports/ai/ai_summary.md"
            ;;
        *)
            warn "Unknown AI provider '$AI_PROVIDER'. Kept local AI summary."
            ;;
    esac
}

create_ai_context() {
    domain="$1"
    max_findings="$2"
    output_file="$3"

    python3 - "$domain" "$max_findings" "$output_file" << 'PY'
import json
import os
import re
import sys

domain, max_findings, output_file = sys.argv[1], int(sys.argv[2]), sys.argv[3]
reports_dir = "reports"
findings_dir = os.path.join(reports_dir, "findings")
urls_dir = os.path.join(reports_dir, "urls")
js_dir = os.path.join(reports_dir, "js")
pd_dir = os.path.join(reports_dir, "pd")

DROP_KEYS = {
    "match", "secret", "raw", "raw_request", "raw_response", "request", "response",
    "curl-command", "curl_command", "extracted-results", "extracted_results",
    "matcher-status", "matcher_status", "template-url", "template_url",
}

SENSITIVE_QUERY_RE = re.compile(
    r"(?i)([?&][^=\s&]*(?:token|secret|password|passwd|pwd|api[_-]?key|apikey|client[_-]?secret|session|sid|jwt)[^=\s&]*=)[^&#\s]+"
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)((?:token|secret|password|passwd|pwd|api[_-]?key|apikey|client[_-]?secret|jwt)[\"']?\s*[:=]\s*[\"']?)[^\"'\s,}]+"
)

def sanitize_text(value):
    value = SENSITIVE_QUERY_RE.sub(r"\1[omitted]", value)
    value = SENSITIVE_ASSIGNMENT_RE.sub(r"\1[omitted]", value)
    if len(value) > 700:
        value = value[:700] + "...[truncated]"
    return value

def safe_value(value):
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in DROP_KEYS or any(token in lowered for token in ("secret", "password", "token", "apikey", "api_key")):
                if "hash" in lowered or "length" in lowered:
                    cleaned[key] = item
                else:
                    cleaned[key] = "[omitted]"
            else:
                cleaned[key] = safe_value(item)
        return cleaned
    if isinstance(value, list):
        return [safe_value(item) for item in value[:max_findings]]
    if isinstance(value, str):
        return sanitize_text(value)
    return value

def load_json(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            data = json.load(handle)
    except Exception:
        return []
    if data is None:
        return []
    if isinstance(data, list):
        return [safe_value(item) for item in data[:max_findings]]
    return [safe_value(data)]

def load_jsonl(path):
    rows = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(safe_value(json.loads(line)))
                except Exception:
                    rows.append({"line": sanitize_text(line)})
                if len(rows) >= max_findings:
                    break
    except FileNotFoundError:
        pass
    return rows

def count_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return sum(1 for _ in handle)
    except FileNotFoundError:
        return 0

def sample_text(path, limit=25):
    rows = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    rows.append(sanitize_text(line))
                if len(rows) >= limit:
                    break
    except FileNotFoundError:
        pass
    return rows

context = {
    "target": domain,
    "note": "Secret-like values, raw requests, raw responses, and long bodies are omitted before AI triage.",
    "counts": {
        "subdomains": count_lines("raw/subdomains.txt"),
        "resolved_domains": count_lines("raw/resolved_subdomains.txt"),
        "live_hosts": count_lines("raw/authsubs.txt"),
        "urls": count_lines("raw/urls.txt"),
        "live_js": count_lines("raw/authjs_files.txt"),
        "live_json": count_lines("raw/authjson_files.txt"),
    },
    "confirmed_findings": load_json(os.path.join(findings_dir, "confirmed_findings.json")),
    "nuclei_findings": load_jsonl(os.path.join(pd_dir, "nuclei_findings.jsonl")),
    "nuclei_potential_url_findings": load_jsonl(os.path.join(pd_dir, "nuclei_potential_url_findings.jsonl")),
    "js_vulnerability_indicators": load_json(os.path.join(js_dir, "js_vulnerability_findings.json")),
    "genuine_leak_metadata": load_json(os.path.join(js_dir, "genuine_leaks.json")),
    "generic_key_metadata": load_json(os.path.join(js_dir, "generic_api_keys.json")),
    "smart_sensitive_files": load_json(os.path.join(urls_dir, "smart_sensitive_files.json")),
    "smart_secret_urls": load_json(os.path.join(urls_dir, "smart_secret_urls.json")),
    "url_info_disclosure_samples": sample_text(os.path.join(urls_dir, "url_info_disclosure.txt")),
}

with open(output_file, "w", encoding="utf-8") as handle:
    json.dump(context, handle, indent=2)
    handle.write("\n")
PY
}

create_rule_based_ai_reports() {
    domain="$1"
    context_file="$2"
    findings_file="$3"
    summary_file="$4"

    python3 - "$domain" "$context_file" "$findings_file" "$summary_file" << 'PY'
import json
import sys
from collections import Counter

domain, context_file, findings_file, summary_file = sys.argv[1:5]

with open(context_file, "r", encoding="utf-8") as handle:
    context = json.load(handle)

weights = {
    "subdomain_takeover": 100,
    "open_redirect": 82,
    "cors_origin_reflection_with_credentials": 78,
    "graphql_introspection_enabled": 76,
    "public_cloud_bucket_listing": 88,
    "exposed_sensitive_file": 86,
}

def severity(score):
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"

ranked = []
for item in context.get("confirmed_findings", []):
    kind = item.get("type", "finding")
    score = weights.get(kind, 60)
    if item.get("confidence") == "confirmed":
        score += 8
    ranked.append({
        "title": kind.replace("_", " ").title(),
        "type": kind,
        "severity": severity(score),
        "score": min(score, 100),
        "confidence": item.get("confidence", "unknown"),
        "source_url": item.get("source_url", ""),
        "evidence": item.get("evidence", ""),
        "recommended_next_step": "Manually reproduce the finding, capture request/response proof, and verify program scope before reporting."
    })

for item in context.get("nuclei_findings", [])[:20]:
    info = item.get("info", {}) if isinstance(item, dict) else {}
    sev = str(info.get("severity", "medium")).lower()
    base = {"critical": 88, "high": 75, "medium": 55, "low": 35}.get(sev, 45)
    ranked.append({
        "title": info.get("name", item.get("template-id", "Nuclei finding")),
        "type": "nuclei",
        "severity": sev,
        "score": base,
        "confidence": "template-match",
        "source_url": item.get("matched-at", item.get("host", "")),
        "evidence": item.get("template-id", ""),
        "recommended_next_step": "Validate the template result manually and collect clean reproduction evidence."
    })

ranked = sorted(ranked, key=lambda item: item["score"], reverse=True)
with open(findings_file, "w", encoding="utf-8") as handle:
    json.dump(ranked, handle, indent=2)
    handle.write("\n")

counts = context.get("counts", {})
type_counts = Counter(item["type"] for item in ranked)

lines = [
    f"# ReconRaptor AI Triage Summary for {domain}",
    "",
    "## Scan Shape",
    f"- Live hosts: {counts.get('live_hosts', 0)}",
    f"- URLs collected: {counts.get('urls', 0)}",
    f"- Live JavaScript files: {counts.get('live_js', 0)}",
    f"- Confirmed or high-signal findings: {len(ranked)}",
    "",
    "## Highest Priority Findings",
]

if ranked:
    for item in ranked[:10]:
        lines.append(f"- {item['severity'].upper()} | {item['title']} | {item.get('source_url', '')}")
        if item.get("evidence"):
            lines.append(f"  Evidence: {item['evidence']}")
else:
    lines.append("- No confirmed findings were available for AI triage.")

lines.extend([
    "",
    "## Finding Groups",
])

if type_counts:
    for kind, count in type_counts.most_common():
        lines.append(f"- {kind}: {count}")
else:
    lines.append("- No groups available.")

lines.extend([
    "",
    "## Suggested Manual Testing",
    "- Reproduce confirmed findings from a clean browser or curl session.",
    "- Prioritize exposed files, takeover, cloud storage, GraphQL introspection, and CORS with credentials.",
    "- Treat generic JS indicators as leads unless a validator or manual test confirms impact.",
    "",
    "## Data Handling",
    "- This local summary was generated from ai_context.json, which omits raw secret-like values and large bodies.",
])

with open(summary_file, "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n")
PY
}

run_openai_triage() {
    domain="$1"

    if [ -z "$OPENAI_API_KEY" ]; then
        warn "OPENAI_API_KEY is not set. Skipping OpenAI triage."
        return 1
    fi

    step "Running OpenAI triage with $OPENAI_MODEL"
    build_openai_payload "$domain" "reports/ai/ai_context.json" "reports/ai/ai_openai_request.json"

    if ! curl -fsS https://api.openai.com/v1/responses \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -H "Content-Type: application/json" \
        -d @reports/ai/ai_openai_request.json \
        -o reports/ai/ai_openai_response.json; then
        return 1
    fi

    extract_ai_text "reports/ai/ai_openai_response.json" "reports/ai/ai_summary.md"
    success "OpenAI triage saved to reports/ai/ai_summary.md"
}

build_openai_payload() {
    domain="$1"
    context_file="$2"
    output_file="$3"

    python3 - "$domain" "$context_file" "$output_file" "$OPENAI_MODEL" << 'PY'
import json
import sys

domain, context_file, output_file, model = sys.argv[1:5]

with open(context_file, "r", encoding="utf-8") as handle:
    context = json.load(handle)

prompt = f"""You are helping triage an authorized security recon scan for {domain}.

Use only the sanitized JSON context below. Do not invent findings. Do not ask to exploit anything.
Create a concise bug-bounty triage report in Markdown with:
1. Executive summary
2. Top confirmed findings ranked by severity
3. Likely false positives or weak leads
4. Duplicate/root-cause grouping
5. Manual reproduction checklist
6. Report-ready wording for the highest-impact confirmed issues

Sanitized context:
{json.dumps(context, indent=2)}
"""

payload = {
    "model": model,
    "input": prompt,
    "max_output_tokens": 2500
}

with open(output_file, "w", encoding="utf-8") as handle:
    json.dump(payload, handle)
    handle.write("\n")
PY
}

extract_ai_text() {
    response_file="$1"
    output_file="$2"

    python3 - "$response_file" "$output_file" << 'PY'
import json
import sys

response_file, output_file = sys.argv[1:3]
with open(response_file, "r", encoding="utf-8") as handle:
    data = json.load(handle)

text = data.get("output_text", "")
if not text:
    parts = []
    for item in data.get("output", []):
        for content in item.get("content", []):
            if content.get("type") in {"output_text", "text"} and content.get("text"):
                parts.append(content["text"])
    text = "\n".join(parts)

if not text and data.get("error"):
    text = "# ReconRaptor AI Triage Failed\n\n" + json.dumps(data["error"], indent=2)

with open(output_file, "w", encoding="utf-8") as handle:
    handle.write(text.strip() + "\n")
PY
}

run_ollama_triage() {
    domain="$1"

    if ! command -v ollama >/dev/null 2>&1; then
        warn "ollama is not installed. Skipping local model triage."
        return 1
    fi

    step "Running local Ollama triage with $OLLAMA_MODEL"
    build_ollama_payload "$domain" "reports/ai/ai_context.json" "reports/ai/ai_ollama_request.json"

    if ! curl -fsS http://127.0.0.1:11434/api/generate \
        -H "Content-Type: application/json" \
        -d @reports/ai/ai_ollama_request.json \
        -o reports/ai/ai_ollama_response.json; then
        return 1
    fi

    python3 - "reports/ai/ai_ollama_response.json" "reports/ai/ai_summary.md" << 'PY'
import json
import sys

response_file, output_file = sys.argv[1:3]
with open(response_file, "r", encoding="utf-8", errors="ignore") as handle:
    data = json.load(handle)
with open(output_file, "w", encoding="utf-8") as handle:
    handle.write(data.get("response", "").strip() + "\n")
PY
    success "Ollama triage saved to reports/ai/ai_summary.md"
}

build_ollama_payload() {
    domain="$1"
    context_file="$2"
    output_file="$3"

    python3 - "$domain" "$context_file" "$output_file" "$OLLAMA_MODEL" << 'PY'
import json
import sys

domain, context_file, output_file, model = sys.argv[1:5]
with open(context_file, "r", encoding="utf-8") as handle:
    context = json.load(handle)

prompt = f"""Triage this authorized recon scan for {domain}. Use only this sanitized context.
Rank confirmed findings, call out likely false positives, group duplicates, and give concise manual validation steps.

{json.dumps(context, indent=2)}
"""

with open(output_file, "w", encoding="utf-8") as handle:
    json.dump({"model": model, "prompt": prompt, "stream": False}, handle)
    handle.write("\n")
PY
}

organize_output() {
    mkdir -p raw reports/findings reports/urls reports/js reports/pd reports/candidates evidence

    for file in subdomains.txt resolved_subdomains.txt authsubs.txt unauthsubs.txt urls.txt js_files.txt json_files.txt authjs_files.txt authjson_files.txt; do
        [ -f "$file" ] && mv -f "$file" "raw/$file"
    done

    for file in confirmed_findings.json confirmed_findings.jsonl confirmed_findings_summary.txt subdomain_takeover_findings.json; do
        [ -f "$file" ] && mv -f "$file" "reports/findings/$file"
    done

    for file in url_info_disclosure.txt url_regex_dictionary.txt smart_sensitive_files.json smart_secret_urls.json smart_url_filter_dictionary.txt; do
        [ -f "$file" ] && mv -f "$file" "reports/urls/$file"
    done

    for file in generic_api_keys.json genuine_leaks.json gitleaks_report.json js_vulnerability_findings.json js_regex_dictionary.txt js_secret_summary.txt; do
        [ -f "$file" ] && mv -f "$file" "reports/js/$file"
    done

    for file in nuclei_findings.jsonl nuclei_potential_url_findings.jsonl tls_findings.jsonl; do
        [ -f "$file" ] && mv -f "$file" "reports/pd/$file"
    done

    for file in sensitive_file_candidates.txt open_redirect_candidates.txt cors_candidates.txt graphql_candidates.txt bucket_candidates.txt potential_vuln_urls.txt; do
        [ -f "$file" ] && mv -f "$file" "reports/candidates/$file"
    done

    [ -f downloaded_js_map.txt ] && mv -f downloaded_js_map.txt evidence/downloaded_js_map.txt
    [ -d downloaded_js ] && mv -f downloaded_js evidence/downloaded_js
    [ -d validator_tmp ] && mv -f validator_tmp evidence/validator_tmp
}

write_result_index() {
    domain="$1"
    index_file="START_HERE.md"

    {
        printf '# ReconRaptor AI results for %s\n\n' "$domain"
        printf 'Start with this short list, then open the folder that matches what you want to review.\n\n'
        printf '## Start here\n\n'
        if [ "$AI_ENABLED" = "true" ]; then
            printf '1. AI triage: `reports/ai/ai_summary.md`\n'
        fi
        printf '1. Confirmed findings: `reports/findings/confirmed_findings.json`\n'
        printf '2. URL exposure leads: `reports/urls/`\n'
        printf '3. JavaScript secrets and client-side indicators: `reports/js/`\n'
        printf '4. Nuclei and TLS checks: `reports/pd/`\n'
        printf '5. Raw discovery data: `raw/`\n'
        printf '6. Downloaded JS and validator evidence: `evidence/`\n\n'

        printf '## Counts\n\n'
        printf '| Item | Count |\n'
        printf '| --- | ---: |\n'
        printf '| Live hosts | %s |\n' "$(count_lines raw/authsubs.txt)"
        printf '| URLs collected | %s |\n' "$(count_lines raw/urls.txt)"
        printf '| Confirmed findings | %s |\n' "$(count_json_findings reports/findings/confirmed_findings.json)"
        printf '| URL disclosure leads | %s |\n' "$(count_lines reports/urls/url_info_disclosure.txt)"
        printf '| Smart sensitive files | %s |\n' "$(count_json_findings reports/urls/smart_sensitive_files.json)"
        printf '| Smart URL secrets | %s |\n' "$(count_json_findings reports/urls/smart_secret_urls.json)"
        printf '| Genuine JS leaks | %s |\n' "$(count_json_findings reports/js/genuine_leaks.json)"
        printf '| JS indicators | %s |\n' "$(count_json_findings reports/js/js_vulnerability_findings.json)"
        printf '| Nuclei findings | %s |\n' "$(count_jsonl_findings reports/pd/nuclei_findings.jsonl)"
        printf '| Focused Nuclei findings | %s |\n' "$(count_jsonl_findings reports/pd/nuclei_potential_url_findings.jsonl)"
        if [ "$AI_ENABLED" = "true" ]; then
            printf '| AI-ranked findings | %s |\n' "$(count_json_findings reports/ai/ai_findings.json)"
        fi

        printf '\n## Folder guide\n\n'
        printf '| Folder | What is inside |\n'
        printf '| --- | --- |\n'
        printf '| `reports/findings/` | Confirmed or high-confidence validator output |\n'
        printf '| `reports/ai/` | AI context, ranked findings, and triage summary |\n'
        printf '| `reports/urls/` | URL-based exposure leads and dictionaries |\n'
        printf '| `reports/js/` | JavaScript secret scans and client-side indicators |\n'
        printf '| `reports/pd/` | Nuclei and TLS output |\n'
        printf '| `reports/candidates/` | Candidate URLs checked by validators |\n'
        printf '| `raw/` | Subdomains, live hosts, URLs, JS and JSON lists |\n'
        printf '| `evidence/` | Downloaded JS and temporary validator evidence |\n\n'

        printf 'Treat AI and scanner output as triage. Reproduce findings manually before reporting.\n'
    } > "$index_file"
}

print_summary() {
    domain="$1"
    subdomains_count=$(count_lines raw/subdomains.txt)
    resolved_count=$(count_lines raw/resolved_subdomains.txt)
    live_count=$(count_lines raw/authsubs.txt)
    non_live_count=$(count_lines raw/unauthsubs.txt)
    urls_count=$(count_lines raw/urls.txt)
    url_disclosures_count=$(count_lines reports/urls/url_info_disclosure.txt)
    smart_files_count=$(count_json_findings reports/urls/smart_sensitive_files.json)
    smart_url_secrets_count=$(count_json_findings reports/urls/smart_secret_urls.json)
    confirmed_count=$(count_json_findings reports/findings/confirmed_findings.json)
    live_js_count=$(count_lines raw/authjs_files.txt)
    live_json_count=$(count_lines raw/authjson_files.txt)
    generic_keys_count=$(count_json_findings reports/js/generic_api_keys.json)
    genuine_leaks_count=$(count_json_findings reports/js/genuine_leaks.json)
    js_indicators_count=$(count_json_findings reports/js/js_vulnerability_findings.json)
    nuclei_count=$(count_jsonl_findings reports/pd/nuclei_findings.jsonl)
    potential_nuclei_count=$(count_jsonl_findings reports/pd/nuclei_potential_url_findings.jsonl)
    tls_count=$(count_jsonl_findings reports/pd/tls_findings.jsonl)

    section "Scan Summary"

    summary_group "Target coverage"
    summary_row "Subdomains found" "$subdomains_count"
    summary_row "Resolved domains" "$resolved_count"
    summary_row "Live hosts" "$live_count"
    summary_row "Non-live hosts" "$non_live_count"
    summary_row "URLs collected" "$urls_count"

    summary_group "Finding signals"
    summary_row "Confirmed findings" "$confirmed_count"
    summary_row "URL disclosure leads" "$url_disclosures_count"
    summary_row "Sensitive file matches" "$smart_files_count"
    summary_row "Secret URLs" "$smart_url_secrets_count"
    summary_row "Nuclei findings" "$nuclei_count"
    summary_row "Focused Nuclei findings" "$potential_nuclei_count"

    summary_group "JavaScript analysis"
    summary_row "Live JS files" "$live_js_count"
    summary_row "Live JSON files" "$live_json_count"
    summary_row "Generic API keys" "$generic_keys_count"
    summary_row "Genuine leaks" "$genuine_leaks_count"
    summary_row "Client-side indicators" "$js_indicators_count"
    summary_row "TLS records" "$tls_count"

    if [ "$AI_ENABLED" = "true" ]; then
        summary_group "AI triage"
        summary_row "AI-ranked findings" "$(count_json_findings reports/ai/ai_findings.json)"
    fi

    summary_group "Where to go next"
    summary_path "Directory" "recon_$domain"
    summary_path "Start here" "START_HERE.md"
    summary_path "Confirmed" "reports/findings/confirmed_findings.json"
    summary_path "URL reports" "reports/urls/"
    summary_path "JS reports" "reports/js/"
    summary_path "PD reports" "reports/pd/"
    summary_path "Candidates" "reports/candidates/"
    summary_path "Evidence" "evidence/"
    if [ "$AI_ENABLED" = "true" ]; then
        summary_path "AI report" "reports/ai/ai_summary.md"
    fi
}

# Recon start
recon() {
    section "Target: $1"
    mkdir -p "recon_$1"
    cd "recon_$1" || exit 1
    print_run_profile "$1"

    section "Subdomain Discovery"
    step "Finding subdomains"
    subfinder -d "$1" -silent > subdomains.txt
    success "Saved $(count_lines subdomains.txt) subdomains to subdomains.txt"

    step "Resolving subdomains with dnsx"
    dnsx -l subdomains.txt -retry 1 -silent > resolved_subdomains.txt
    if [ ! -s resolved_subdomains.txt ]; then
        warn "dnsx found no resolved subdomains; falling back to raw subdomain list."
        cp subdomains.txt resolved_subdomains.txt
    fi
    success "Saved $(count_lines resolved_subdomains.txt) resolved subdomains to resolved_subdomains.txt"

    step "Checking live domains"
    cat resolved_subdomains.txt | httpx -silent -threads 50 -mc 200 > authsubs.txt
    success "Saved $(count_lines authsubs.txt) live domains to authsubs.txt"

    step "Checking non-live domains"
    cat resolved_subdomains.txt | httpx -silent -threads 50 -mc 400,401,402,403,404 > unauthsubs.txt
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
    katana -list authsubs.txt -c 20 -d 2 -silent >> urls.txt

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
    cat js_files.txt | httpx -silent -threads 50 -mc 200 > authjs_files.txt
    cat json_files.txt | httpx -silent -threads 50 -mc 200 > authjson_files.txt
    success "Validated $(count_lines authjs_files.txt) live JS files and $(count_lines authjson_files.txt) live JSON files"

    section "Secret Analysis"
    download_js_files "authjs_files.txt"
    scan_js_secrets

    section "ProjectDiscovery Checks"
    run_projectdiscovery_checks

    section "Confirmed Validators"
    run_confirmed_validators "$1"

    organize_output
    run_ai_triage "$1"
    write_result_index "$1"
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
        -F "payload_json={\"content\":\"ReconRaptor AI scan report for $1\"}" \
        "$2" >/dev/null; then
        success "Discord upload complete."
    else
        fail "Discord upload failed. Check the webhook URL and network connection."
        return 1
    fi
}

usage() {
    banner
    printf '\n%bUsage%b\n' "$BOLD" "$RESET"
    printf '  %s -d <domain> [options]\n\n' "$0"
    printf '%bOptions%b\n' "$BOLD" "$RESET"
    printf '  %-30s %s\n' '-d, --domain <domain>' 'Target domain to scan'
    printf '  %-30s %s\n' '-w, --webhook <url>' 'Upload the final zip to Discord'
    printf '  %-30s %s\n' '--ai' 'Enable AI-powered triage'
    printf '  %-30s %s\n' '--ai-provider <mode>' 'auto, openai, ollama, or rules'
    printf '  %-30s %s\n' '--ai-model <model>' 'Model name for OpenAI or Ollama'
    printf '  %-30s %s\n' '-h, --help' 'Show this help screen'
    printf '\n%bExamples%b\n' "$BOLD" "$RESET"
    printf '  %s -d example.com\n' "$0"
    printf '  %s -d example.com --ai --ai-provider ollama --ai-model llama3.2:3b\n' "$0"
}

# Args parsing
domain=""
webhook=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    -d|--domain)
        if [ -z "${2:-}" ]; then usage; exit 1; fi
        domain="$2"
        shift 2
        ;;
    -w|--webhook)
        if [ -z "${2:-}" ]; then usage; exit 1; fi
        webhook="$2"
        shift 2
        ;;
    --ai)
        AI_ENABLED="true"
        shift
        ;;
    --ai-provider)
        if [ -z "${2:-}" ]; then usage; exit 1; fi
        AI_PROVIDER="$2"
        shift 2
        ;;
    --ai-model)
        if [ -z "${2:-}" ]; then usage; exit 1; fi
        OPENAI_MODEL="$2"
        OLLAMA_MODEL="$2"
        shift 2
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage
        exit 1
        ;;
  esac
done

if [ -z "$domain" ]; then
    fail "Please provide a domain using -d option."
    usage
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

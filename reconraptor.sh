#!/bin/bash

# Colors. Use printf-friendly ANSI escapes so shells do not print "\e[32m" literally.
ESC=$(printf '\033')
RED="${ESC}[31m"
GREEN="${ESC}[32m"
CYAN="${ESC}[36m"
RESET="${ESC}[0m"

info() {
    printf '%b%s%b\n' "$1" "$2" "$RESET"
}

banner() {
printf '%b' "$CYAN"
cat << "EOF"

 ____                            ____              _
|  _ \ ___  ___ ___  _ __      |  _ \ __ _ _ __ | |_ ___  _ __
| |_) / _ \/ __/ _ \| '_ \_____| |_) / _` | '_ \| __/ _ \| '__|
|  _ <  __/ (_| (_) | | | |____|  _ < (_| | |_) | || (_) | |
|_| \_\___|\___\___/|_| |_|    |_| \_\__,_| .__/ \__\___/|_|
                                           |_|

EOF
printf '%b' "$RESET"
}

# Requirements check
check_installed() {
    for tool in subfinder httpx waybackurls curl; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            info "$RED" "[-] $tool is not installed! Please run ./install.sh"
            exit 1
        fi
    done
}

# Recon start
recon() {
    info "$CYAN" "[*] Starting Recon on $1..."
    mkdir -p "recon_$1"
    cd "recon_$1" || exit 1

    info "$GREEN" "[*] Finding subdomains..."
    subfinder -d "$1" -silent > subdomains.txt

    info "$GREEN" "[*] Checking live domains..."
    cat subdomains.txt | httpx -silent -mc 200 > authsubs.txt

    info "$GREEN" "[*] Checking domains which are not live..."
    cat subdomains.txt | httpx -silent -mc 400,401,402,403,404 > unauthsubs.txt
    
    subfile="authsubs.txt"
    LINE_COUNT=$(wc -l < "authsubs.txt")
    if [ "$LINE_COUNT" -gt 20 ]; then
        info "$RED" "[!] $1 has alot of subdomains so the whole recon may take time, please keep paitents or else don't have a check up......"
    else
        info "$RED" "[+] $1 has Fewer Subdomains so it can be quick enjoy.........."
    fi

    printf '.\n'

    info "$GREEN" "[*] Fetching waybackurls..."
    cat authsubs.txt | waybackurls > urls.txt

    subfile="unauthsubs.txt"
    LINE_COUNT=$(wc -l < "unauthsubs.txt")
    if [ "$LINE_COUNT" -gt 20 ]; then
        info "$RED" "[!] $1 has alot of subdomains so the whole recon may take time, please keep paitents or else don't have a check up......"
    else
        info "$RED" "[+] $1 has Fewer Subdomains so it can be quick enjoy.........."
    fi

    printf '.\n'

    info "$GREEN" "[*] Fetching waybackurls..."
    cat unauthsubs.txt | waybackurls >> urls.txt

    info "$GREEN" "[*] Extracting JS & JSON files..."
    grep -E "\.js$" urls.txt > js_files.txt
    grep -E "\.json$" urls.txt > json_files.txt
    info "$RED" "[*] You are almost there..."
    printf '.\n'
    info "$GREEN" "[*] Validating the JS & JSON files..."

    cat js_files.txt | httpx -silent -mc 200 > authjs_files.txt
    cat json_files.txt | httpx -silent -mc 200 > authjson_files.txt

    info "$CYAN" "[+] Recon Complete. Results in recon_$1 directory."
}

# Discord Upload
upload_discord() {
    info "$CYAN" "[*] Uploading results to Discord..."
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
    info "$RED" "[!] Please provide a domain using -d option."
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

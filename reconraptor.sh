#!/bin/bash

# Colors
RED="\e[31m"
GREEN="\e[32m"
CYAN="\e[36m"
RESET="\e[0m"

banner() {
cat << "EOF"

██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                                                                             
EOF
}

# Requirements check
check_installed() {
    for tool in subfinder httpx waybackurls curl; do
        if ! command -v $tool &> /dev/null; then
            echo -e "${RED}[-] $tool is not installed! Please run ./install.sh${RESET}"
            exit 1
        fi
    done
}

# Recon start
recon() {
    echo -e "${CYAN}🚀 Starting Recon on $1...${RESET}"
    mkdir -p recon_$1
    cd recon_$1

    echo -e "${GREEN}🔍 Finding subdomains...${RESET}"
    subfinder -d $1 -silent > subdomains.txt

    echo -e "${GREEN}🌐 Checking live domains...${RESET}"
    cat subdomains.txt | httpx -silent -mc 200 > live.txt

    echo -e "${GREEN}📜 Fetching waybackurls...${RESET}"
    cat live.txt | waybackurls > urls.txt

    echo -e "${GREEN}📁 Extracting JS & JSON files...${RESET}"
    grep -E "\.js$" urls.txt > js_files.txt
    grep -E "\.json$" urls.txt > json_files.txt

    echo -e "${CYAN}✅ Recon Complete. Results in recon_$1 directory.${RESET}"
}

# Discord Upload
upload_discord() {
    echo -e "${CYAN}📤 Uploading results to Discord...${RESET}"
    zip -r results_$1.zip recon_$1/
    curl -X POST -F "file=@results_$1.zip" -F "payload_json={\"content\":\"📡 ReconRaptor Scan Report for *$1*\"}" $2
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

if [[ -z "$domain" ]]; then
    echo -e "${RED}❌ Please provide a domain using -d option.${RESET}"
    exit 1
fi

clear
banner
check_installed
recon "$domain"

if [[ ! -z "$webhook" ]]; then
    upload_discord "$domain" "$webhook"
fi

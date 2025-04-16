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
    cat subdomains.txt | httpx -silent -mc 200 > authsubs.txt

    echo -e "${GREEN}🌐 Checking domains which are not live...${RESET}"
    cat subdomains.txt | httpx -silent -mc 400,401,402,403,404 > unauthsubs.txt
    
    subfile="authsubs.txt"
    LINE_COUNT=$(wc -l < "authsubs.txt")
    if [ "$LINE_COUNT" -gt 20 ]; then
        echo -e "${RED}📁 $1 has alot of subdomains so the whole recon may take time, please keep paitents or else don't have a check up......${RESET}"
    else
        echo -e "${RED}📁 $1 has Fewer Subdomains so it can be quick enjoy.......... ${RESET}"
    fi

    echo .

    echo -e "${GREEN}📜 Fetching waybackurls...${RESET}"
    cat authsubs.txt | waybackurls > urls.txt

    subfile="unauthsubs.txt"
    LINE_COUNT=$(wc -l < "unauthsubs.txt")
    if [ "$LINE_COUNT" -gt 20 ]; then
        echo -e "${RED}📁 $1 has alot of subdomains so the whole recon may take time, please keep paitents or else don't have a check up......${RESET}"
    else
        echo -e "${RED}📁 $1 has Fewer Subdomains so it can be quick enjoy.......... ${RESET}"
    fi

    echo .

    echo -e "${GREEN}📜 Fetching waybackurls...${RESET}"
    cat unauthsubs.txt | waybackurls >> urls.txt

    echo -e "${GREEN}📁 Extracting JS & JSON files...${RESET}"
    grep -E "\.js$" urls.txt > js_files.txt
    grep -E "\.json$" urls.txt > json_files.txt
    echo -e "${RED}📁 You are almost there...${RESET}"
    echo .
    echo -e "${GREEN}📁 Validating the JS & JSON files...${RESET}" 

    cat js_files.txt | httpx -silent -mc 200 > authjs_files.txt
    cat json_files.txt | httpx -silent -mc 200 > authjson_files.txt

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

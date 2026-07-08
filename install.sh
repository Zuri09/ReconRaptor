#!/bin/bash

set -e

echo "[*] Checking dependencies..."

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Go if missing
if ! command_exists go; then
    echo "[*] Installing Go..."

    if command_exists wget; then
        wget https://golang.org/dl/go1.21.1.linux-amd64.tar.gz
    elif command_exists curl; then
        curl -LO https://golang.org/dl/go1.21.1.linux-amd64.tar.gz
    else
        echo "[!] wget or curl is required to download Go."
        exit 1
    fi

    sudo tar -C /usr/local -xzf go1.21.1.linux-amd64.tar.gz
    export PATH="$PATH:/usr/local/go/bin"
    rm go1.21.1.linux-amd64.tar.gz
else
    echo "[OK] Go is already installed"
fi

GO_BIN="$(go env GOPATH)/bin"
export PATH="$PATH:$GO_BIN"

for profile in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$profile" ] && ! grep -q 'go env GOPATH' "$profile"; then
        printf '\nexport PATH="$PATH:$(go env GOPATH)/bin"\n' >> "$profile"
    fi
done

# Install tools
echo "[*] Installing subfinder, httpx, katana, waybackurls, and gitleaks..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/zricethezav/gitleaks/v8@latest

echo "[*] Verifying installed tools..."
for tool in subfinder httpx katana waybackurls gitleaks; do
    if command_exists "$tool"; then
        echo "[OK] $tool installed"
    else
        echo "[!] $tool installed, but it is not in PATH yet."
    fi
done

echo "Add this to your shell profile if any tool is not found after restarting your terminal:"
echo "export PATH=\$PATH:$GO_BIN"

echo "[OK] All tools installed. You can now run ./reconraptor.sh -d target.com"

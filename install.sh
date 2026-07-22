#!/bin/bash

set -e

GO_VERSION="1.24.2"
INSTALL_OLLAMA=false
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.2:3b}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --with-ollama)
            INSTALL_OLLAMA=true
            shift
            ;;
        --ollama-model)
            if [ -z "${2:-}" ]; then
                echo "Usage: $0 [--with-ollama] [--ollama-model <model>]"
                exit 1
            fi
            OLLAMA_MODEL="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--with-ollama] [--ollama-model <model>]"
            exit 0
            ;;
        *)
            echo "Usage: $0 [--with-ollama] [--ollama-model <model>]"
            exit 1
            ;;
    esac
done

echo "[*] Checking dependencies..."

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Go if missing
if ! command_exists go; then
    echo "[*] Installing Go..."
    os_name=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch_name=$(uname -m)

    case "$arch_name" in
        x86_64) arch_name="amd64" ;;
        arm64|aarch64) arch_name="arm64" ;;
        *)
            echo "[!] Unsupported architecture: $arch_name"
            exit 1
            ;;
    esac

    go_archive="go${GO_VERSION}.${os_name}-${arch_name}.tar.gz"
    go_url="https://go.dev/dl/$go_archive"

    if command_exists wget; then
        wget "$go_url"
    elif command_exists curl; then
        curl -LO "$go_url"
    else
        echo "[!] wget or curl is required to download Go."
        exit 1
    fi

    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "$go_archive"
    export PATH="$PATH:/usr/local/go/bin"
    rm "$go_archive"
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
echo "[*] Installing subfinder, dnsx, httpx, katana, nuclei, tlsx, subzy, waybackurls, and gitleaks..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/PentestPad/subzy@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/zricethezav/gitleaks/v8@latest

echo "[*] Verifying installed tools..."
for tool in subfinder dnsx httpx katana nuclei tlsx subzy waybackurls gitleaks; do
    if command_exists "$tool"; then
        echo "[OK] $tool installed"
    else
        echo "[!] $tool installed, but it is not in PATH yet."
    fi
done

if [ "$INSTALL_OLLAMA" = true ]; then
    echo "[*] Setting up Ollama for local AI triage..."

    if ! command_exists ollama; then
        if command_exists brew; then
            brew install ollama
        else
            echo "[!] Homebrew is required to install Ollama automatically on macOS."
            echo "    Install Ollama manually from https://ollama.com/download and rerun this command."
            exit 1
        fi
    else
        echo "[OK] Ollama is already installed"
    fi

    if command_exists brew; then
        brew services start ollama >/dev/null 2>&1 || true
    fi

    echo "[*] Pulling Ollama model: $OLLAMA_MODEL"
    ollama pull "$OLLAMA_MODEL"
    echo "[OK] Ollama is ready. Use: ./reconraptor.sh -d target.com --ai --ai-provider ollama"
fi

echo "Add this to your shell profile if any tool is not found after restarting your terminal:"
echo "export PATH=\$PATH:$GO_BIN"

echo "[OK] All tools installed. You can now run ./reconraptor.sh -d target.com"

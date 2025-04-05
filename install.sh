#!/bin/bash

echo "🔧 Checking dependencies..."

# Install Go if missing
if ! command -v go &> /dev/null; then
    echo "🛠️ Installing Go..."
    wget https://golang.org/dl/go1.21.1.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.1.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    source ~/.bashrc
    rm go1.21.1.linux-amd64.tar.gz
else
    echo "✅ Go is already installed"
fi

# Install tools
echo "📦 Installing subfinder, httpx, waybackurls..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/tomnomnom/waybackurls@latest

echo "✅ All tools installed. You can now run ./reconraptor.sh -d target.com"

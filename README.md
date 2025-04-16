# 🚀 ReconRaptor

A badass, no-nonsense, emoji-powered, subdomain-destroying, URL-digging recon tool for bug bounty hunters! 😎

## 🌟 Features

- 🔍 Subdomain discovery using `subfinder`
- 🌐 Live domain detection using `httpx`
- 📜 Historical URL collection using `waybackurls`
- 📁 Auto-categorization of `.js` and `.json` files
- 📦 Zips your recon results
- 📤 Optional Discord Webhook support to send zipped report
- 🎨 Pretty CLI output with emojis and banners

---

## ⚙️ Installation

Use the provided installer script:

```bash
chmod +x install.sh
./install.sh
```

This will:
- 🔎 Check for Go and install if missing
- 🧰 Install required tools: `subfinder`, `httpx`, `waybackurls`
- 🦖 Place `reconraptor.sh` in your PATH for global usage

---

## 🧪 Usage

```bash
reconraptor -d example.com
```

You will be prompted whether to send results to Discord webhook.
> Save your webhook in a file named `webhook.conf` in the same directory (optional).

---

## 📁 Output Structure

```
bugbounty_example.com/
├── subdomains.txt
├── live_subdomains.txt
├── all_urls.txt
├── js_files.txt
├── json_files.txt
└── results_example.com.zip
```

---

## 💌 Webhook Support

If you provide a `webhook.conf` file, ReconRaptor will ask to send your zipped results to the webhook. Otherwise, it will skip this step.

---

## 📦 Update

To update the tool and its dependencies:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/tomnomnom/waybackurls@latest
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

Crafted with ❤️ by [Zuri](https://github.com/Zuri09)

---

## 💬 Contribute

Pull requests are welcome. Feel free to fork and raise issues!

---

## 🤝 Disclaimer

This tool is for educational purposes only. Use responsibly and ethically.

Happy hacking! 🐱‍💻🚀


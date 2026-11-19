# Field methodology — 2026 writeup collection

Workflow and reconnaissance techniques extracted from public bug-bounty writeups. These
are operational steps for an authorized engagement; the class-level payloads live in
`web-pentest-skills/references/field-techniques-2026.md`.

## 1. Subdomain → IP → port → service

```bash
chaos -d target.com -o target.txt
httpx-toolkit -l target.txt -ip -silent | sed -nE 's/.*\[([0-9.]+)\].*/\1/p' | sort -u > ip.txt
naabu -l ip.txt -top-ports 100 -rate 1500 -verify -silent -o naabu.txt
python naabutonmap.py -i naabu.txt
cat ip.txt | nuclei -tags cve -bs 200
cat naabu.txt | nuclei -tags cve -bs 200
```

- Deduplicate subdomains by resolved IP; scan each backend once.
- Exclude Cloudflare/Akamai/Fastly ranges; use titles to separate edge pages from origins.
- Keep only verified-open ports for deeper scans.
- Triage by response size/word count, not only status; inspect 403s for bypasses.

## 2. Backup/sensitive-file fuzzing

```bash
ffuf -w ip.txt:SUB -w payloads/backup_files_only.txt:FILE -u https://SUB/FILE -mc 200 -rate 50 -fs 0 -c
ffuf -w naabu.txt:SUB -w payloads/backup_files_only.txt:FILE -u https://SUB/FILE -mc 200 -rate 50 -fs 0 -c
```

## 3. Wayback Machine (CDX API)

```bash
curl 'https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey' > all_urls.txt
```

Extension-filtered pull (backups, configs, docs, keys, DBs):

```bash
domain=target.com
curl "https://web.archive.org/cdx/search/cdx?url=*.$domain/*" \
  "&collapse=urlkey&output=text&fl=original" \
  "&filter=original:.*\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$" \
  -o filtered_urls.txt
```

- Normalize with `uro`, then grep for the extension set.
- Recover deleted 404 files from the snapshot timeline.
- Compare historical `robots.txt` with the current one for removed/hidden paths.
- Archived URLs preserve query strings; inspect forgotten endpoints and parameters.
- PDF secrets: download archived PDFs, `pdftotext - - | grep -Eaiq "confidential|internal|password|ssn|..."`.

## 4. Origin IP discovery behind a WAF

- Fingerprint the edge: `ping`, Wappalyzer, `wafw00f https://target.com`.
- Reverse DNS: `dnsrecon -d target.com`.
- Shodan certificate:
  `shodan search Ssl.cert.subject.CN:"<DOMAIN>" 200 --fields ip_str | httpx-toolkit -sc -title -server -td`.
- Censys: domain search, compare certificates and hosts.
- Historical DNS: SecurityTrails historical data, ViewDNS IP history.
- SPF records: authorized sending IPs may be origins.
- Passive DNS: VirusTotal, AlienVault OTX.
- Favicon hash: hash the favicon, search Shodan/Censys/Fofa/ZoomEye.
- Direct-IP verification: map the candidate in `/etc/hosts` or set Burp target to the IP;
  confirm content and certificate. Reject candidates that still redirect to the CDN/WAF.

## 5. S3 bucket recon

- Fingerprint: AWS XML error, Wappalyzer, source `s3` references.
- Dorks: `site:s3.amazonaws.com "target.com"`, `site:*.s3.amazonaws.com "target.com"`,
  `site:s3.amazonaws.com intitle:"index of"`, `inurl:".s3.amazonaws.com/"`.
- Subdomain sweep:
  `subfinder -d target.com -all -silent | httpx-toolkit -sc -title -td | grep "Amazon S3"`.
- JS extraction: `katana -u https://site.com/ -d 5 -jc`, then regex S3 URLs.
- Permutations: `lazys3`, `cewl` wordlist, `s3scanner -bucket-file file.txt -enumerate`.
- CLI: `aws s3 ls s3://bucket --no-sign-request --recursive --human-readable`; grep for
  `.env`, `.pem`, `.key`, `.json`, `.yml`, `.sql`, `.bak`, `id_rsa`.
- Impact: `aws s3 cp s3://bucket/ ./ --recursive --no-sign-request`; `FULL` = write.
  Document minimally and disclose responsibly.

## 6. Nuclei quick checks

```bash
cat domains.txt | nuclei -t openRedirect.yaml --retries 2
cat domains.txt | nuclei -t wp-setup-config.yaml
cat domains.txt | nuclei -t iis.yaml -c 30
cat domains.txt | nuclei -t gitExposed.yaml
cat domains.txt | nuclei -t cors.yaml
cat domains.txt | nuclei -t credentials-disclosure-all.yaml -c 30
cat domains.txt | nuclei -t blind-ssrf.yaml -c 30 -dast
cat domains.txt | nuclei -t errorsqli.yaml -dast
cat domains.txt | nuclei -t cRlf.yaml -rl 50 -c 30
```

- Swagger discovery:
  `subfinder -d domain -all -silent | httpx-toolkit -path /swagger-api/ -sc -content-length -mc 200`.
- Template library: `https://github.com/coffinxp/nuclei-templates`.

## 7. ffuf patterns

```bash
ffuf -u https://example.com/FUZZ -w wordlist.txt -ic -c
ffuf -u https://example.com/indexFUZZ -w wordlist.txt -e .php,.asp,.bak,.db
ffuf -u https://example.com/FUZZ -w wordlist.txt -recursion -recursion-depth 3
ffuf -w wordlist.txt -u https://example.com/FUZZ -fc 404,500
ffuf -w wordlist.txt -u "https://example.com/page.php?FUZZ=value"
ffuf -w passwords.txt -X POST -d "username=admin&password=FUZZ" -u https://example.com/login
ffuf -w vhosts.txt -u https://example.com/ -H "Host: FUZZ.example.com"
ffuf -w subdomains.txt -u https://FUZZ.example.com/
ffuf -u https://example.com/W2/W1/ -w dict.txt:W1 -w dns_dict.txt:W2
ffuf -w users.txt:USER -w passwords.txt:PASS -u "https://example.com/login?username=USER&password=PASS" -mode clusterbomb
ffuf -w wordlist.txt -u https://example.com/FUZZ -rate 50 -t 50
```

## 8. Fast XSS pipeline

```bash
gau target.com | gf xss | uro > xss_candidates.txt
cat xss_candidates.txt | Gxss > reflected.txt
cat reflected.txt | Kxss > kxss.txt
cat reflected.txt | httpx-toolkit -ct -silent -nc | grep -Ei 'text/html|xhtml|xml|svg'
dalfox pipe --remote-payloads=portswigger,payloadbox --waf-evasion --deep-domxss
```

Confirm in a browser before reporting; Dalfox output is a candidate, not proof.

## 9. SQLi recon pipeline

```bash
subfinder -d example.com -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'
echo https://example.com | gau | uro | grep -E ".php|.asp|.aspx|.jspx|.jsp" | grep "=" > urls.txt
echo https://example.com | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | uro | grep -E ".php|.asp|.aspx|.jspx|.jsp" > urls2.txt
cat urls1.txt urls2.txt | gf sqli | uro > cleaned-sql.txt
ghauri -m cleaned-sql.txt --batch --dbs --level 3 --confirm
sqlmap -m cleaned-sql.txt --batch --random-agent --tamper=space2comment --level=5 --risk=3 --drop-set-cookie --threads 10 --dbs
```

Time-based probes and header injection are in the field-techniques guide.

## 10. Operational rules

- Keep concurrency and rate limits low; stop on sustained 429/5xx.
- Do not run DDoS-style tests (pingback DDoS, XML-RPC amplification, mass signup floods)
  against production.
- OAST only to a domain you control.
- Record every command and result in the engagement `STATE.md` / `notes/`.

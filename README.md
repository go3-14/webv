# Web Vulnerability Scanner (webv)

A command-line based vulnerability scanner designed for educational purposes.
It scans websites for common security issues and generates a structured HTML report with severity classification and mitigation suggestions.

---

## Features

* CLI-based tool (`scan`, `add`, `list`)
* Multiple scan modes:

  * Fast (lightweight checks)
  * Normal (includes Nikto)
  * Deep (full scan with crawling + Nmap)
* Custom payload support (XSS, SQL Injection)
* Endpoint discovery using BeautifulSoup
* Integration with:

  * Nikto
  * Nmap
* HTML report generation with:

  * Severity levels
  * Risk descriptions
  * Fix suggestions

---

## Installation

### 1. Clone repository

```bash
git clone https://github.com/YOUR_USERNAME/webv.git
cd webv
```

---

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

---

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Install external tools

```bash
sudo apt update
sudo apt install nmap nikto
```

---

## Usage

### Scan (Normal)

```bash
python main.py scan <url>
```

---

### Fast Scan

```bash
python main.py scan <url> --fast
```

---

### Deep Scan

```bash
python main.py scan <url> --deep
```

---

### Add Custom Payload

```bash
python main.py add --type xss --payload "<script>alert(1)</script>"
```

---

### List Payloads

```bash
python main.py list
```

---

## Output

* Generates a file:

```plaintext
report_XXXX.html
```

* Includes:

  * Vulnerabilities found
  * Severity classification
  * Risk explanation
  * Fix recommendations
  * Discovered endpoints (deep mode)

---

## Project Structure

```plaintext
main.py
payloads.json
requirements.txt
README.md
```

---

## Notes

* Fast mode skips external tools for speed
* Deep mode performs endpoint crawling and network scanning
* Nmap and Nikto must be installed for full functionality

---

## Disclaimer

This tool is intended for educational purposes only.
Do not scan systems without proper authorization.

---

## Author

Gopi K

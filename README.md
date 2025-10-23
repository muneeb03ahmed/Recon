# 🧠 RECON — Endpoint Discovery & Vulnerability Scanner  
### Made by **Muneeb Ahmed**

---

## ⚡ Overview
**RECON** is an asynchronous Python-based web reconnaissance and endpoint analysis tool.  
It performs fast, **non-destructive** scans to identify potential security issues such as:

- **Endpoint discovery** (via `robots.txt`, `sitemap.xml`, and HTML crawling)
- **Open Redirect detection**
- **Reflected XSS reflection detection (safe marker test)**
- **Boolean-based SQL Injection behavior analysis**
- **Automatic HTML + JSON reporting**

The tool is safe for authorized testing and designed for educational and research use under the **Week-07 Cybersecurity Task** initiative.

---

## 🧩 Key Features

| Category | Description |
|-----------|--------------|
| **Endpoint Discovery** | Scans `robots.txt`, parses `sitemap.xml`, and performs BFS crawl up to configurable depth. |
| **Reflected XSS Check** | Injects benign markers to detect simple reflection without execution. |
| **Boolean SQLi Check** | Compares response differentials between logically true/false payloads to detect anomalies. |
| **Open Redirect Check** | Identifies misconfigured redirection parameters using safe test URL (`https://example.com`). |
| **Concurrency** | Fully async engine using `aiohttp`, capable of scanning dozens of endpoints simultaneously. |
| **Export Formats** | Generates clean `.json` and `.html` reports with summary and detailed findings. |
| **Banner** | Displays a CLI ASCII art banner: **RECON | Made by: Muneeb Ahmed** before each scan. |

---

## ⚙️ Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/<your-repo-name>/recon-tool.git
cd recon-tool

python3 -m venv venv
# Linux/macOS
source venv/bin/activate
# Windows
# venv\Scripts\activate

pip install -r requirements.txt
# or
pip install aiohttp lxml beautifulsoup4 jinja2

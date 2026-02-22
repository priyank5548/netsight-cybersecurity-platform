NetSight — URL / IP Scanner (Streamlit)

Overview
- A free Streamlit web app to scan a URL or IP and collect information:
  - Detect whether input is a URL or IP
  - DNS records (A, AAAA, MX, NS, TXT)
  - WHOIS / domain expiry
  - SSL/TLS certificate details
  - robots.txt
  - Basic IP geolocation via free service
  - Port reachability (common ports)

Python compatibility
- Recommended: Python 3.11 on Windows 11 (works best with latest libraries).
- Code should be compatible with Python 3.10+; TLS-version probing may require recent Python for `ssl.TLSVersion`.

Setup (Windows 11)
1. Install Python 3.11 from https://www.python.org/downloads/windows/ and add to PATH.
2. Open Command Prompt or PowerShell and create a venv (optional but recommended):

```powershell
python -m venv .venv
.\.venv\Scripts\activate
```

3. Install dependencies:

```powershell
pip install -r requirements.txt
```

4. Run the app:

```powershell
streamlit run app.py
```

Notes
- Everything uses free libraries and free public IP geolocation (`ip-api.com`).
- Some whois lookups may be rate-limited. If `whois` package fails, consider using an external whois service.
- For heavy TLS scanning or port scanning, consider adding specialized tools later.

If you want, I can run a quick local test or add a packaged `.exe` launcher for Windows. Which would you prefer next?
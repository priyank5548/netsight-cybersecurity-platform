import socket
import ssl
import requests
import whois
import dns.resolver
import re
import hashlib
from urllib.parse import urlparse
from datetime import datetime

# =============================
# CONFIG
# =============================
ABUSEIPDB_API_KEY = ""   # <-- Paste your API key here

COMMON_DIRS = ["admin", "login", "dashboard", "backup", ".git", "test"]

# =============================
# UTILITIES
# =============================

def clean_input(user_input):
    if user_input.startswith("http"):
        return urlparse(user_input).netloc
    return user_input

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

# =============================
# SSL ANALYSIS
# =============================

def ssl_analysis(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except:
        return None

# =============================
# SECURITY HEADERS
# =============================

def get_headers(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        return r.headers
    except:
        return None

# =============================
# DNS + EMAIL SECURITY
# =============================

def get_dns(domain):
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
        except:
            records[rtype] = []
    return records

# =============================
# SUBDOMAIN ENUM (CRT.SH)
# =============================

def get_subdomains(domain):
    try:
        r = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=10)
        data = r.json()
        subs = set()
        for entry in data:
            name = entry["name_value"]
            for s in name.split("\n"):
                if domain in s:
                    subs.add(s.strip())
        return list(subs)[:20]  # limit output
    except:
        return []

# =============================
# HTTP METHODS
# =============================

def check_http_methods(domain):
    try:
        r = requests.options(f"https://{domain}", timeout=5)
        return r.headers.get("Allow", "Unknown")
    except:
        return "Unable to detect"

# =============================
# DIRECTORY DISCOVERY
# =============================

def directory_scan(domain):
    found = []
    for d in COMMON_DIRS:
        try:
            r = requests.get(f"https://{domain}/{d}", timeout=3)
            if r.status_code == 200:
                found.append(d)
        except:
            pass
    return found

# =============================
# TECHNOLOGY DETECTION
# =============================

def detect_tech(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        html = r.text.lower()
        tech = {}
        tech["Server"] = r.headers.get("Server", "Unknown")
        tech["X-Powered-By"] = r.headers.get("X-Powered-By", "Unknown")

        if "wordpress" in html:
            tech["CMS"] = "WordPress"
        elif "drupal" in html:
            tech["CMS"] = "Drupal"
        elif "joomla" in html:
            tech["CMS"] = "Joomla"
        else:
            tech["CMS"] = "Not Detected"

        return tech
    except:
        return {}

# =============================
# FAVICON HASH
# =============================

def favicon_hash(domain):
    try:
        r = requests.get(f"https://{domain}/favicon.ico", timeout=5)
        if r.status_code == 200:
            return hashlib.md5(r.content).hexdigest()
        return "Not Found"
    except:
        return "Error"

# =============================
# WAF DETECTION
# =============================

def detect_waf(headers):
    if not headers:
        return "Unknown"

    server = headers.get("Server", "").lower()

    if "cloudflare" in server:
        return "Cloudflare"
    if "akamai" in server:
        return "Akamai"
    if "imperva" in server:
        return "Imperva"

    return "Not Detected"

# =============================
# REVERSE DNS
# =============================

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Not Available"

# =============================
# ABUSEIPDB
# =============================

def abuseip_lookup(ip):
    if not ABUSEIPDB_API_KEY:
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        r = requests.get(url, headers=headers, params=params)
        return r.json()["data"]
    except:
        return None

# =============================
# MAIN REPORT
# =============================

def main():
    target = input("Enter URL or Domain: ").strip()
    domain = clean_input(target)
    ip = resolve_ip(domain)

    print("\n" + "="*60)
    print("        ADVANCED WEBSITE RECON REPORT")
    print("="*60)
    print(f"Scan Time: {datetime.now()}")
    print(f"Target: {domain}")
    print(f"IP Address: {ip if ip else 'Could not Resolve'}")

    # Reverse DNS
    if ip:
        print(f"Reverse DNS: {reverse_dns(ip)}")

    # SSL
    print("\n[ SSL / TLS ]")
    cert = ssl_analysis(domain)
    if cert:
        print("SSL Enabled")
        print("Valid From:", cert.get("notBefore"))
        print("Valid Until:", cert.get("notAfter"))
    else:
        print("SSL Not Available")

    # Headers
    print("\n[ SECURITY HEADERS ]")
    headers = get_headers(domain)
    if headers:
        important = ["Strict-Transport-Security",
                     "Content-Security-Policy",
                     "X-Frame-Options"]
        for h in important:
            print(f"{h}: {'Present' if h in headers else 'Missing'}")

    # DNS
    print("\n[ DNS RECORDS ]")
    dns_records = get_dns(domain)
    for rtype, values in dns_records.items():
        print(f"{rtype}: {', '.join(values) if values else 'None'}")

    # Email security
    print("\n[ EMAIL SECURITY ]")
    txt_records = dns_records.get("TXT", [])
    spf = any("v=spf1" in r for r in txt_records)
    dmarc = any("v=DMARC1" in r for r in txt_records)
    print("SPF:", "Present" if spf else "Missing")
    print("DMARC:", "Present" if dmarc else "Missing")

    # Subdomains
    print("\n[ SUBDOMAINS (Certificate Transparency) ]")
    subs = get_subdomains(domain)
    if subs:
        for s in subs:
            print("-", s)
    else:
        print("No subdomains found")

    # HTTP Methods
    print("\n[ HTTP METHODS ]")
    print(check_http_methods(domain))

    # Directories
    print("\n[ COMMON DIRECTORIES FOUND ]")
    dirs = directory_scan(domain)
    if dirs:
        for d in dirs:
            print("-", d)
    else:
        print("None Found")

    # Tech
    print("\n[ TECHNOLOGY DETECTION ]")
    tech = detect_tech(domain)
    for k, v in tech.items():
        print(f"{k}: {v}")

    # Favicon
    print("\n[ FAVICON HASH ]")
    print(favicon_hash(domain))

    # WAF
    print("\n[ WAF DETECTION ]")
    print(detect_waf(headers))

    # AbuseIPDB
    print("\n[ IP REPUTATION - AbuseIPDB ]")
    rep = abuseip_lookup(ip) if ip else None
    if rep:
        print("Abuse Score:", rep["abuseConfidenceScore"])
        print("Total Reports:", rep["totalReports"])
        print("Last Reported:", rep["lastReportedAt"])
    else:
        print("API Key not configured or no data")

    print("\n" + "="*60)
    print("Scan Completed")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()

import socket
import ssl
import requests
import dns.resolver
import hashlib
from urllib.parse import urlparse, urljoin
from datetime import datetime

COMMON_DIRS = ["admin", "login", "dashboard", "backup", ".git", "test"]

# Disable SSL warnings for self-signed certs
try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

def clean_input(user_input):
    """Clean and extract domain from URL"""
    if user_input.startswith("http"):
        return urlparse(user_input).netloc
    return user_input

def resolve_ip(domain):
    """Resolve domain to IP address"""
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        return None

def ssl_analysis(domain):
    """Analyze SSL/TLS certificate"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except:
        return None

def get_headers(domain):
    """Get HTTP response headers"""
    try:
        r = requests.get(f"https://{domain}", timeout=5, verify=False)
        return dict(r.headers)
    except:
        try:
            r = requests.get(f"http://{domain}", timeout=5)
            return dict(r.headers)
        except:
            return None

def get_dns(domain):
    """Resolve DNS records"""
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
        except:
            records[rtype] = []
    return records

def get_subdomains_from_cert(domain):
    """Extract subdomains from SSL certificate (SAN field)"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                san = cert.get('subjectAltName', [])
                subdomains = set()
                for entry in san:
                    if entry[0] == 'DNS':
                        subdomain = entry[1]
                        # Only include if it contains the target domain
                        if domain in subdomain:
                            subdomains.add(subdomain)
                return list(subdomains)
    except:
        return []

def get_subdomains_bruteforce(domain):
    """Brute-force common subdomain names (expanded list)"""
    common_subs = [
        # Common services
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "email",
        "admin", "administrator", "portal", "dashboard", "panel",
        
        # API and Development
        "api", "api1", "api2", "dev", "development", "test", "testing", 
        "staging", "stage", "prod", "production", "demo", "sandbox",
        
        # Applications
        "app", "apps", "application", "blog", "shop", "store", "ecommerce",
        "forum", "support", "help", "helpdesk", "wiki", "kb", "docs",
        
        # Infrastructure
        "vpn", "remote", "secure", "gateway", "proxy", "firewall",
        "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
        "mx", "mx1", "mx2", "mx3", "smtp1", "smtp2", "pop3",
        
        # Mobile & CDN
        "mobile", "m", "cdn", "cdn1", "cdn2", "static", "assets", 
        "img", "images", "media", "files", "download", "downloads",
        
        # Control Panels
        "cpanel", "whm", "plesk", "webmail", "autodiscover", "autoconfig",
        
        # Regions/Environments
        "us", "eu", "asia", "east", "west", "north", "south",
        "cloud", "server", "host", "web", "web1", "web2",
        
        # Security & Monitoring
        "vpn", "ssh", "sftp", "git", "gitlab", "github", "bitbucket",
        "jenkins", "ci", "cd", "monitoring", "metrics", "logs",
        
        # Databases
        "db", "database", "mysql", "postgres", "mongo", "redis",
        
        # Common patterns
        "old", "new", "beta", "alpha", "v1", "v2", "v3",
        "login", "signin", "signup", "register", "account",
        "status", "monitor", "stats", "analytics", "tracking",
        
        # Communication
        "chat", "messenger", "sms", "voice", "call", "meet", "zoom",
        
        # Payment & Commerce
        "pay", "payment", "checkout", "cart", "billing", "invoice",
        
        # Content
        "news", "blog", "article", "video", "music", "stream",
        "live", "tv", "radio", "podcast",
        
        # Social
        "social", "community", "profile", "user", "users",
        
        # Other common
        "backup", "archive", "old", "legacy", "internal", "external",
        "public", "private", "client", "customer", "partner"
    ]
    
    found = set()
    for sub in common_subs:
        full_domain = f"{sub}.{domain}"
        try:
            # Try to resolve the subdomain
            socket.gethostbyname(full_domain)
            found.add(full_domain)
        except:
            pass  # Subdomain doesn't exist
    
    return list(found)

def get_subdomains_crtsh(domain):
    """Get subdomains from Certificate Transparency (more aggressive parsing)"""
    try:
        # Try with wildcard query for more results
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        if r.status_code == 200:
            try:
                data = r.json()
            except:
                return []
            
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                # Handle multiple names separated by newlines
                for s in name.split("\n"):
                    s = s.strip()
                    if not s:
                        continue
                    
                    # Remove wildcard prefix
                    if s.startswith('*.'):
                        s = s[2:]
                    
                    # Only include if it's the target domain or a subdomain
                    if s == domain or s.endswith('.' + domain):
                        subs.add(s)
            
            return list(subs)
    except Exception as e:
        pass
    return []

def get_subdomains(domain):
    """
    Get subdomains using multiple methods (no API keys):
    1. Certificate Transparency logs (primary - most comprehensive)
    2. SSL Certificate SAN field  
    3. DNS brute-forcing common names
    """
    all_subdomains = set()
    
    # Method 1: Certificate Transparency (most comprehensive)
    # Try this first as it can find the most subdomains
    crtsh_subs = get_subdomains_crtsh(domain)
    if crtsh_subs:
        all_subdomains.update(crtsh_subs)
    
    # Method 2: Extract from SSL certificate
    cert_subs = get_subdomains_from_cert(domain)
    all_subdomains.update(cert_subs)
    
    # Method 3: Brute-force common subdomains (fallback/supplement)
    brute_subs = get_subdomains_bruteforce(domain)
    all_subdomains.update(brute_subs)
    
    # Clean up results
    # Remove the base domain if it appears
    all_subdomains.discard(domain)
    
    # Sort by subdomain levels (fewer dots first, then alphabetically)
    result = sorted(list(all_subdomains), key=lambda x: (x.count('.'), x))
    
    # Return up to 100 subdomains (increased limit)
    if result:
        return result[:100]
    else:
        return ["No subdomains found"]

def check_http_methods(domain):
    """Check allowed HTTP methods"""
    try:
        r = requests.options(f"https://{domain}", timeout=5, verify=False)
        return r.headers.get("Allow", "Unknown")
    except:
        try:
            r = requests.options(f"http://{domain}", timeout=5)
            return r.headers.get("Allow", "Unknown")
        except:
            return "Unable to detect"

def directory_scan(domain):
    """Scan for common directories"""
    found = []
    for d in COMMON_DIRS:
        try:
            r = requests.get(f"https://{domain}/{d}", timeout=3, verify=False)
            if r.status_code == 200:
                found.append(d)
        except:
            try:
                r = requests.get(f"http://{domain}/{d}", timeout=3)
                if r.status_code == 200:
                    found.append(d)
            except:
                pass
    return found

def detect_tech(domain):
    """Detect technology stack"""
    try:
        try:
            r = requests.get(f"https://{domain}", timeout=5, verify=False)
        except:
            r = requests.get(f"http://{domain}", timeout=5)
        
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

def favicon_hash(domain):
    """Get favicon hash"""
    try:
        r = requests.get(f"https://{domain}/favicon.ico", timeout=5, verify=False)
        if r.status_code == 200:
            return hashlib.md5(r.content).hexdigest()
        return "Not Found"
    except:
        try:
            r = requests.get(f"http://{domain}/favicon.ico", timeout=5)
            if r.status_code == 200:
                return hashlib.md5(r.content).hexdigest()
        except:
            pass
        return "Not Found"

def detect_waf(headers):
    """Detect Web Application Firewall"""
    if not headers:
        return "Unknown"

    server = headers.get("Server", "").lower()

    if "cloudflare" in server:
        return "Cloudflare"
    if "akamai" in server:
        return "Akamai"
    if "imperva" in server:
        return "Imperva"
    if "f5" in server:
        return "F5 BIG-IP"
    if "barracuda" in server:
        return "Barracuda"

    return "Not Detected"

def reverse_dns(ip):
    """Reverse DNS lookup"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Not Available"

def get_whois(domain):
    """Get WHOIS registration data."""
    try:
        import whois
        w = whois.whois(domain)
        raw = str(w)
        def _norm(v):
            if isinstance(v, list):
                v = v[0] if v else None
            if hasattr(v, 'isoformat'):
                return v.isoformat()
            return v
        ns = getattr(w, 'name_servers', None) or getattr(w, 'nameservers', None)
        ns_ips = {}
        if ns:
            for n in (ns if isinstance(ns, list) else [ns]):
                try:
                    ans = dns.resolver.resolve(str(n), 'A', lifetime=3)
                    ns_ips[str(n)] = [a.to_text() for a in ans]
                except Exception:
                    ns_ips[str(n)] = []
        return {
            'whois': True,
            'registrar': getattr(w, 'registrar', None),
            'registrar_url': None,
            'registered_on': _norm(getattr(w, 'creation_date', None)),
            'expires_on': _norm(getattr(w, 'expiration_date', None)),
            'updated_on': _norm(getattr(w, 'updated_date', None)),
            'status': getattr(w, 'status', None),
            'dnssec': None,
            'name_servers': ns,
            'name_server_ips': ns_ips,
            'registrant': {},
            'whois_raw': raw,
        }
    except Exception as e:
        return {'whois': False, 'error': str(e)}


def fetch_html_assets(domain):
    """Fetch HTML and extract links, scripts, iframes."""
    result = {'links': [], 'scripts': [], 'iframes': [], 'final_url': None, 'redirect_chain': [], 'headers': {}}
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return result
    for scheme in ('https://', 'http://'):
        url = scheme + domain.rstrip('/') + '/'
        try:
            r = requests.get(url, timeout=8, allow_redirects=True, verify=False)
            result['redirect_chain'] = [h.url for h in r.history] + [r.url]
            result['final_url'] = r.url
            result['headers'] = dict(r.headers)
            if r.ok:
                soup = BeautifulSoup(r.text, 'html.parser')
                base = r.url
                for a in soup.find_all('a', href=True):
                    result['links'].append(urljoin(base, a['href']))
                for s in soup.find_all('script', src=True):
                    result['scripts'].append(urljoin(base, s['src']))
                for iframe in soup.find_all('iframe', src=True):
                    result['iframes'].append(urljoin(base, iframe['src']))
                return result
        except Exception:
            continue
    return result


def get_ip_geolocation(ip):
    """Get IP geolocation via ip-api.com (free)."""
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org', timeout=5)
        if r.ok:
            return r.json()
    except Exception:
        pass
    return {}


def check_ports(host, ports=(80, 443)):
    """Check if ports are open."""
    out = {}
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=3) as s:
                try:
                    svc = socket.getservbyport(p, 'tcp')
                except Exception:
                    svc = None
                out[p] = {'open': True, 'service': svc, 'banner': None}
        except Exception:
            out[p] = {'open': False, 'service': None, 'banner': None}
    return out


def check_email_security_detailed(domain):
    """Check SPF, DMARC, DKIM."""
    out = {'spf': False, 'dmarc': False, 'dmarc_record': None, 'spf_record': None, 'dkim': {}}
    resolver = dns.resolver.Resolver()
    try:
        ans = resolver.resolve(domain, 'TXT', lifetime=3)
        txts = [r.to_text() for r in ans]
        spf = next((t for t in txts if 'v=spf1' in t.lower()), None)
        out['spf'] = bool(spf)
        out['spf_record'] = spf
    except Exception:
        pass
    try:
        ans = resolver.resolve(f'_dmarc.{domain}', 'TXT', lifetime=3)
        txts = [r.to_text() for r in ans]
        dmarc = next((t for t in txts if 'v=dmarc1' in t.lower()), None)
        out['dmarc'] = bool(dmarc)
        out['dmarc_record'] = dmarc
    except Exception:
        pass
    for sel in ['default', 'google', 'mail', 'selector1']:
        try:
            resolver.resolve(f'{sel}._domainkey.{domain}', 'TXT', lifetime=2)
            out['dkim'][sel] = True
        except Exception:
            out['dkim'][sel] = False
    return out


def compute_risk_score(result):
    """Compute security risk score 0-100."""
    score = 0
    if not (result.get('ssl_info') or {}).get('enabled'):
        score += 25
    if not (result.get('ports') or {}).get(443, {}).get('open', False):
        score += 15
    eh = result.get('email_security') or {}
    if not eh.get('spf'):
        score += 5
    if not eh.get('dmarc'):
        score += 5
    return min(100, score)


def detect_tech_extended(html, headers):
    """Extended technology detection."""
    tech = {}
    if not headers:
        return tech
    tech['server'] = headers.get('Server', 'Unknown')
    tech['x_powered_by'] = headers.get('X-Powered-By', 'Unknown')
    if not html:
        return tech
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, 'html.parser')
        gen = soup.find('meta', attrs={'name': 'generator'})
        if gen and gen.get('content'):
            tech['generator'] = gen.get('content')
    except Exception:
        pass
    lc = html.lower()
    if 'wordpress' in lc or '/wp-content/' in lc:
        tech['cms'] = 'WordPress'
    elif 'drupal' in lc:
        tech['cms'] = 'Drupal'
    elif 'joomla' in lc:
        tech['cms'] = 'Joomla'
    else:
        tech['cms'] = 'Not Detected'
    if 'jquery' in lc:
        tech['js'] = 'jQuery'
    elif 'react' in lc:
        tech['js'] = 'React'
    elif 'angular' in lc:
        tech['js'] = 'Angular'
    return tech


def scan_url_for_web(target):
    """Main scanning function for web interface"""
    result = {
        "status": "success",
        "target": None,
        "normalized_target": None,
        "ip": None,
        "reverse_dns": None,
        "scan_timestamp": None,
        "ssl_info": {},
        "headers": {},
        "dns_records": {},
        "email_security": {},
        "subdomains": [],
        "links": [],
        "view_paths": [],
        "scripts": [],
        "iframes": [],
        "http_methods": None,
        "directories": [],
        "technology": {},
        "favicon_hash": None,
        "waf": None,
        "error": None,
        "ip_info": {},
        "hosting_provider": None,
        "final_url": None,
        "redirect_chain": [],
        "https_forced": False,
        "whois": {},
        "ports": {},
        "risk_score": 0,
        "risk_level": "Unknown",
    }

    try:
        domain = clean_input(target.strip())
        if not domain:
            result["status"] = "error"
            result["error"] = "Invalid input"
            return result

        result["target"] = domain
        result["normalized_target"] = domain
        result["scan_timestamp"] = datetime.utcnow().isoformat()
        
        # Resolve IP
        ip = resolve_ip(domain)
        result["ip"] = ip

        if ip:
            result["reverse_dns"] = reverse_dns(ip) if reverse_dns(ip) != "Not Available" else None
            result["ip_info"] = get_ip_geolocation(ip)
            ia = result["ip_info"]
            if ia.get('status') == 'success':
                result["hosting_provider"] = ia.get('isp') or ia.get('org')

        # Port check
        result["ports"] = check_ports(domain, (80, 443))

        # SSL Analysis
        cert = ssl_analysis(domain)
        if cert:
            result["ssl_info"] = {
                "enabled": True,
                "valid_from": str(cert.get("notBefore", "Unknown")),
                "valid_until": str(cert.get("notAfter", "Unknown"))
            }
        else:
            result["ssl_info"] = {"enabled": False}

        # Headers & HTML fetch
        html_assets = fetch_html_assets(domain)
        result["links"] = html_assets.get("links", [])
        result["scripts"] = html_assets.get("scripts", [])
        result["iframes"] = html_assets.get("iframes", [])
        result["final_url"] = html_assets.get("final_url")
        result["redirect_chain"] = html_assets.get("redirect_chain", [])
        if html_assets.get("headers"):
            result["headers"] = html_assets["headers"]

        # View paths (unique paths from links)
        seen = set()
        for link in result["links"]:
            try:
                p = urlparse(link).path or '/'
                if p not in seen:
                    seen.add(p)
                    result["view_paths"].append(p)
            except Exception:
                pass

        # HTTPS forced
        rc = result.get("redirect_chain") or []
        if len(rc) >= 2 and rc[0].startswith("http://") and any(u.startswith("https://") for u in rc[1:]):
            result["https_forced"] = True

        # Fallback headers if fetch failed
        if not result["headers"]:
            result["headers"] = get_headers(domain) or {}

        # DNS
        dns_records = get_dns(domain)
        result["dns_records"] = dns_records

        # Email Security (detailed)
        result["email_security"] = check_email_security_detailed(domain)
        result["email_security"]["spf"] = "Present" if result["email_security"].get("spf") else "Missing/Unknown"
        result["email_security"]["dmarc"] = "Present" if result["email_security"].get("dmarc") else "Missing/Unknown"

        # Subdomains
        result["subdomains"] = get_subdomains(domain)
        if result["subdomains"] == ["No subdomains found"]:
            result["subdomains"] = []

        # HTTP Methods
        result["http_methods"] = check_http_methods(domain)

        # Directories
        result["directories"] = directory_scan(domain)

        # Technology
        result["technology"] = detect_tech(domain)
        html = None
        try:
            r = requests.get(f"https://{domain}", timeout=5, verify=False)
            html = r.text
        except Exception:
            try:
                r = requests.get(f"http://{domain}", timeout=5)
                html = r.text
            except Exception:
                pass
        ext = detect_tech_extended(html, result.get("headers"))
        for k, v in ext.items():
            if v and v != 'Unknown':
                result["technology"][k] = v

        # Favicon
        result["favicon_hash"] = favicon_hash(domain)

        # WAF
        result["waf"] = detect_waf(result.get("headers")) if result.get("headers") else "Unknown"

        # WHOIS
        result["whois"] = get_whois(domain)

        # Risk score
        result["risk_score"] = compute_risk_score(result)
        if result["risk_score"] < 20:
            result["risk_level"] = "Minimal"
        elif result["risk_score"] < 40:
            result["risk_level"] = "Low"
        elif result["risk_score"] < 60:
            result["risk_level"] = "Medium"
        elif result["risk_score"] < 80:
            result["risk_level"] = "High"
        else:
            result["risk_level"] = "Critical"

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result

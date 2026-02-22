import ipaddress
import socket
import ssl
import requests
import whois
import dns.resolver
import tldextract
import datetime
from ipwhois import IPWhois
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
from collections import Counter
import re


def detect_input_type(value: str) -> str:
    v = value.strip()
    # remove scheme for detection
    if v.startswith('http://') or v.startswith('https://'):
        v = v.split('://', 1)[1]
    # strip path
    v = v.split('/')[0]
    try:
        ipaddress.ip_address(v)
        return 'ip'
    except Exception:
        return 'url'


def normalize_host(value: str) -> str:
    v = value.strip()
    if v.startswith('http://') or v.startswith('https://'):
        parsed = v.split('://', 1)[1]
    else:
        parsed = v
    host = parsed.split('/')[0]
    # remove credentials if any
    if '@' in host:
        host = host.split('@')[-1]
    # strip surrounding [] for IPv6 hosts
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    return host


def check_security_headers(headers: dict) -> dict:
    """Check presence and basic configuration of important security headers."""
    out = {}
    if not headers:
        return out
    # normalize keys
    nh = {k.lower(): v for k, v in (headers.items() if isinstance(headers, dict) else [])}
    # HSTS
    hsts = nh.get('strict-transport-security')
    if hsts:
        # try to parse max-age
        try:
            import re
            m = re.search(r'max-age=(\d+)', hsts)
            if m:
                maxage = int(m.group(1))
                if maxage >= 15768000:
                    out['strict-transport-security'] = {'status': 'present', 'value': hsts}
                else:
                    out['strict-transport-security'] = {'status': 'misconfigured', 'value': hsts, 'note': 'max-age too low'}
            else:
                out['strict-transport-security'] = {'status': 'misconfigured', 'value': hsts, 'note': 'no max-age parsed'}
        except Exception:
            out['strict-transport-security'] = {'status': 'present', 'value': hsts}
    else:
        out['strict-transport-security'] = {'status': 'missing'}

    # CSP
    csp = nh.get('content-security-policy')
    if csp:
        if "'unsafe-inline'" in csp or 'default-src *' in csp:
            out['content-security-policy'] = {'status': 'misconfigured', 'value': csp}
        else:
            out['content-security-policy'] = {'status': 'present', 'value': csp}
    else:
        out['content-security-policy'] = {'status': 'missing'}

    # X-Frame-Options
    xfo = nh.get('x-frame-options')
    if xfo:
        out['x-frame-options'] = {'status': 'present', 'value': xfo}
    else:
        out['x-frame-options'] = {'status': 'missing'}

    # X-Content-Type-Options
    xcto = nh.get('x-content-type-options')
    if xcto:
        if xcto.lower().strip() == 'nosniff':
            out['x-content-type-options'] = {'status': 'present', 'value': xcto}
        else:
            out['x-content-type-options'] = {'status': 'misconfigured', 'value': xcto}
    else:
        out['x-content-type-options'] = {'status': 'missing'}

    # Referrer-Policy
    rp = nh.get('referrer-policy')
    if rp:
        out['referrer-policy'] = {'status': 'present', 'value': rp}
    else:
        out['referrer-policy'] = {'status': 'missing'}

    # Permissions-Policy (Feature-Policy)
    pp = nh.get('permissions-policy') or nh.get('feature-policy')
    if pp:
        out['permissions-policy'] = {'status': 'present', 'value': pp}
    else:
        out['permissions-policy'] = {'status': 'missing'}

    return out


def get_dns_records(domain: str) -> dict:
    out = {}
    resolver = dns.resolver.Resolver()
    types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    for t in types:
        try:
            answers = resolver.resolve(domain, t, lifetime=5)
            out[t] = [r.to_text() for r in answers]
        except Exception:
            out[t] = []
    return out


def get_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        raw = str(w)

        def _norm_date(val):
            if isinstance(val, list):
                val = val[0]
            if isinstance(val, datetime.datetime):
                return val.isoformat()
            return val

        domain_name = getattr(w, 'domain_name', None)
        registrar = getattr(w, 'registrar', None)
        creation = _norm_date(getattr(w, 'creation_date', None))
        expiration = _norm_date(getattr(w, 'expiration_date', None))
        updated = _norm_date(getattr(w, 'updated_date', None))
        status = getattr(w, 'status', None)
        name_servers = getattr(w, 'name_servers', None) or getattr(w, 'nameservers', None)
        emails = getattr(w, 'emails', None)

        # try to extract extra registrar/contact fields from raw text
        import re
        registrar_iana = None
        abuse_email = None
        abuse_phone = None
        registrant_org = None
        registrant_country = None
        registrant_email = None
        registrant_name = None
        registrant_address = None
        registrant_phone = None
        admin_name = None
        admin_email = None
        admin_phone = None
        tech_contact_email = None
        registrar_url = None
        domain_status = None
        dnssec = None

        m = re.search(r'(Registrar IANA ID|IANA ID)\s*:\s*(\d+)', raw, re.IGNORECASE)
        if m:
            registrar_iana = m.group(2)

        m = re.search(r'Abuse Email\s*:\s*(\S+@\S+)', raw, re.IGNORECASE)
        if m:
            abuse_email = m.group(1)
        else:
            m = re.search(r'Abuse Contact Email\s*:\s*(\S+@\S+)', raw, re.IGNORECASE)
            if m:
                abuse_email = m.group(1)

        m = re.search(r'Abuse Phone\s*:\s*([+\d\-() ]{6,})', raw, re.IGNORECASE)
        if m:
            abuse_phone = m.group(1).strip()

        # # admin contact
        # m = re.search(r'Admin Name\s*:\s*(.+)', raw, re.IGNORECASE)
        # if m:
        #     admin_name = m.group(1).strip()
        # m = re.search(r'Admin Email\s*:\s*(\S+@\S+)', raw, re.IGNORECASE)
        # if m:
        #     admin_email = m.group(1)
        # m = re.search(r'Admin Phone\s*:\s*([+\d\-() ]{6,})', raw, re.IGNORECASE)
        # if m:
        #     admin_phone = m.group(1).strip()

        # # technical contact
        # m = re.search(r'Technical Contact Email\s*:\s*(\S+@\S+)', raw, re.IGNORECASE)
        # if m:
        #     tech_contact_email = m.group(1)

        # # registrar URL
        # m = re.search(r'Registrar URL\s*:\s*(https?://\S+)', raw, re.IGNORECASE)
        # if m:
        #     registrar_url = m.group(1).strip()

        # domain status and dnssec
        m = re.findall(r'Domain Status\s*:\s*(.+)', raw, re.IGNORECASE)
        if m:
            domain_status = [s.strip() for s in m]
        m = re.search(r'DNSSEC\s*:\s*(.+)', raw, re.IGNORECASE)
        if m:
            dnssec = m.group(1).strip()

        # attempt to resolve name server IPs
        ns_ips = {}
        try:
            resolver = dns.resolver.Resolver()
            for ns in (name_servers or []):
                try:
                    ans = resolver.resolve(ns, 'A', lifetime=3)
                    ns_ips[ns] = [a.to_text() for a in ans]
                except Exception:
                    ns_ips[ns] = []
        except Exception:
            ns_ips = {}

        return {
            'whois': True,
            'domain': domain_name,
            'registered_on': creation,
            'expires_on': expiration,
            'updated_on': updated,
            'status': status,
            'domain_status': domain_status,
            'dnssec': dnssec,
            'name_servers': name_servers,
            'name_server_ips': ns_ips,
            'registrar': registrar,
            'registrar_url': registrar_url,
            'registrar_iana': registrar_iana,
            'emails': emails,
            'registrant': {
                'name': registrant_name,
                'organization': registrant_org,
                'address': registrant_address,
                'country': registrant_country,
                'email': registrant_email,
                'phone': registrant_phone,
            },
            'administrative_contact': {
                'name': admin_name,
                'email': admin_email,
                'phone': admin_phone,
            },
            'technical_contact': {
                'email': tech_contact_email
            },
            'registrar_abuse': {
                'email': abuse_email,
                'phone': abuse_phone
            },
            'whois_raw': raw,
        }
    except Exception as e:
        return {'whois': False, 'error': str(e)}


def get_cert_info(host: str, port: int = 443) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # cert is a dict with subject, issuer, notBefore, notAfter
                info = {
                    'subject': cert.get('subject'),
                    'issuer': cert.get('issuer'),
                    'notBefore': cert.get('notBefore'),
                    'notAfter': cert.get('notAfter'),
                    'serialNumber': cert.get('serialNumber') if 'serialNumber' in cert else None
                }
                return {'ok': True, 'cert': info}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def probe_tls_versions(host: str, port: int = 443) -> dict:
    results = {}
    # TLSVersion is available in modern Python; if not, skip detailed probing
    try:
        versions = [
            ssl.TLSVersion.TLSv1_3,
            ssl.TLSVersion.TLSv1_2,
            ssl.TLSVersion.TLSv1_1,
            ssl.TLSVersion.TLSv1
        ]
    except Exception:
        return {'note': 'TLS version probing requires modern Python with ssl.TLSVersion support.'}

    for v in versions:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = v
            ctx.maximum_version = v
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    results[str(v)] = 'supported'
        except Exception as e:
            results[str(v)] = 'not-supported'
    return results


def check_ports(host: str, ports=(80, 443)) -> dict:
    out = {}
    for p in ports:
        ok = False
        banner = None
        svc = None
        try:
            with socket.create_connection((host, p), timeout=3) as s:
                ok = True
                # try to receive a small banner
                try:
                    s.settimeout(1.0)
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                except Exception:
                    banner = None
        except Exception:
            ok = False
        # attempt to map to a service name
        try:
            svc = socket.getservbyport(p, 'tcp')
        except Exception:
            svc = None
        out[p] = {'open': ok, 'service': svc, 'banner': banner}
    return out


def reverse_dns_lookup(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None


def check_email_security(domain: str) -> dict:
    out = {'spf': None, 'dmarc': None, 'dkim': {}}
    resolver = dns.resolver.Resolver()
    # SPF: look for TXT records containing v=spf1
    try:
        txts = []
        answers = resolver.resolve(domain, 'TXT', lifetime=3)
        for r in answers:
            txt = ''.join(r.strings) if hasattr(r, 'strings') else r.to_text()
            txts.append(txt)
        spf = next((t for t in txts if 'v=spf1' in t.lower()), None)
        out['spf'] = bool(spf)
        out['spf_record'] = spf
    except Exception:
        out['spf'] = None
    # DMARC: check _dmarc.domain TXT
    try:
        dname = f"_dmarc.{domain}"
        answers = resolver.resolve(dname, 'TXT', lifetime=3)
        dtxts = [ ''.join(r.strings) if hasattr(r, 'strings') else r.to_text() for r in answers ]
        dmarc = next((t for t in dtxts if 'v=dmarc1' in t.lower()), None)
        out['dmarc'] = bool(dmarc)
        out['dmarc_record'] = dmarc
    except Exception:
        out['dmarc'] = None
    # DKIM: probe a small set of common selectors
    selectors = ['default', 'selector1', 'google', 'mail', 'smtp', 's1']
    for s in selectors:
        try:
            q = f"{s}._domainkey.{domain}"
            answers = resolver.resolve(q, 'TXT', lifetime=3)
            if answers:
                out['dkim'][s] = True
            else:
                out['dkim'][s] = False
        except Exception:
            out['dkim'][s] = False
    return out


def name_server_reputation(name_servers: list) -> dict:
    out = {'ns_ips': {}, 'ns_dnsbl': {}}
    resolver = dns.resolver.Resolver()
    for ns in (name_servers or []):
        try:
            answers = resolver.resolve(ns, 'A', lifetime=3)
            ips = [a.to_text() for a in answers]
        except Exception:
            ips = []
        out['ns_ips'][ns] = ips
        # check each IP against DNSBL
        bl_results = []
        for ip in ips:
            try:
                db = check_dnsbl(ip)
                if db.get('listed'):
                    bl_results.append({ip: db.get('details')})
            except Exception:
                continue
        out['ns_dnsbl'][ns] = bl_results
    return out


def fetch_html_and_assets(host: str) -> dict:
    """Try HTTPS first then HTTP. Return final url, redirect chain and parsed assets."""
    result = {'fetched': False, 'final_url': None, 'status_code': None, 'links': [], 'scripts': [], 'iframes': [], 'embeds': [], 'redirect_chain': []}
    session = requests.Session()
    for scheme in ('https://', 'http://'):
        url = scheme + host.rstrip('/') + '/'
        try:
            r = session.get(url, timeout=8, allow_redirects=True)
            result['status_code'] = r.status_code
            # build redirect chain
            chain = [h.url for h in r.history] + [r.url]
            result['redirect_chain'] = chain
            if r.ok:
                result['fetched'] = True
                result['final_url'] = r.url
                html = r.text
                result['html'] = html
                result['headers'] = dict(r.headers)
                soup = BeautifulSoup(html, 'html.parser')
                # links
                for a in soup.find_all('a', href=True):
                    href = a['href']
                    full = urljoin(r.url, href)
                    result['links'].append(full)
                # scripts
                for s in soup.find_all('script'):
                    src = s.get('src')
                    if src:
                        result['scripts'].append(urljoin(r.url, src))
                # iframes
                for it in soup.find_all('iframe'):
                    src = it.get('src')
                    if src:
                        result['iframes'].append(urljoin(r.url, src))
                # embed/object
                for emb in soup.find_all(['embed', 'object']):
                    src = emb.get('src') or emb.get('data')
                    if src:
                        result['embeds'].append(urljoin(r.url, src))
                return result
        except Exception:
            continue
    return result


def fetch_robots(domain: str) -> dict:
    paths = []
    tried = []
    for scheme in ('https://', 'http://'):
        url = scheme + domain.rstrip('/') + '/robots.txt'
        tried.append(url)
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return {'url': url, 'status': r.status_code, 'body': r.text}
        except Exception:
            continue
    return {'found': False, 'tried': tried}


def fetch_html_and_assets(host: str) -> dict:
    """Try HTTPS first then HTTP. Return final url and parsed assets."""
    result = {'fetched': False, 'final_url': None, 'status_code': None, 'links': [], 'scripts': [], 'iframes': [], 'embeds': []}
    for scheme in ('https://', 'http://'):
        url = scheme + host.rstrip('/') + '/'
        try:
            r = requests.get(url, timeout=6)
            if r.ok:
                result['fetched'] = True
                result['final_url'] = r.url
                html = r.text
                result['html'] = html
                result['headers'] = dict(r.headers)
                soup = BeautifulSoup(html, 'html.parser')
                # links
                for a in soup.find_all('a', href=True):
                    href = a['href']
                    full = urljoin(r.url, href)
                    result['links'].append(full)
                # scripts
                for s in soup.find_all('script'):
                    src = s.get('src')
                    if src:
                        result['scripts'].append(urljoin(r.url, src))
                # iframes
                for it in soup.find_all('iframe'):
                    src = it.get('src')
                    if src:
                        result['iframes'].append(urljoin(r.url, src))
                # embed/object
                for emb in soup.find_all(['embed', 'object']):
                    src = emb.get('src') or emb.get('data')
                    if src:
                        result['embeds'].append(urljoin(r.url, src))
                return result
        except Exception:
            continue
    return result


def detect_technologies(html: str, headers: dict, final_url: str) -> dict:
    tech = {}
    headers = headers or {}
    if headers.get('Server'):
        tech['server'] = headers.get('Server')
    xp = headers.get('X-Powered-By') or headers.get('x-powered-by')
    if xp:
        tech['x_powered_by'] = xp
    if headers.get('set-cookie'):
        tech['set_cookie'] = headers.get('set-cookie')

    # meta generator
    try:
        soup = BeautifulSoup(html or '', 'html.parser')
        gen = soup.find('meta', attrs={'name': 'generator'})
        if gen and gen.get('content'):
            tech['generator'] = gen.get('content')
    except Exception:
        pass

    # CMS heuristics
    cms = []
    lc = (html or '').lower()
    if '/wp-content/' in lc or 'wp-' in lc:
        cms.append('WordPress')
    if 'joomla' in lc or '/components/' in lc:
        cms.append('Joomla')
    if 'drupal' in lc or '/sites/' in lc:
        cms.append('Drupal')
    if cms:
        tech['cms'] = list(dict.fromkeys(cms))

    # JS frameworks
    js = []
    if ' react ' in lc or 'reactdom' in lc or 'react.js' in lc:
        js.append('React')
    if 'angular' in lc or 'ng-app' in lc:
        js.append('Angular')
    if 'vue' in lc or 'vue.js' in lc:
        js.append('Vue.js')
    if 'jquery' in lc:
        js.append('jQuery')
    if js:
        tech['js'] = list(dict.fromkeys(js))

    # check for common server-side tech in headers or html
    ss = []
    if xp:
        ss.append(xp)
    if headers.get('Server'):
        ss.append(headers.get('Server'))
    if ss:
        tech['server_side'] = ss

    # final URL
    if final_url:
        tech['final_url'] = final_url

    return tech


def find_subdomains(domain: str, wordlist=None) -> list:
    if wordlist is None:
        wordlist = ['www', 'mail', 'ftp', 'm', 'api', 'dev', 'test', 'staging', 'admin', 'blog', 'shop', 'webmail']
    found = []
    resolver = dns.resolver.Resolver()
    for w in wordlist:
        name = f"{w}.{domain}"
        try:
            answers = resolver.resolve(name, 'A', lifetime=3)
            if answers:
                found.append(name)
        except Exception:
            continue
    return found


def compute_risk_score(scan: dict) -> dict:
    """Simple heuristic to compute risk score (0-100) and level."""
    score = 0
    factors = []
    # no https or 443 closed
    ports = scan.get('ports') or {}
    # ports now map to {port: {'open': bool, 'service': str, 'banner': str}}
    if not (ports.get(443) or {}).get('open'):
        score += 25
        factors.append('No HTTPS / port 443 closed')
    # expired or missing cert
    sslinfo = scan.get('ssl') or {}
    if not sslinfo.get('ok'):
        score += 15
        factors.append('Missing or unreachable TLS certificate')
    else:
        cert = sslinfo.get('cert') or {}
        # simple date checks
        not_after = cert.get('notAfter')
        if not_after:
            try:
                # if certificate expires within 30 days, add risk
                from dateutil import parser as dateparser
                exp = dateparser.parse(not_after)
                if (exp - datetime.datetime.utcnow()).days < 30:
                    score += 10
                    factors.append('Certificate expiring soon')
            except Exception:
                pass
    # robots missing
    if not (scan.get('robots') or {}).get('body'):
        score += 5
        factors.append('robots.txt missing')
    # flash or swf found
    embeds = scan.get('embeds') or []
    for e in embeds:
        if e.lower().endswith('.swf'):
            score += 20
            factors.append('Flash/SWF embed found')
    # admin-like paths
    links = scan.get('links') or []
    for l in links:
        p = urlparse(l).path.lower()
        if any(x in p for x in ['/admin', '/login', '/user', '/wp-admin', '/manager']):
            score += 3
            factors.append('Admin/login pages exposed')
    # DNSBL / reputation factors
    rep = scan.get('reputation') or {}
    if rep.get('dnsbl') and rep.get('dnsbl').get('listed'):
        score += 40
        factors.append('IP listed on DNSBL')
    if rep.get('domain_age_days') is not None and rep.get('domain_age_days') < 90:
        score += 10
        factors.append('Young domain age')
    # clamp
    if score > 100:
        score = 100
    # map to level
    if score < 20:
        level = 'Minimal'
    elif score < 40:
        level = 'Low'
    elif score < 60:
        level = 'Medium'
    elif score < 80:
        level = 'High'
    else:
        level = 'Critical'
    # compact top factors
    top_factors = list(dict.fromkeys(factors))[:5]
    return {'score': score, 'level': level, 'factors': top_factors}


def get_ip_info(ip: str) -> dict:
    out = {}
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query', timeout=5)
        if r.ok:
            out['ip-api'] = r.json()
    except Exception as e:
        out['ip-api-error'] = str(e)
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(asn_methods=['whois', 'http'])
        out['ipwhois'] = {'asn': res.get('asn'), 'asn_description': res.get('asn_description'), 'network': res.get('network')}
    except Exception:
        out['ipwhois'] = None
    return out


def check_dnsbl(ip: str) -> dict:
    """Query a small set of DNSBLs for the IP. Returns list of positives."""
    positives = []
    try:
        reversed_ip = '.'.join(ip.split('.')[::-1])
    except Exception:
        return {'error': 'unsupported-ip-format'}
    bls = ['zen.spamhaus.org', 'bl.spamcop.net', 'dnsbl.sorbs.net']
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    for bl in bls:
        try:
            q = f"{reversed_ip}.{bl}"
            answers = resolver.resolve(q, 'A')
            if answers:
                positives.append({'bl': bl, 'response': [a.to_text() for a in answers]})
        except Exception:
            continue
    return {'listed': len(positives) > 0, 'details': positives}


def get_reputation(domain: str = None, ip: str = None) -> dict:
    """Lightweight reputation checks: DNSBL for IP and domain age heuristics."""
    out = {'malicious_reports': False, 'notes': []}
    if ip:
        try:
            db = check_dnsbl(ip)
            out['dnsbl'] = db
            if db.get('listed'):
                out['malicious_reports'] = True
                out['notes'].append('IP listed in one or more DNSBLs')
        except Exception as e:
            out['dnsbl_error'] = str(e)
    if domain:
        try:
            w = get_whois(domain)
            out['whois'] = {'registered_on': w.get('registered_on'), 'registrar': w.get('registrar')}
            # domain age heuristic
            if w.get('registered_on'):
                try:
                    reg = w.get('registered_on')
                    # try parse
                    import dateutil.parser as dp
                    d = dp.parse(reg)
                    age_days = (datetime.datetime.utcnow() - d).days
                    out['domain_age_days'] = age_days
                    if age_days < 90:
                        out['notes'].append('Domain age < 90 days (suspicious)')
                        out['malicious_reports'] = True
                except Exception:
                    pass
        except Exception as e:
            out['whois_error'] = str(e)
    return out


def scan_target(value: str, detected_type: str = None) -> dict:
    if detected_type is None:
        detected_type = detect_input_type(value)
    result = {'input': value, 'type': detected_type, 'scan_timestamp': datetime.datetime.utcnow().isoformat()}
    if detected_type == 'ip':
        ip = value.strip()
        result['normalized_target'] = ip
        result['scope'] = 'Active (ports)'
        result['ip_info'] = get_ip_info(ip)
        result['ports'] = check_ports(ip, ports=(22, 80, 443, 3306))
        # reverse DNS
        try:
            rd = reverse_dns_lookup(ip)
            result['reverse_dns'] = rd
        except Exception:
            result['reverse_dns'] = None
        # hosting/provider and country from ip_info
        try:
            ipapi = result.get('ip_info', {}).get('ip-api') or {}
            result['hosting_provider'] = ipapi.get('isp') or ipapi.get('org')
            result['country'] = ipapi.get('country')
        except Exception:
            result['hosting_provider'] = None
            result['country'] = None
        # reputation for IP
        try:
            result['reputation'] = get_reputation(ip=ip)
        except Exception:
            result['reputation'] = {}
        # findings basic
        findings = []
        if (result['ports'].get(22) or {}).get('open'):
            findings.append({'title': 'SSH port open', 'severity': 'Low', 'evidence': 'port 22 reachable', 'why': 'SSH exposed may be targeted', 'fix': 'Restrict SSH via firewall or VPN'})
        if result.get('reputation', {}).get('dnsbl', {}).get('listed'):
            findings.append({'title': 'IP listed on DNSBL', 'severity': 'High', 'evidence': result['reputation']['dnsbl']['details'], 'why': 'Listed IP suggests malicious history', 'fix': 'Investigate hosting and request delisting'})
        result['findings'] = findings
    else:
        host = normalize_host(value)
        result['host'] = host
        result['normalized_target'] = host
        # initial scope: we will fetch HTTP and check ports (safe active)
        result['scope'] = 'Active (safe)'
        # DNS
        result['dns'] = get_dns_records(host)
        # HTML assets (links, scripts, iframes, embeds)
        html_assets = fetch_html_and_assets(host)
        result['links'] = html_assets.get('links', [])
        result['scripts'] = html_assets.get('scripts', [])
        result['iframes'] = html_assets.get('iframes', [])
        result['embeds'] = html_assets.get('embeds', [])
        result['final_url'] = html_assets.get('final_url')
        result['redirect_chain'] = html_assets.get('redirect_chain')
        result['headers'] = html_assets.get('headers')
        result['html'] = html_assets.get('html')
        # security headers summary
        try:
            result['security_headers'] = check_security_headers(result.get('headers') or {})
        except Exception:
            result['security_headers'] = {}
        # detect technologies
        try:
            result['tech'] = detect_technologies(result.get('html'), result.get('headers'), result.get('final_url'))
        except Exception:
            result['tech'] = {}
        # whois
        try:
            result['whois'] = get_whois(host)
        except Exception as e:
            result['whois'] = {'error': str(e)}
        # SSL certificate
        result['ports'] = check_ports(host, ports=(80, 443))
        if (result['ports'].get(443) or {}).get('open'):
            result['ssl'] = get_cert_info(host, 443)
            result['tls_probe'] = probe_tls_versions(host, 443)
        else:
            result['ssl'] = {'ok': False, 'error': 'port 443 closed or unreachable'}
        # robots.txt
        result['robots'] = fetch_robots(host)
        # IP info for A records
        a_records = result['dns'].get('A', [])
        if a_records:
            ip = a_records[0].split()[0]
            result['ip_info'] = get_ip_info(ip)
            # reverse DNS for main A
            result['reverse_dns'] = reverse_dns_lookup(ip)
            # hosting/provider/country
            try:
                ipapi = result.get('ip_info', {}).get('ip-api') or {}
                result['hosting_provider'] = ipapi.get('isp') or ipapi.get('org')
                result['country'] = ipapi.get('country')
            except Exception:
                result['hosting_provider'] = None
                result['country'] = None
        # reputation (lightweight)
        try:
            rep = get_reputation(domain=host, ip=(a_records[0].split()[0] if a_records else None))
            result['reputation'] = rep
        except Exception:
            result['reputation'] = {}
        # email security
        try:
            result['email_security'] = check_email_security(host)
        except Exception:
            result['email_security'] = {}
        # name server reputation
        try:
            who = result.get('whois') or {}
            ns = who.get('name_servers') or []
            result['name_server_reputation'] = name_server_reputation(ns)
        except Exception:
            result['name_server_reputation'] = {}
        # subdomains
        try:
            ext = tldextract.extract(host)
            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            result['subdomains'] = find_subdomains(domain)
        except Exception:
            result['subdomains'] = []
        # findings + risk score
        try:
            rs = compute_risk_score(result)
            result['risk_score'] = rs.get('score')
            result['risk_level'] = rs.get('level')
            result['top_risk_factors'] = rs.get('factors')[:3]
        except Exception:
            result['risk_score'] = None
            result['risk_level'] = None

        # build findings list based on rules
        findings = []
        # TLS findings
        sslinfo = result.get('ssl') or {}
        if not sslinfo.get('ok'):
            findings.append({'title': 'Missing or invalid TLS', 'severity': 'High', 'evidence': sslinfo.get('error'), 'why': 'No valid TLS increases interception risk', 'fix': 'Install valid certificate and enable HTTPS'})
        else:
            cert = sslinfo.get('cert') or {}
            not_after = cert.get('notAfter')
            if not_after:
                try:
                    from dateutil import parser as dateparser
                    exp = dateparser.parse(not_after)
                    days = (exp - datetime.datetime.utcnow()).days
                    if days < 30:
                        findings.append({'title': 'TLS certificate expiring soon', 'severity': 'Medium', 'evidence': f'expiring in {days} days', 'why': 'Short expiry may lead to downtime', 'fix': 'Renew certificate'} )
                except Exception:
                    pass

        # security headers findings
        sh = result.get('security_headers') or {}
        for k, v in sh.items():
            if v.get('status') == 'missing':
                findings.append({'title': f'Missing header: {k}', 'severity': 'Low', 'evidence': None, 'why': f'{k} helps mitigate specific risks', 'fix': f'Add {k} with recommended configuration'})
            if v.get('status') == 'misconfigured':
                findings.append({'title': f'Misconfigured header: {k}', 'severity': 'Low', 'evidence': v.get('value'), 'why': f'{k} is present but not recommended configuration', 'fix': f'Adjust {k} to recommended values'})

        # exposed admin pages
        for l in result.get('links') or []:
            p = urlparse(l).path.lower()
            if any(x in p for x in ['/admin', '/login', '/wp-admin', '/manager']):
                findings.append({'title': 'Exposed admin/login page', 'severity': 'Medium', 'evidence': l, 'why': 'Public admin pages increase risk of credential attacks', 'fix': 'Restrict access or hide admin endpoints'})

        # reputation findings
        rep = result.get('reputation') or {}
        if rep.get('dnsbl') and rep.get('dnsbl').get('listed'):
            findings.append({'title': 'Listed on DNSBL', 'severity': 'High', 'evidence': rep.get('dnsbl').get('details'), 'why': 'Listed IP indicates malicious history', 'fix': 'Investigate and request delisting'})
        if rep.get('domain_age_days') is not None and rep.get('domain_age_days') < 90:
            findings.append({'title': 'Young domain age', 'severity': 'Low', 'evidence': f"age_days={rep.get('domain_age_days')}", 'why': 'Young domains are commonly used for phishing', 'fix': 'Monitor and validate ownership'})

        # attach findings
        result['findings'] = findings
    return result


if __name__ == '__main__':
    import json
    test = input('Enter url or ip: ').strip()
    t = detect_input_type(test)
    out = scan_target(test, t)
    print(json.dumps(out, indent=2))

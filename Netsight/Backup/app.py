import streamlit as st
from streamlit.components.v1 import html
from scanner import scan_target, detect_input_type, normalize_host
import json
from urllib.parse import urlparse

st.set_page_config(page_title='NetSight Scanner', layout='wide')

st.markdown(
    """
    <style>
    .stApp { background: #0b1220; color: #e6eef8; }
    .stButton>button { background-color:#1f6feb; color:white }
    .result-key { font-weight:600; color:#e6eef8 }
    .small-muted { color:#94a3b8; font-size:12px }
    .card { background:#0f1724; padding:12px; border-radius:8px; border: 1px solid #1f2937; margin-bottom: 10px; }
    .gauge-track { background:#0b1220; border-radius:9px; padding:6px }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title('NetSight — URL / IP Scanner')
st.write('Enter a URL (with or without scheme) or an IP address and click **Scan**.')

user_input = st.text_input('URL or IP', '')

def show_kv_pair(label, value):
    st.write(f"**{label}:** {value}")

def show_dns(dns):
    if not dns:
        st.write('No DNS data')
        return
    cols = st.columns(3)
    keys = list(dns.keys())
    for i, k in enumerate(keys):
        with cols[i % 3]:
            st.write(f"**{k}**")
            items = dns.get(k) or []
            if items:
                for it in items:
                    st.write('-', it)
            else:
                st.write('_— none —_')

def show_ports(ports):
    if not ports:
        return
    rows = []
    for p, info in ports.items():
        open_s = 'Yes' if (info or {}).get('open') else 'No'
        svc = (info or {}).get('service') or ''
        banner = (info or {}).get('banner') or ''
        rows.append({'port': p, 'open': open_s, 'service': svc, 'banner': banner})
    st.table(rows)

if st.button('Scan'):
    if not user_input.strip():
        st.error('Please enter a URL or IP address')
    else:
        with st.spinner('Scanning — this may take a few seconds'):
            try:
                typ = detect_input_type(user_input)
                data = scan_target(user_input, typ)

                st.success(f'Scan complete — detected: {typ.upper()}')

                # --- 1. TARGET SUMMARY ---
                st.subheader('Target Summary')
                left, right = st.columns([2, 3])
                with left:
                    if typ == 'ip':
                        show_kv_pair('Type', 'IP Address')
                        show_kv_pair('IP', data.get('input'))
                    else:
                        show_kv_pair('Type', 'URL / Domain')
                        show_kv_pair('Host', data.get('host'))
                    show_kv_pair('Normalized Target', data.get('normalized_target') or data.get('host'))
                    show_kv_pair('Scan Timestamp', data.get('scan_timestamp') or 'N/A')
                with right:
                    ipinfo = data.get('ip_info', {})
                    if ipinfo:
                        st.write('**IP Geolocation**')
                        ia = ipinfo.get('ip-api') or {}
                        if ia:
                            st.write(f"{ia.get('country', '')} — {ia.get('regionName', '')} — {ia.get('city', '')}")
                            st.write(f"ISP: {ia.get('isp', '')}")
                        # hosting provider + reverse DNS
                        if data.get('hosting_provider'):
                            st.write(f"Hosting: {data.get('hosting_provider')}")
                        if data.get('reverse_dns'):
                            st.write(f"Reverse DNS: {data.get('reverse_dns')}")

                # --- 2. SECURITY OVERVIEW (CARDS & GAUGE) ---
                score = data.get('risk_score') or 0
                level = data.get('risk_level') or 'Unknown'
                st.markdown("<div class='card'>", unsafe_allow_html=True)
                sec_left, sec_right = st.columns([1, 3])
                with sec_left:
                    st.markdown('**Security Score**')
                    gauge_small = f"""
                    <div style='display:flex;flex-direction:column;align-items:center;gap:8px'>
                      <div style='width:120px;height:100px;border-radius:8px;background:#071028;display:flex;align-items:center;justify-content:center;flex-direction:column'>
                        <div style='font-size:32px;font-weight:700;color:#fff'>{score}</div>
                        <div style='font-size:12px;color:#94a3b8'>{level}</div>
                      </div>
                      <div style='width:100%; height:12px; background:linear-gradient(90deg,#16a34a 0%,#f59e0b 50%,#ef4444 100%); border-radius:9px; position:relative; margin-top:10px;'>
                        <div style='position:absolute;left:{score}%;top:-6px;width:6px;height:24px;background:#fafafa;border-radius:3px;transform:translateX(-50%);'></div>
                      </div>
                    </div>
                    """
                    st.markdown(gauge_small, unsafe_allow_html=True)
                with sec_right:
                    headers_preview = data.get('headers') or {}
                    sslinfo = data.get('ssl') or {}
                    ssl_status = 'No cert' if not sslinfo.get('ok') else 'Valid'
                    ssl_until = (sslinfo.get('cert') or {}).get('notAfter') if sslinfo.get('ok') else ''
                    
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        st.markdown(f"<div class='card'><b>SSL Cert</b><br><span style='color:#94a3b8; font-size:12px;'>{ssl_until or ssl_status}</span></div>", unsafe_allow_html=True)
                    with c2:
                        missing_headers = len([h for h in ['content-security-policy', 'x-frame-options', 'strict-transport-security'] if h not in [k.lower() for k in headers_preview.keys()]])
                        st.markdown(f"<div class='card'><b>Headers</b><br><span style='color:#94a3b8; font-size:12px;'>{missing_headers} Missing</span></div>", unsafe_allow_html=True)
                    with c3:
                        dnssec = 'Active' if data.get('dns', {}).get('NS') else 'Unknown'
                        st.markdown(f"<div class='card'><b>DNSSEC</b><br><span style='color:#94a3b8; font-size:12px;'>{dnssec}</span></div>", unsafe_allow_html=True)
                    
                    trf = data.get('top_risk_factors') or []
                    if trf:
                        with st.expander('Top Risk Factors'):
                            for f in trf: st.write(f"- {f}")
                st.markdown("</div>", unsafe_allow_html=True)

                st.markdown('---')

                # --- 3. DNS & WHOIS ---
                if typ != 'ip':
                    col_dns, col_whois = st.columns(2)
                    with col_dns:
                        st.subheader('DNS Records')
                        gauge_small1 = f"""
                        <div style='marginLeft:2px;'>
                        </div>
                        """
                        st.markdown(gauge_small1, unsafe_allow_html=True)
                        show_dns(data.get('dns', {}))
                        # Redirect chain and final destination
                        redirect_chain = data.get('final_url') and data.get('html') and data.get('final_url')
                        if data.get('final_url') or (data.get('html') and data.get('final_url')):
                            rd = data.get('final_url')
                            st.markdown(f"**Final destination:** {rd}")
                        if data.get('redirect_chain'):
                            with st.expander('Redirect Chain'):
                                for u in data.get('redirect_chain'):
                                    st.write(u)
                        # HTTPS forced?
                        https_forced = False
                        try:
                            rc = data.get('redirect_chain') or []
                            if rc and any(u.startswith('https://') for u in rc) and rc[0].startswith('http://'):
                                https_forced = True
                        except Exception:
                            https_forced = False
                        st.write(f"**HTTPS forced:** {'Yes' if https_forced else 'No'}")
                    with col_whois:
                        st.subheader('WHOIS / Registration')
                        who = data.get('whois') or {}
                        if who.get('whois'):
                            st.markdown(f"**Registrar:** {who.get('registrar') or '—'}")
                            st.markdown(f"**Registrar URL:** {who.get('registrar_url') or '—'}")
                            st.markdown(f"**Registered On:** {who.get('registered_on') or '—'}")
                            st.markdown(f"**Expires On:** {who.get('expires_on') or '—'}")
                            st.markdown(f"**Updated On:** {who.get('updated_on') or '—'}")
                            st.markdown(f"**Status:** {who.get('status') or '—'}")
                            st.markdown(f"**DNSSEC:** {who.get('dnssec') or '—'}")
                            ns = who.get('name_servers') or []
                           
                            if who.get('name_server_ips'):
                                with st.expander('Name server IPs'):
                                    for n, ips in (who.get('name_server_ips') or {}).items():
                                        st.write(f"- {n}: {', '.join(ips) if ips else '—'}")

                        # Name server reputation
                        nsrep = data.get('name_server_reputation') or {}
                        if nsrep:
                            with st.expander('Name server reputation'):
                                for ns, ips in (nsrep.get('ns_ips') or {}).items():
                                    st.write(f"- {ns}: {', '.join(ips) if ips else '—'}")
                                for ns, bl in (nsrep.get('ns_dnsbl') or {}).items():
                                    if bl:
                                        st.write(f"- {ns} DNSBL positives: {bl}")

                            with st.expander('Registrant'):
                                r = who.get('registrant') or {}
                                if r:
                                    for k, v in r.items():
                                        st.write(f"**{k.title()}:** {v}")
                                else:
                                    st.write('—')

                            # with st.expander('Administrative Contact'):
                            #     ac = who.get('administrative_contact') or {}
                            #     if ac:
                            #         for k, v in ac.items():
                            #             st.write(f"**{k.title()}:** {v}")
                            #     else:
                            #         st.write('—')

                            # with st.expander('Technical Contact'):
                            #     tc = who.get('technical_contact') or {}
                            #     if tc:
                            #         for k, v in tc.items():
                            #             st.write(f"**{k.title()}:** {v}")
                            #     else:
                            #         st.write('—')

                            # with st.expander('Registrar Abuse'):
                            #     ra = who.get('registrar_abuse') or {}
                            #     if ra:
                            #         for k, v in ra.items():
                            #             st.write(f"**{k.title()}:** {v}")
                            #     else:
                            #         st.write('—')

                            with st.expander('Raw WHOIS'):
                                st.text_area("Raw WHOIS", who.get('whois_raw') or '', height=300)
                        else:
                            err = who.get('error') or who.get('whois_error')
                            if err:
                                st.error(f"WHOIS lookup failed: {err}")
                            else:
                                st.info("No WHOIS data found.")

                # --- 4. CONTENT DISCOVERY ---
                st.subheader('Content Discovery')
                col_links, col_assets = st.columns(2)
                
                with col_links:
                    links = data.get('links') or []
                    st.write(f'**Links found ({len(links)})**')
                    if links:
                        with st.expander("View Path List"):
                            for l in links:
                                try: st.write(f"`{urlparse(l).path or '/'}`")
                                except: st.write(l)
                        
                        # The Interactive Link Explorer Widget
                        safe_links_json = json.dumps(links)
                        widget = f"""
                        <html><body style='background:#0f1724; color:#e6eef8; font-family:sans-serif;'>
                            <select id='s' style='width:100%; padding:8px; background:#0b1220; color:white; border:1px solid #30363d;'></select>
                            <button onclick='window.open(document.getElementById("s").value, "_blank")' style='margin-top:8px; background:#1f6feb; color:white; border:none; padding:8px; border-radius:4px; cursor:pointer;'>Open Link</button>
                            <textarea id='t' style='width:100%; height:80px; margin-top:8px; background:#0b1220; color:#94a3b8; border:1px solid #30363d;' readonly></textarea>
                            <script>
                                const l = {safe_links_json}; const s = document.getElementById('s'); const t = document.getElementById('t');
                                l.forEach(u => {{ let o = document.createElement('option'); o.value = u; o.text = u; s.appendChild(o); }});
                                t.value = l.join('\\n');
                            </script>
                        </body></html>
                        """
                        html(widget, height=220)
                    else:
                        st.info("No links found.")

                with col_assets:
                    st.write('**Scripts & Objects**')
                    scripts = data.get('scripts') or []
                    if scripts:
                        with st.expander(f"JS Files ({len(scripts)})"):
                            for s in scripts: st.write(f"- {s}")
                    
                    iframes = data.get('iframes') or []
                    if iframes:
                        with st.expander(f"Iframes ({len(iframes)})"):
                            for f in iframes: st.write(f"- {f}")
                    
                    subs = data.get('subdomains') or []
                    if subs:
                        with st.expander("Discovered Subdomains"):
                            for s in subs: st.write(f"- {s}")

                # Email security
                email_sec = data.get('email_security') or {}
                if email_sec:
                    st.subheader('Email Security')
                    st.write(f"SPF: { 'Present' if email_sec.get('spf') else 'Missing/Unknown' }")
                    st.write(f"DMARC: { 'Present' if email_sec.get('dmarc') else 'Missing/Unknown' }")
                    with st.expander('DKIM selectors (probe results)'):
                        for s, val in (email_sec.get('dkim') or {}).items():
                            st.write(f"- {s}: {'Found' if val else 'Not found'}")

                # --- 5. RISK GAUGE & TECH STACK ---
                st.markdown('---')
                st.subheader('Infrastructure & Risk Analysis')
                
                inf_left, inf_right = st.columns(2)
                with inf_left:
                    st.write(f'**Risk Score:** {score} — {level}')
                    gauge_html = f"""
                    <div class='gauge-track'>
                        <div style='position:relative;height:18px;border-radius:9px;background:#111827'>
                            <div style='position:absolute;left:0;right:0;top:0;bottom:0;border-radius:9px;background:linear-gradient(90deg,#16a34a 0%,#f59e0b 50%,#ef4444 100%);'></div>
                            <div style='position:absolute;left:{score}%;top:-6px;width:8px;height:30px;background:#fafafa;border-radius:3px;transform:translateX(-50%);'></div>
                        </div>
                    </div>
                    """
                    st.markdown(gauge_html, unsafe_allow_html=True)
                    
                    st.write("**Port Reachability**")
                    show_ports(data.get('ports') or {})

                with inf_right:
                    with st.expander('Target Technologies', expanded=True):
                        tech = data.get('tech') or {}
                        if tech:
                            for k, v in tech.items():
                                if v: st.write(f"**{k.replace('_',' ').title()}:** {v if isinstance(v, str) else ', '.join(v)}")
                        else:
                            st.write("No specific tech detected.")
                    
                    hdrs = data.get('headers') or {}
                    if hdrs:
                        with st.expander('View Response Headers'):
                            for k, v in list(hdrs.items())[:15]: st.write(f"**{k}:** {v}")

                st.download_button('Download JSON Report', data=json.dumps(data, indent=2), file_name='netsight_scan.json', mime='application/json')

            except Exception as e:
                st.exception(e)
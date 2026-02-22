"""
Windows Registry Security Scanner
Defense cybersecurity - detects malicious activity, persistence, hijacking & anomalies.
"""
import winreg
import re
import os
from datetime import datetime
from collections import defaultdict

# Access flags for 64-bit registry on 64-bit Windows
KEY_READ_64 = winreg.KEY_READ | getattr(winreg, 'KEY_WOW64_64KEY', 0)
KEY_READ_32 = winreg.KEY_READ | getattr(winreg, 'KEY_WOW64_32KEY', 0)


class RegistryScanner:
    """
    Windows Registry Scanner for security analysis.
    Detects suspicious entries, malware persistence, hijacking, and anomalies.
    Defense cybersecurity perspective.
    """

    # Startup / persistence locations
    STARTUP_LOCATIONS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
    ]

    AUTOSTART_LOCATIONS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"),
    ]

    BROWSER_LOCATIONS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Internet Explorer\Main"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Internet Explorer\Main"),
    ]

    SERVICES_LOCATION = (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Services")
    WINLOGON_LOCATION = (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon")
    WINLOGON_WOW64 = (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon")

    # Additional critical security locations
    WINDOWS_NT_LOCATION = (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Windows")
    IFEO_BASE = (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
    IFEO_WOW64 = (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
    SAFEBOOT_LOCATION = (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\SafeBoot")
    LSA_LOCATION = (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Lsa")
    SESSION_MANAGER = (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Session Manager")
    APP_CERT_DLLS = (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Session Manager\AppCertDlls")
    FILE_ASSOC_EXE = (winreg.HKEY_CLASSES_ROOT, r"exefile\shell\open\command")
    PRINT_MONITORS = (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Print\Monitors")

    # Suspicious indicators
    SUSPICIOUS_PATHS = [
        "temp", "tmp", "appdata\\local\\temp", "programdata",
        "public\\", "roaming\\", "\\users\\public", "\\temp\\",
        "appdata\\roaming\\", "program files (x86)\\", "\\recycler",
    ]

    SUSPICIOUS_EXTENSIONS = [
        ".vbs", ".bat", ".cmd", ".ps1", ".scr", ".hta", ".js", ".jse", ".wsf"
    ]

    # Malware / obfuscation indicators
    OBFUSCATION_PATTERNS = [
        (r"-enc\s+[A-Za-z0-9+/=]{20,}", "Base64-encoded PowerShell command"),
        (r"-e\s+[A-Za-z0-9+/=]{20,}", "Base64-encoded command"),
        (r"FromBase64String|\[Convert\]::", "Base64 decoding in command"),
        (r"iex\s*\(|Invoke-Expression", "Dynamic code execution"),
        (r"hidden|bypass|encoded", "Stealth execution flag"),
        (r"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/", "Direct IP URL (C2 indicator)"),
        (r"powershell.*-w\s*1\s+", "Hidden window execution"),
        (r"cmd\s+/c\s+echo\s+[A-Za-z0-9+/=]+", "Encoded cmd payload"),
    ]

    # Legitimate whitelist - reduce false positives
    KNOWN_GOOD_STARTS = [
        "c:\\program files", "c:\\program files (x86)",
        "c:\\windows\\system32", "c:\\windows\\syswow64",
        "c:\\windows\\explorer.exe", "c:\\windows\\system32\\svchost.exe",
        "c:\\windows\\system32\\userinit.exe", "c:\\intel\\",
        "c:\\nvidia\\", "c:\\amd\\", "d:\\program files",
    ]

    def __init__(self):
        self.results = {
            'startup_programs': [],
            'autostart_folders': [],
            'browser_settings': [],
            'winlogon': [],
            'services': [],
            'suspicious_entries': [],
            'appinit_dlls': [],
            'ifeo_debuggers': [],
            'safeboot': [],
            'lsa_packages': [],
            'session_manager': [],
            'appcert_dlls': [],
            'file_associations': [],
            'print_monitors': [],
            'url_protocols': [],
            'anomaly_summary': [],
            'statistics': {},
            'errors': []
        }

    def _open_key(self, hive, path, wow64_64=True):
        """Open registry key with optional 64/32 bit view."""
        flags = KEY_READ_64 if wow64_64 else KEY_READ_32
        try:
            return winreg.OpenKey(hive, path, 0, flags)
        except (FileNotFoundError, PermissionError):
            try:
                return winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            except Exception:
                raise

    def scan_registry_key(self, hive, path, wow64_64=True):
        """Scan a specific registry key and return all values."""
        entries = []
        try:
            key = self._open_key(hive, path, wow64_64)
            i = 0
            while True:
                try:
                    name, value, value_type = winreg.EnumValue(key, i)
                    val_str = str(value) if value is not None else ""
                    entries.append({
                        'name': name,
                        'value': val_str,
                        'type': value_type,
                        'path': path
                    })
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except FileNotFoundError:
            pass
        except PermissionError:
            self.results['errors'].append(f"Access denied: {path}")
        except Exception as e:
            self.results['errors'].append(f"Error scanning {path}: {str(e)}")

        return entries

    def _add_suspicious(self, entry_type, location, name, value, reason, severity="high"):
        """Add suspicious entry with severity."""
        self.results['suspicious_entries'].append({
            'type': entry_type,
            'location': location,
            'name': name,
            'value': str(value)[:500] if value else "",
            'reason': reason,
            'severity': severity
        })

    def is_known_good(self, value):
        """Check if value appears to be from known good path."""
        if not value:
            return False
        v = value.lower().strip()
        for good in self.KNOWN_GOOD_STARTS:
            if v.startswith(good):
                return True
        # Microsoft signed paths
        if "microsoft" in v and ("system32" in v or "syswow64" in v):
            return True
        return False

    def is_suspicious(self, value):
        """Check if a registry value looks suspicious. Returns (is_suspicious, reason, severity)."""
        if not value:
            return False, None, "info"
        value_lower = str(value).lower()

        # Skip known good
        if self.is_known_good(value):
            return False, None, "info"

        # Obfuscation patterns (critical)
        for pattern, reason in self.OBFUSCATION_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                return True, reason, "critical"

        # Suspicious paths
        for suspicious_path in self.SUSPICIOUS_PATHS:
            if suspicious_path in value_lower:
                return True, f"Suspicious path: {suspicious_path}", "high"

        # Suspicious extensions
        for ext in self.SUSPICIOUS_EXTENSIONS:
            if ext in value_lower or value_lower.strip().endswith(ext):
                return True, f"Suspicious extension: {ext}", "high"

        # Encoded commands
        if any(indicator in value_lower for indicator in ["powershell", "cmd /c", "wscript", "cscript"]):
            if any(s in value_lower for s in ["hidden", "bypass", "encoded", "-enc", "-e ", "-w 1"]):
                return True, "Possibly obfuscated/stealth command", "critical"

        # Double extension
        parts = value_lower.split('.')
        if len(parts) > 2:
            if any(ext in parts[-2] for ext in ['pdf', 'doc', 'txt', 'jpg', 'png', 'exe']):
                return True, "Double extension (likely disguised)", "high"

        # Long base64-like string
        if re.search(r'[A-Za-z0-9+/]{60,}={0,2}', value):
            if 'powershell' in value_lower or 'cmd' in value_lower:
                return True, "Long encoded string with shell", "critical"

        return False, None, "info"

    def scan_startup_programs(self):
        """Scan all startup program locations."""
        startup_entries = []

        for hive, path in self.STARTUP_LOCATIONS:
            hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
            entries = self.scan_registry_key(hive, path)

            for entry in entries:
                is_susp, reason, severity = self.is_suspicious(entry['value'])
                startup_entries.append({
                    'hive': hive_name,
                    'location': path,
                    'name': entry['name'],
                    'command': entry['value'],
                    'suspicious': is_susp,
                    'reason': reason if is_susp else None,
                    'severity': severity if is_susp else "info"
                })

                if is_susp:
                    self._add_suspicious(
                        'Startup Program', f"{hive_name}\\{path}",
                        entry['name'], entry['value'], reason, severity
                    )

        self.results['startup_programs'] = startup_entries
        return startup_entries

    def scan_autostart_folders(self):
        """Scan autostart folder locations."""
        autostart_entries = []

        for hive, path in self.AUTOSTART_LOCATIONS:
            hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
            entries = self.scan_registry_key(hive, path)

            for entry in entries:
                if 'startup' in entry['name'].lower():
                    autostart_entries.append({
                        'hive': hive_name,
                        'location': path,
                        'name': entry['name'],
                        'path': entry['value']
                    })

        self.results['autostart_folders'] = autostart_entries
        return autostart_entries

    def scan_browser_settings(self):
        """Scan browser-related registry entries."""
        browser_entries = []

        for hive, path in self.BROWSER_LOCATIONS:
            hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
            entries = self.scan_registry_key(hive, path)

            for entry in entries:
                browser_entries.append({
                    'hive': hive_name,
                    'setting': entry['name'],
                    'value': entry['value']
                })

                if entry['name'].lower() in ['start page', 'search page', 'default_page_url']:
                    val = entry['value']
                    if val and val not in ['about:blank', '']:
                        if 'google.' not in val.lower() and 'bing.' not in val.lower() and 'microsoft.' not in val.lower():
                            self._add_suspicious(
                                'Browser Setting', f"{hive_name}\\{path}",
                                entry['name'], val, 'Unusual homepage/search page (potential hijack)', "medium"
                            )

        self.results['browser_settings'] = browser_entries
        return browser_entries

    def scan_winlogon(self):
        """Scan Winlogon for suspicious entries (shell, userinit hijacking)."""
        winlogon_entries = []

        for hive, path in [self.WINLOGON_LOCATION, self.WINLOGON_WOW64]:
            entries = self.scan_registry_key(hive, path)

            for entry in entries:
                winlogon_entries.append({'name': entry['name'], 'value': entry['value']})

                if entry['name'].lower() == 'shell':
                    expected = 'explorer.exe'
                    val = entry['value'].strip().lower()
                    if val != expected and not val.endswith('explorer.exe'):
                        self._add_suspicious(
                            'Winlogon Shell', f"HKLM\\{path}",
                            entry['name'], entry['value'],
                            f"Unexpected shell (expected: {expected}). Possible hijacking.", "critical"
                        )

                elif entry['name'].lower() == 'userinit':
                    expected = r"c:\windows\system32\userinit.exe"
                    val = entry['value'].lower()
                    if expected not in val:
                        self._add_suspicious(
                            'Winlogon Userinit', f"HKLM\\{path}",
                            entry['name'], entry['value'],
                            f"Userinit modified (should contain userinit.exe). Credential theft risk.", "critical"
                        )

        self.results['winlogon'] = winlogon_entries
        return winlogon_entries

    def scan_appinit_dlls(self):
        """Scan AppInit_DLLs - common malware DLL injection point."""
        hive, path = self.WINDOWS_NT_LOCATION
        entries = self.scan_registry_key(hive, path)
        appinit = []

        for entry in entries:
            if entry['name'].lower() in ['appinit_dlls', 'loadappinit_dlls', 'requireunsignedappinit_dlls']:
                val = entry['value']
                appinit.append({'name': entry['name'], 'value': val, 'path': path})

                if val and val.strip():
                    # Non-empty AppInit_DLLs loads DLLs into every process - high risk
                    severity = "critical" if entry['name'].lower() == 'appinit_dlls' else "high"
                    self._add_suspicious(
                        'AppInit_DLLs', f"HKLM\\{path}",
                        entry['name'], val,
                        "DLL injection point - loads into processes. Malware commonly abuses this.", severity
                    )

        self.results['appinit_dlls'] = appinit
        return appinit

    def scan_ifeo_debuggers(self):
        """Scan Image File Execution Options for debugger hijacking."""
        ifeo_entries = []

        for hive, base_path in [self.IFEO_BASE, self.IFEO_WOW64]:
            try:
                key = self._open_key(hive, base_path)
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        try:
                            subkey = winreg.OpenKey(key, subkey_name, 0, KEY_READ_64)
                            try:
                                debugger, _ = winreg.QueryValueEx(subkey, "Debugger")
                                if debugger:
                                    ifeo_entries.append({
                                        'target': subkey_name,
                                        'debugger': str(debugger),
                                        'path': f"{base_path}\\{subkey_name}"
                                    })
                                    # Debugger pointing to non-Microsoft path is suspicious
                                    d = str(debugger).lower()
                                    if 'system32' not in d and 'syswow64' not in d:
                                        self._add_suspicious(
                                            'IFEO Debugger', f"HKLM\\{base_path}\\{subkey_name}",
                                            'Debugger', debugger,
                                            f"Debugger hijacking - {subkey_name} will run debugger instead. Persistence tactic.", "critical"
                                        )
                            except (FileNotFoundError, OSError):
                                pass
                            winreg.CloseKey(subkey)
                        except (PermissionError, OSError):
                            pass
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        self.results['ifeo_debuggers'] = ifeo_entries
        return ifeo_entries

    def scan_safeboot(self):
        """Scan Safe Boot configuration for modifications."""
        hive, path = self.SAFEBOOT_LOCATION
        try:
            key = self._open_key(hive, path)
            entries = []
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    entries.append({'mode': subkey_name, 'path': f"{path}\\{subkey_name}"})
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
            self.results['safeboot'] = entries
        except Exception:
            self.results['safeboot'] = []

        return self.results['safeboot']

    def scan_lsa_packages(self):
        """Scan LSA Authentication/Security packages - credential theft vector."""
        hive, path = self.LSA_LOCATION
        entries = self.scan_registry_key(hive, path)
        lsa_data = []
        known_good = {'msv1_0', 'kerberos', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'livessp', 'cloudap', 'negoexts', 'msapsspc'}

        for entry in entries:
            if entry['name'].lower() in ['authentication packages', 'security packages', 'notification packages']:
                val = entry['value']
                if isinstance(val, (list, tuple)):
                    val = ','.join(str(v) for v in val)
                val = str(val).strip()
                lsa_data.append({'name': entry['name'], 'value': val})

                if val:
                    packages = [p.strip() for p in re.split(r'[,\s\[\]\'\"]+', val) if p.strip() and len(p.strip()) > 2]
                    for pkg in packages:
                        pkg_lower = pkg.lower()
                        if pkg_lower not in known_good and not pkg_lower.startswith('*'):
                            self._add_suspicious(
                                'LSA Package', f"HKLM\\{path}",
                                entry['name'], val,
                                f"Non-standard LSA package: {pkg}. Potential credential theft.", "critical"
                            )
                            break

        self.results['lsa_packages'] = lsa_data
        return lsa_data

    def scan_session_manager(self):
        """Scan Session Manager BootExecute - early boot execution."""
        hive, path = self.SESSION_MANAGER
        entries = self.scan_registry_key(hive, path)
        sm_data = []

        for entry in entries:
            if entry['name'].lower() in ['bootexecute', 'setupexecute', 'Execute']:
                val = entry['value']
                sm_data.append({'name': entry['name'], 'value': val})

                if val:
                    # Autocheck and native defrag are normal; others need review
                    v = val.lower()
                    if 'autocheck' not in v and 'sdnative' not in v:
                        if len(val) > 20:
                            self._add_suspicious(
                                'Session Manager', f"HKLM\\{path}",
                                entry['name'], val,
                                "Custom BootExecute - runs at early boot. Rootkit persistence.", "critical"
                            )

        self.results['session_manager'] = sm_data
        return sm_data

    def scan_appcert_dlls(self):
        """Scan AppCertDlls - DLLs loaded into processes calling certain APIs."""
        hive, path = self.APP_CERT_DLLS
        entries = self.scan_registry_key(hive, path)
        cert_dlls = []

        for entry in entries:
            if entry['value']:
                cert_dlls.append({'name': entry['name'], 'value': entry['value']})
                self._add_suspicious(
                    'AppCertDlls', f"HKLM\\{path}",
                    entry['name'], entry['value'],
                    "DLL loaded into processes - hooking/injection vector.", "high"
                )

        self.results['appcert_dlls'] = cert_dlls
        return cert_dlls

    def scan_file_associations(self):
        """Scan .exe file association - hijacking."""
        hive, path = self.FILE_ASSOC_EXE
        entries = self.scan_registry_key(hive, path)
        assoc = []

        for entry in entries:
            val = entry['value']
            assoc.append({'name': entry['name'], 'value': val})

            if val:
                is_susp, reason, severity = self.is_suspicious(val)
                if is_susp:
                    self._add_suspicious(
                        'File Association (.exe)', f"HKCR\\{path}",
                        entry['name'], val,
                        f".exe handler anomaly: {reason}", severity
                    )

        self.results['file_associations'] = assoc
        return assoc

    def scan_print_monitors(self):
        """Scan Print Monitors - persistence mechanism."""
        hive, path = self.PRINT_MONITORS
        monitors = []

        try:
            key = self._open_key(hive, path)
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                    try:
                        sk = winreg.OpenKey(key, sub, 0, KEY_READ_64)
                        try:
                            driver, _ = winreg.QueryValueEx(sk, "Driver")
                            monitors.append({'name': sub, 'driver': str(driver)})
                            d = str(driver).lower()
                            if 'system32' not in d and 'spool' not in d:
                                self._add_suspicious(
                                    'Print Monitor', f"HKLM\\{path}\\{sub}",
                                    'Driver', driver,
                                    "Non-standard print monitor - persistence vector.", "medium"
                                )
                        except (FileNotFoundError, OSError):
                            pass
                        winreg.CloseKey(sk)
                    except (PermissionError, OSError):
                        pass
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

        self.results['print_monitors'] = monitors
        return monitors

    def scan_services(self, limit=80):
        """Scan Windows services for suspicious ImagePath."""
        services = []
        hive, path = self.SERVICES_LOCATION

        try:
            key = self._open_key(hive, path)
            i = 0
            count = 0

            while count < limit:
                try:
                    service_name = winreg.EnumKey(key, i)
                    i += 1

                    try:
                        service_key = winreg.OpenKey(key, service_name, 0, KEY_READ_64)

                        try:
                            image_path, _ = winreg.QueryValueEx(service_key, "ImagePath")
                            ip = str(image_path)
                            is_susp, reason, severity = self.is_suspicious(ip)

                            services.append({
                                'name': service_name,
                                'path': ip,
                                'suspicious': is_susp,
                                'reason': reason if is_susp else None,
                                'severity': severity if is_susp else "info"
                            })

                            if is_susp:
                                self._add_suspicious(
                                    'Service', f"HKLM\\{path}\\{service_name}",
                                    service_name, ip, reason, severity
                                )
                            count += 1
                        except (FileNotFoundError, OSError):
                            pass

                        winreg.CloseKey(service_key)
                    except (PermissionError, OSError):
                        pass

                except OSError:
                    break

            winreg.CloseKey(key)
        except Exception as e:
            self.results['errors'].append(f"Error scanning services: {str(e)}")

        self.results['services'] = services
        return services

    def build_anomaly_summary(self):
        """Build summary of anomalies by severity."""
        susp = self.results['suspicious_entries']
        by_severity = defaultdict(list)
        for e in susp:
            by_severity[e.get('severity', 'info')].append(e['type'])

        self.results['anomaly_summary'] = {
            'critical': len(by_severity.get('critical', [])),
            'high': len(by_severity.get('high', [])),
            'medium': len(by_severity.get('medium', [])),
            'low': len(by_severity.get('low', [])),
            'total': len(susp)
        }
        return self.results['anomaly_summary']

    def generate_statistics(self):
        """Generate statistics from scan results."""
        self.build_anomaly_summary()
        summary = self.results['anomaly_summary']

        stats = {
            'total_startup_programs': len(self.results['startup_programs']),
            'total_autostart_folders': len(self.results['autostart_folders']),
            'total_browser_settings': len(self.results['browser_settings']),
            'total_winlogon_entries': len(self.results['winlogon']),
            'total_services_scanned': len(self.results['services']),
            'total_suspicious': len(self.results['suspicious_entries']),
            'suspicious_critical': summary['critical'],
            'suspicious_high': summary['high'],
            'suspicious_medium': summary['medium'],
            'suspicious_low': summary['low'],
            'suspicious_startup': len([e for e in self.results['startup_programs'] if e.get('suspicious')]),
            'suspicious_services': len([s for s in self.results['services'] if s.get('suspicious')]),
            'appinit_count': len(self.results['appinit_dlls']),
            'ifeo_count': len(self.results['ifeo_debuggers']),
            'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        self.results['statistics'] = stats
        return stats

    def perform_full_scan(self):
        """Perform a complete registry security scan."""
        self.scan_startup_programs()
        self.scan_autostart_folders()
        self.scan_browser_settings()
        self.scan_winlogon()
        self.scan_appinit_dlls()
        self.scan_ifeo_debuggers()
        self.scan_safeboot()
        self.scan_lsa_packages()
        self.scan_session_manager()
        self.scan_appcert_dlls()
        self.scan_file_associations()
        self.scan_print_monitors()
        self.scan_services()
        self.generate_statistics()

        return self.results


if __name__ == "__main__":
    scanner = RegistryScanner()
    results = scanner.perform_full_scan()

    print("\n=== REGISTRY SCAN RESULTS ===")
    print(f"Startup Programs: {results['statistics']['total_startup_programs']}")
    print(f"Suspicious Entries: {results['statistics']['total_suspicious']}")
    print(f"  Critical: {results['statistics']['suspicious_critical']}")
    print(f"  High: {results['statistics']['suspicious_high']}")

    if results['suspicious_entries']:
        print("\n=== SUSPICIOUS ENTRIES ===")
        for entry in results['suspicious_entries'][:10]:
            print(f"[{entry.get('severity', '?')}] {entry['type']}: {entry['name']}")
            print(f"    Location: {entry['location']}")
            print(f"    Reason: {entry['reason']}\n")

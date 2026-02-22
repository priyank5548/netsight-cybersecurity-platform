import sys
import os
import hashlib
import math
import re
import datetime
import pefile
import yara
from io import StringIO

# --- LIBRARIES ---
try:
    import pefile
    import puremagic
    from oletools.olevba import VBA_Parser
except ImportError as e:
    raise ImportError("Missing libraries. Run: pip install pefile puremagic oletools")

# --- CONFIGURATION ---
KNOWN_MALWARE_DB = {
    'b48f58334c6799d5543c72b2260f8983': {'family': 'WannaCry', 'type': 'Ransomware'},
    '87bed5a7cba00c7e1f4015f1bbede187': {'family': 'Ryuk', 'type': 'Ransomware'},
}

PATTERNS = {
    "IPv4 Address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "URL": r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
    "Registry Keys": r"HKEY_\w+",
    "Suspicious Commands": r"(cmd\.exe|powershell|/bin/sh|/bin/bash|wget|curl)"
}

EMBEDDED_SIGNATURES = {
    b'PK\x03\x04': "ZIP Archive / Office Doc",
    b'MZ': "Windows Executable (EXE)",
    b'%PDF': "PDF Document",
    b'\x7fELF': "Linux Executable"
}


class WebUniversalAnalyzer:
    """
    Modified version of UniversalAnalyzer that returns structured output
    suitable for web display instead of printing to console.
    """
    def __init__(self, file_path):
        self.file_path = file_path
        self.filename = os.path.basename(file_path)
        self.results = {
            'filename': self.filename,
            'identification': {},
            'threat_attribution': {},
            'pe_analysis': {},
            'embedded_files': [],
            'content_scan': {},
            'size_analysis': {},
            'extra_info': {},
            'yara_results': {},
            'errors': []
        }
        try:
            with open(file_path, 'rb') as f:
                self.data = f.read()
        except Exception as e:
            self.results['errors'].append(f"Error reading file: {e}")

    def get_hashes(self):
        md5 = hashlib.md5(self.data).hexdigest()
        sha256 = hashlib.sha256(self.data).hexdigest()
        return md5, sha256

    def calculate_entropy(self):
        if not self.data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(self.data.count(x)) / len(self.data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def extract_strings(self):
        try:
            content_str = self.data.decode('utf-8', 'ignore')
        except:
            self.results['content_scan']['error'] = "Error decoding data"
            return

        found_patterns = {}
        for label, pattern in PATTERNS.items():
            matches = list(set(re.findall(pattern, content_str)))
            if matches:
                found_patterns[label] = matches[:10]  # Limit to 10 matches
        
        self.results['content_scan'] = found_patterns if found_patterns else {'status': 'No suspicious patterns found'}

    def scan_embedded(self):
        embedded = {}
        for signature, desc in EMBEDDED_SIGNATURES.items():
            matches = [m.start() for m in re.finditer(re.escape(signature), self.data)]
            matches = [m for m in matches if m != 0]

            if matches:
                embedded[desc] = [hex(offset) for offset in matches[:10]]  # Limit to 10
        
        self.results['embedded_files'] = embedded if embedded else {'status': 'No hidden files detected'}

    def check_threat_attribution(self, pe_object=None):
        imphash = None
        if pe_object:
            try:
                imphash = pe_object.get_imphash()
            except:
                pass

        if imphash:
            self.results['threat_attribution']['imphash'] = imphash
            if imphash in KNOWN_MALWARE_DB:
                info = KNOWN_MALWARE_DB[imphash]
                self.results['threat_attribution']['status'] = 'KNOWN THREAT DETECTED'
                self.results['threat_attribution']['family'] = info['family']
                self.results['threat_attribution']['type'] = info['type']
            else:
                self.results['threat_attribution']['status'] = 'Unknown (Not in local DB)'
        else:
            self.results['threat_attribution']['status'] = 'N/A (Not a PE File)'

    def analyze_pe_advanced(self, pe):
        pe_data = {}
        
        # Digital Signature Check
        try:
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if sec_dir.VirtualAddress == 0:
                pe_data['signature'] = 'UNSIGNED FILE (Risk)'
            else:
                pe_data['signature'] = 'Digitally Signed'
        except:
            pe_data['signature'] = 'Unknown'

        # Packer Detection
        packed_sections = []
        for section in pe.sections:
            try:
                name = section.Name.decode('utf-8', 'ignore').strip('\x00')
            except:
                name = "Unknown"

            if any(x in name for x in ['.UPX', 'UPX0', 'UPX1']):
                packed_sections.append(name)

        pe_data['packer'] = packed_sections if packed_sections else 'No common packer detected'

        # Compilation Time
        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            ts_date = datetime.datetime.fromtimestamp(ts)
            pe_data['compiled'] = str(ts_date)
            if ts_date.year > datetime.datetime.now().year:
                pe_data['timestomping'] = 'DETECTED (Future Date)'
        except:
            pe_data['compiled'] = 'Error reading timestamp'

        # Dangerous APIs
        suspicious_apis = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "ShellExecute"]
        found_apis = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        n = imp.name.decode('utf-8', 'ignore')
                        for bad in suspicious_apis:
                            if bad in n: 
                                found_apis.append(n)

        pe_data['dangerous_apis'] = list(set(found_apis)) if found_apis else 'None detected'

        self.results['pe_analysis'] = pe_data

    def malware_size(self, pe):
        try:
            raw_size = sum(section.SizeOfRawData for section in pe.sections)
            virtual_size = sum(section.Misc_VirtualSize for section in pe.sections)
            ratio = (virtual_size/raw_size) if raw_size > 0 else None

            self.results['size_analysis'] = {
                'raw_size': raw_size,
                'virtual_size': virtual_size,
                'ratio': ratio,
                'suspicious': ratio > 0.2 if ratio else False
            }
        except Exception as e:
            self.results['size_analysis']['error'] = str(e)
    
    def extra_info(self, pe):
        try:
            extra = {}
            
            # RWX sections
            rwx_sections = []
            normal_sections = []
            for section in pe.sections:
                name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                if section.IMAGE_SCN_MEM_EXECUTE and section.IMAGE_SCN_MEM_WRITE:
                    rwx_sections.append(name)
                else:
                    normal_sections.append(name)

            extra['rwx_sections'] = rwx_sections if rwx_sections else 'None detected'
            extra['normal_sections'] = normal_sections

            # Entry point
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            for section in pe.sections:
                if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                    extra['entry_point_section'] = section.Name.decode('utf-8', 'ignore').strip('\x00')
                    break
            
            # Import count
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                import_count = sum(len(e.imports) for e in pe.DIRECTORY_ENTRY_IMPORT)
                extra['import_count'] = import_count
                extra['packed_loader'] = import_count < 10

            self.results['extra_info'] = extra
        except Exception as e:
            self.results['extra_info']['error'] = str(e)

    def yara_scan(self, rule_root):
        if not os.path.exists(rule_root):
            self.results['yara_results'] = {'error': 'YARA rules directory not found'}
            return

        compiled_rules = []
        skipped = 0
        matched_rules = []

        # Compile rules
        for root, _, files in os.walk(rule_root):
            for file in files:
                if file.endswith((".yar", ".yara")):
                    path = os.path.join(root, file)
                    try:
                        rules = yara.compile(filepath=path)
                        compiled_rules.append((path, rules))
                    except Exception as e:
                        skipped += 1

        # Scan
        for rule_path, rules in compiled_rules:
            try:
                matches = rules.match(self.file_path, timeout=60)
                if matches:
                    for match in matches:
                        matched_rules.append({
                            'file': os.path.basename(rule_path),
                            'rule': match.rule
                        })
            except Exception as e:
                pass

        self.results['yara_results'] = {
            'loaded_rules': len(compiled_rules),
            'skipped_rules': skipped,
            'matches': matched_rules if matched_rules else 'No YARA matches found'
        }

    def run(self):
        # Identification
        md5, sha256 = self.get_hashes()
        self.results['identification']['md5'] = md5
        self.results['identification']['sha256'] = sha256

        try:
            formats = puremagic.magic_string(self.data)
            true_fmt = formats[0].name if formats else "Unknown"
        except:
            true_fmt = "Unknown"

        decl_ext = os.path.splitext(self.filename)[1].lower() or "(none)"
        self.results['identification']['extension'] = decl_ext
        self.results['identification']['format'] = true_fmt

        # Try to parse as PE
        pe_object = None
        is_valid_pe = False
        try:
            pe_object = pefile.PE(data=self.data)
            is_valid_pe = True
        except:
            is_valid_pe = False

        # Extension spoofing check
        if is_valid_pe and ".exe" not in decl_ext and ".dll" not in decl_ext:
            self.results['identification']['spoofing'] = f"Extension Spoofing Detected! (Is PE, but named {decl_ext})"

        # Entropy
        entropy = self.calculate_entropy()
        self.results['identification']['entropy'] = round(entropy, 3)
        self.results['identification']['entropy_suspicious'] = entropy > 7.2

        # Module execution
        self.check_threat_attribution(pe_object)

        if is_valid_pe and pe_object:
            self.analyze_pe_advanced(pe_object)
            self.malware_size(pe_object)
            self.extra_info(pe_object)

        self.scan_embedded()
        self.extract_strings()

        # YARA scan
        yara_path = os.path.join(os.path.dirname(self.file_path), '..', 'file_analysis', 'yara_rules')
        if os.path.exists(yara_path):
            self.yara_scan(yara_path)

        return self.results


def analyze_file_for_web(file_path):
    """
    Wrapper function to analyze a file and return results suitable for web display.
    """
    analyzer = WebUniversalAnalyzer(file_path)
    return analyzer.run()

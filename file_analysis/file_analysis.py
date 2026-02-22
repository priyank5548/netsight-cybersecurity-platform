import sys
import os
import hashlib
import math
import re
import datetime
import pefile
import yara

# --- LIBRARIES ---
try:
    import pefile
    import puremagic
    from oletools.olevba import VBA_Parser
    from colorama import init, Fore, Style, Back
except ImportError as e:
    print("[-] CRITICAL: Missing libraries.")
    print("    Run: pip install pefile puremagic oletools colorama")
    sys.exit(1)

init(autoreset=True)

# --- CONFIGURATION ---
KNOWN_MALWARE_DB = {
    'b48f58334c6799d5543c72b2260f8983': {'family': 'WannaCry', 'type': 'Ransomware'},
    '87bed5a7cba00c7e1f4015f1bbede187': {'family': 'Ryuk', 'type': 'Ransomware'},
    # Add your test file hashes here!
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


class UniversalAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.filename = os.path.basename(file_path)
        try:
            with open(file_path, 'rb') as f:
                self.data = f.read()
        except Exception as e:
            print(f"[-] Error reading file: {e}")
            sys.exit(1)

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
        print(f"\n{Back.RED}{Fore.WHITE}[*] SCANNING CONTENT (Offline Regex)...")
        try:
            content_str = self.data.decode('utf-8', 'ignore')
        except:
            print("Error in the data decode in the def extract_strings")
            return

        found = False
        for label, pattern in PATTERNS.items():
            matches = list(set(re.findall(pattern, content_str)))
            if matches:
                found = True
                print(f"    {Fore.YELLOW}Found {label}s:")
                for m in matches[:5]:
                    print(f"        -> {m}")
        
        print(" ")
        if not found:
            print(f"    {Fore.GREEN}[+] No suspicious text strings found.")
            print(" ")

    def scan_embedded(self):
        print(f"\n{Back.CYAN} {Fore.CYAN}[*] SCANNING FOR EMBEDDED FILES (Dropper Check)...")
        found = False
        for signature, desc in EMBEDDED_SIGNATURES.items():
            # Find signature, skip index 0
            matches = [m.start() for m in re.finditer(re.escape(signature), self.data)]
            matches = [m for m in matches if m != 0]

            if matches:
                found = True
                # print(f"    {Fore.MAGENTA}[!] Found Hidden {desc}:")
                count=len(matches)
                found_embedded = True
                print(f"    {Fore.MAGENTA}[!] Found Hidden {desc}: {count} Detected.")
                # Limit display to first 5 matches to keep output clean
                for offset in matches:
                    # Convert decimal offset to Hex (e.g., 0x4A00)
                    print(f"        -> Located at Offset: {Fore.WHITE}{hex(offset)}")
        if not found:
            print(f"    {Fore.GREEN}[+] No hidden files detected.")

    def check_threat_attribution(self, pe_object=None):
        print(f"\n{Back.RED}{Fore.WHITE} --- THREAT ATTRIBUTION --- {Style.RESET_ALL}")
        imphash = None

        # Try to get Imphash from the PE object if it exists
        if pe_object:
            imphash = pe_object.get_imphash()

        if imphash:
            print(f"    Imphash:    {Fore.YELLOW}{imphash}")
            if imphash in KNOWN_MALWARE_DB:
                info = KNOWN_MALWARE_DB[imphash]
                print(f"    Status:     {Fore.RED}KNOWN THREAT DETECTED")
                print(f"    Family:     {Fore.RED}{info['family']}")
            else:
                print(f"    Status:     {Fore.GREEN}Unknown (Not in local DB)")
        else:
            print(f"    Status:     {Fore.WHITE}N/A (Not a PE File)")

    def analyze_pe_advanced(self, pe):
        """
        Runs deep analysis. 'pe' is the pre-loaded pefile object.
        """
        print(f"\n{Back.BLUE}{Fore.WHITE} --- WINDOWS PE DEEP ANALYSIS --- {Style.RESET_ALL}")

        # 1. Digital Signature Check
        try:
            # Index 4 is the SECURITY directory
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if sec_dir.VirtualAddress == 0:
                print(f"    Signature:   {Fore.RED}[!] UNSIGNED FILE (Risk)")
            else:
                print(f"    Signature:   {Fore.GREEN}[OK] Digitally Signed (Presence Detected)")
        except:
            print(f"    Signature:   {Fore.WHITE}Unknown (Structure Error)")

        # 2. Packer Detection (via Section Names)
        print("    Packer Check: Scanning Section Names...")
        is_packed = False
        for section in pe.sections:
            try:
                name = section.Name.decode('utf-8', 'ignore').strip('\x00')
            except:
                name = "Unknown"

            # Check for UPX or odd section names
            if any(x in name for x in ['.UPX', 'UPX0', 'UPX1']):
                print(f"        -> {Fore.RED}[!] PACKER DETECTED: UPX ({name})")
                is_packed = True

        if not is_packed:
            print(f"        -> {Fore.GREEN}[+] No common packer names found.")

        # 3. Compilation Time
        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            ts_date = datetime.datetime.fromtimestamp(ts)
            print(f"    Compiled:    {Fore.YELLOW}{ts_date}")
            if ts_date.year > datetime.datetime.now().year:
                print(f"    {Fore.RED}    [!] TIMESTOMPING DETECTED (Future Date)")
        except:
            print(f"{Fore.RED} ERROR READING TIMESRAMP")
            pass

        # 4. Imports (Dangerous APIs)
        suspicious_apis = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "ShellExecute"]
        found_apis = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        n = imp.name.decode('utf-8')
                        for bad in suspicious_apis:
                            if bad in n: found_apis.append(n)

        if found_apis:
            print(f"    Dangerous APIs: {Fore.RED}{list(set(found_apis))}")

    def run(self):
        print(f"{Style.BRIGHT}=== UNIVERSAL ANALYZER v6.0 (Aggressive Mode) ===")
        print(f"Target: {self.filename}")

        # Identity
        md5, _ = self.get_hashes()
        print(f"\n{Back.CYAN} {Fore.WHITE}[*] IDENTIFICATION")
        print(f"    MD5: {md5}")

        try:
            formats = puremagic.magic_string(self.data)
            true_fmt = formats[0].name if formats else "Unknown"
        except:
            true_fmt = "Unknown (ERROR: ukknown in the puremagic puremagic)"

        decl_ext = os.path.splitext(self.filename)[1].lower() or "(none)"
        print(f"    Appear: {Fore.YELLOW}{decl_ext}")
        print(f"    Format: {Fore.GREEN}{true_fmt}")

        # --- LOGIC FIX: AGGRESSIVE PE PARSING ---
        # We try to create a PE object regardless of what puremagic says.
        pe_object = None
        is_valid_pe = False
        try:
            pe_object = pefile.PE(data=self.data)
            is_valid_pe = True
        except:
            print(f"{Fore.RED} ERROR CREAING THE PE OBJECT")
            is_valid_pe = False

        # Extension Spoofing Check
        # If it is a valid PE but extension is not .exe/.dll
        if is_valid_pe and ".exe" not in decl_ext and ".dll" not in decl_ext:
            print(f"    {Fore.RED}[!!!] CRITICAL: Extension Spoofing Detected! (Is PE, but named {decl_ext})")

        # Entropy
        entropy = self.calculate_entropy()
        ent_c = Fore.RED if entropy > 7.2 else Fore.GREEN
        print(f"    Entropy: {ent_c}{entropy:.3f} / 8.000")

        # --- MODULE EXECUTION ---

        # 1. Threat Attribution (Passes PE object if it exists)
        self.check_threat_attribution(pe_object)

        # 2. Deep PE Analysis (Runs if PE object exists, IGNORING Format Name)
        if is_valid_pe:
            self.analyze_pe_advanced(pe_object)
        else:
            print(f"\n{Fore.CYAN}[*] File is generic/data. Skipping Windows PE analysis.")

        
        yara_rule_folder="yara_rules"

        # 3. Other Scans
        self.scan_embedded()
        self.extract_strings()
        self.malware_size()
        self.extra_info()
        self.yara_scan(yara_rule_folder, self.file_path)

        print(f"\n{Style.BRIGHT}=== ANALYSIS COMPLETE ===")


    def malware_size(self):
        try:

            virtual_size = 0
            ratio = 0

    
            pe = pefile.PE(target_file, fast_load=True)
            pe.parse_data_directories()

            raw_size = sum(section.SizeOfRawData for section in pe.sections)

            virtual_size = sum(
                section.Misc_VirtualSize for section in pe.sections
            )

            ratio = (virtual_size/raw_size) if raw_size > 0 else None

            print(f"{Back.GREEN} {Fore.WHITE} [*] SIZE")
            print(f"Raw Size: {raw_size}")
            print(f"Virtual Size: {virtual_size}")
            print(f"{Fore.GREEN}Ratio: {ratio}" if ratio < 0.2 else f"{Fore.RED} Ratio: {ratio}")
            print(" ")

        except:
            print(f"{Fore.RED}SIZE ANALYSIS ERROR")
            print(" ")
    
    def extra_info(self):
        try:
            pe = pefile.PE(self.file_path)
            print(f"{Back.BLUE}{Fore.WHITE}[*] EXTRA INFO ")

            for section in pe.sections:
                if section.IMAGE_SCN_MEM_EXECUTE and section.IMAGE_SCN_MEM_WRITE:
                    print(f"{section.Name.decode()}:" f"{Fore.RED} [!] RWX section detected")
                else:
                    print(f"{section.Name.decode()}:" f"{Fore.GREEN} No RWX section detected")

            print(" ")
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            for section in pe.sections:
                if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                    print(f"Entry point in section: {section.Name}")
            
            print(" ")
            import_count = sum(len(e.imports) for e in pe.DIRECTORY_ENTRY_IMPORT)
            if import_count < 10:
                print(f"{Fore.RED} [!] Low import count (possible packed loader): {import_count}" )
            else:
                print(f"{Fore.GREEN} High import count (No packed loader): {import_count} ")



        except Exception as e:
            print(f"{Fore.RED} ERROR IN THE EXTRA INFO :")
            print(f"{e}")  


    def yara_scan(self, rule_root, sample_path):
        compiled_rules = []
        skipped = 0
        matched = 0

        print("\n\n")
        print(f"{Back.LIGHTBLUE_EX}{Fore.WHITE}[*] YARA RULES\n")

        # 1️⃣ Compile each rule file safely
        print(f"{Fore.MAGENTA} SKIP RULES:")
        for root, _, files in os.walk(rule_root):
            for file in files:
                if file.endswith((".yar", ".yara")):
                    path = os.path.join(root, file)
                    try:
                        rules = yara.compile(filepath=path)
                        compiled_rules.append((path, rules))
                    except Exception as e:
                        skipped += 1
                        print(f"[{skipped}] Skipped rule: {path}")
                        print(f"    Reason: {e}")

        print("")
        print(f"{Fore.MAGENTA} [+] Loaded {len(compiled_rules)} rule files")
        print(f"{Fore.MAGENTA} [!] Skipped {skipped} incompatible rules\n")


        print(f"{Fore.MAGENTA}MATCH RULES:")
        # 2️⃣ Scan the sample
        detected = False
        for rule_path, rules in compiled_rules:
            try:
                matches = rules.match(sample_path, timeout=60)
                if matches:
                    detected = True
                    matched+= 1
                    print(f"[{matched}] Match from {rule_path}")
                    for match in matches:
                        print(f"    Rule: {match.rule}")
                    print("-" * 50)
            except Exception as e:
                print(f"[!] Scan error with {rule_path}: {e}")

        if not detected:
            print(f"{Fore.GREEN}[-] No YARA matches found")
        
        total = len(compiled_rules) + skipped + matched
        print(f"{Fore.MAGENTA} [+] TOTAL: {total}")

        print("\n")    






       


if __name__ == "__main__":
    target_file = input("Enter path to file: ").strip().strip('"')
    if os.path.exists(target_file):
        UniversalAnalyzer(target_file).run()
    else:
        print("[-] File not found.")
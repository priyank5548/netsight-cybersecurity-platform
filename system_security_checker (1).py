import subprocess

class SystemSecurityChecker:
    def check_security(self):
        findings = []
        score = 100
        
        # 1. Check Firewall (Windows)
        try:
            output = subprocess.check_output("netsh advfirewall show allprofiles state", shell=True).decode()
            if "OFF" in output:
                findings.append("CRITICAL: Windows Firewall is disabled on one or more profiles.")
                score -= 30
        except:
            findings.append("Error checking firewall status.")

        # 2. Check Windows Defender (Service Status)
        try:
            # sc query WinDefend
            output = subprocess.check_output("sc query WinDefend", shell=True).decode()
            if "STOPPED" in output:
                findings.append("CRITICAL: Windows Defender service is STOPPED.")
                score -= 40
        except:
            pass

        return {
            "system_score": max(0, score),
            "findings": findings
        }
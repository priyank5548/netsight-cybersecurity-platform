"""
MODULE 6: Firewall & System Security Checker
Windows security configuration analysis
"""

import subprocess
import winreg
import json
from typing import Dict, List
from datetime import datetime

from config.logging_config import get_logger

logger = get_logger(__name__)


class SystemSecurityChecker:
    """System security configuration analyzer for Windows"""
    
    def __init__(self, config_path: str = "config/config.json"):
        """
        Initialize system security checker
        
        Args:
            config_path: Path to configuration file
        """
        logger.info("SystemSecurityChecker initialized")
    
    def analyze(self) -> Dict:
        """
        Perform comprehensive system security check
        
        Returns:
            Dictionary with security check results
        """
        logger.info("Starting system security analysis")
        
        try:
            # Check Windows Defender status
            defender_status = self._check_defender_status()
            
            # Check firewall status
            firewall_status = self._check_firewall_status()
            
            # Check UAC status
            uac_status = self._check_uac_status()
            
            # Check Windows Update status
            update_status = self._check_update_status()
            
            # Check open ports
            open_ports = self._check_open_ports()
            
            # Check security policies
            security_policies = self._check_security_policies()
            
            # Detect misconfigurations
            misconfigurations = self._detect_misconfigurations(
                defender_status,
                firewall_status,
                uac_status,
                update_status
            )
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(
                defender_enabled=defender_status.get('enabled', False),
                firewall_enabled=firewall_status.get('enabled', False),
                uac_enabled=uac_status.get('enabled', False),
                misconfigurations=len(misconfigurations)
            )
            
            risk_level = self._get_risk_level(risk_score)
            
            # Generate explanation
            explanation = self._generate_explanation(misconfigurations)
            
            result = {
                "timestamp": datetime.now().isoformat(),
                "defender_status": defender_status,
                "firewall_status": firewall_status,
                "uac_status": uac_status,
                "update_status": update_status,
                "open_ports": open_ports,
                "security_policies": security_policies,
                "misconfigurations": misconfigurations,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "explanation": explanation,
                "recommendations": self._generate_recommendations(misconfigurations)
            }
            
            logger.info(f"System security analysis complete - Risk Score: {risk_score}/100")
            return result
            
        except Exception as e:
            logger.error(f"Error during system security analysis: {e}")
            return self._error_result(str(e))
    
    def _check_defender_status(self) -> Dict:
        """Check Windows Defender status"""
        status = {
            "enabled": False,
            "real_time_protection": False,
            "details": []
        }
        
        try:
            # Try PowerShell command to get Defender status
            cmd = 'powershell -Command "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled | ConvertTo-Json"'
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=True)
            
            if result.returncode == 0 and result.stdout:
                # Parse JSON output
                import json
                defender_info = json.loads(result.stdout)
                status['enabled'] = defender_info.get('AntivirusEnabled', False)
                status['real_time_protection'] = defender_info.get('RealTimeProtectionEnabled', False)
            
        except Exception as e:
            logger.debug(f"Error checking Defender status: {e}")
            status['details'].append("Could not determine Defender status")
        
        return status
    
    def _check_firewall_status(self) -> Dict:
        """Check Windows Firewall status for all profiles"""
        status = {
            "enabled": False,
            "profiles": {}
        }
        
        try:
            # Check firewall status using netsh
            cmd = 'netsh advfirewall show allprofiles state'
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=True)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse output for each profile
                profiles = ['Domain', 'Private', 'Public']
                for profile in profiles:
                    if f"{profile} Profile" in output:
                        # Look for "State" line after profile name
                        lines = output.split('\n')
                        for i, line in enumerate(lines):
                            if profile in line:
                                # Check next few lines for State
                                for j in range(i, min(i+5, len(lines))):
                                    if 'State' in lines[j]:
                                        if 'ON' in lines[j].upper():
                                            status['profiles'][profile] = True
                                        else:
                                            status['profiles'][profile] = False
                                        break
                
                # Overall enabled if at least one profile is on
                status['enabled'] = any(status['profiles'].values())
            
        except Exception as e:
            logger.debug(f"Error checking firewall status: {e}")
        
        return status
    
    def _check_uac_status(self) -> Dict:
        """Check User Account Control (UAC) status"""
        status = {
            "enabled": False,
            "level": "Unknown"
        }
        
        try:
            # Check registry for UAC settings
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                0,
                winreg.KEY_READ
            )
            
            # EnableLUA = 1 means UAC is enabled
            enable_lua, _ = winreg.QueryValueEx(key, "EnableLUA")
            status['enabled'] = bool(enable_lua)
            
            # ConsentPromptBehaviorAdmin determines the level
            consent_prompt, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
            
            uac_levels = {
                0: "Never notify",
                1: "Notify without secure desktop",
                2: "Notify with secure desktop",
                5: "Always notify"
            }
            status['level'] = uac_levels.get(consent_prompt, "Unknown")
            
            winreg.CloseKey(key)
            
        except Exception as e:
            logger.debug(f"Error checking UAC status: {e}")
        
        return status
    
    def _check_update_status(self) -> Dict:
        """Check Windows Update status"""
        status = {
            "auto_update_enabled": "Unknown",
            "details": []
        }
        
        try:
            # Check Windows Update service status
            cmd = 'sc query wuauserv'
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=True)
            
            if result.returncode == 0:
                if 'RUNNING' in result.stdout:
                    status['auto_update_enabled'] = True
                    status['details'].append("Windows Update service is running")
                else:
                    status['auto_update_enabled'] = False
                    status['details'].append("Windows Update service is not running")
            
        except Exception as e:
            logger.debug(f"Error checking Windows Update status: {e}")
        
        return status
    
    def _check_open_ports(self) -> List[Dict]:
        """Check for open/listening ports"""
        open_ports = []
        
        try:
            # Use netstat to get listening ports
            cmd = 'netstat -an'
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                
                for line in lines:
                    if 'LISTENING' in line or 'ESTABLISHED' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            local_addr = parts[1]
                            state = parts[3] if len(parts) > 3 else 'UNKNOWN'
                            
                            # Extract port
                            if ':' in local_addr:
                                port = local_addr.split(':')[-1]
                                
                                # Only include if it's a valid port number
                                if port.isdigit():
                                    open_ports.append({
                                        "port": int(port),
                                        "address": local_addr,
                                        "state": state
                                    })
            
        except Exception as e:
            logger.debug(f"Error checking open ports: {e}")
        
        # Deduplicate ports
        unique_ports = {}
        for port_info in open_ports:
            port = port_info['port']
            if port not in unique_ports:
                unique_ports[port] = port_info
        
        return list(unique_ports.values())[:20]  # Limit to 20
    
    def _check_security_policies(self) -> Dict:
        """Check security policies"""
        policies = {
            "password_complexity": "Unknown",
            "account_lockout": "Unknown"
        }
        
        # Note: Full implementation would use secpol.msc export or WMI queries
        # This is simplified
        
        return policies
    
    def _detect_misconfigurations(self, defender_status: Dict, firewall_status: Dict,
                                  uac_status: Dict, update_status: Dict) -> List[str]:
        """Detect security misconfigurations"""
        misconfigurations = []
        
        # Check Defender
        if not defender_status.get('enabled', False):
            misconfigurations.append("Windows Defender is disabled")
        
        if not defender_status.get('real_time_protection', False):
            misconfigurations.append("Real-time protection is disabled")
        
        # Check Firewall
        if not firewall_status.get('enabled', False):
            misconfigurations.append("Windows Firewall is disabled")
        
        profiles = firewall_status.get('profiles', {})
        if 'Public' in profiles and not profiles['Public']:
            misconfigurations.append("Public profile firewall is disabled")
        
        # Check UAC
        if not uac_status.get('enabled', False):
            misconfigurations.append("User Account Control (UAC) is disabled")
        elif uac_status.get('level') == "Never notify":
            misconfigurations.append("UAC is set to lowest level")
        
        # Check Windows Update
        if update_status.get('auto_update_enabled') == False:
            misconfigurations.append("Windows Update service is not running")
        
        return misconfigurations
    
    def _calculate_risk_score(self, defender_enabled: bool, firewall_enabled: bool,
                             uac_enabled: bool, misconfigurations: int) -> int:
        """Calculate overall system security risk score (0-100)"""
        score = 0
        
        # Critical security features disabled
        if not defender_enabled:
            score += 35
        
        if not firewall_enabled:
            score += 30
        
        if not uac_enabled:
            score += 20
        
        # Additional misconfigurations
        score += misconfigurations * 5
        
        return min(100, score)
    
    def _get_risk_level(self, score: int) -> str:
        """Convert score to risk level"""
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_explanation(self, misconfigurations: List[str]) -> str:
        """Generate human-readable explanation"""
        if misconfigurations:
            return f"Found {len(misconfigurations)} security misconfigurations: " + ", ".join(misconfigurations[:3])
        else:
            return "System security configuration appears correct"
    
    def _generate_recommendations(self, misconfigurations: List[str]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if "Windows Defender is disabled" in misconfigurations:
            recommendations.append("Enable Windows Defender antivirus protection")
        
        if "Real-time protection is disabled" in misconfigurations:
            recommendations.append("Enable real-time protection in Windows Defender")
        
        if "Windows Firewall is disabled" in misconfigurations:
            recommendations.append("Enable Windows Firewall for all network profiles")
        
        if "User Account Control (UAC) is disabled" in misconfigurations:
            recommendations.append("Enable User Account Control (UAC)")
        
        if "Windows Update service is not running" in misconfigurations:
            recommendations.append("Enable and start Windows Update service")
        
        if not recommendations:
            recommendations.append("System security settings are properly configured")
            recommendations.append("Continue monitoring and keep system updated")
        
        return recommendations
    
    def _error_result(self, error_message: str) -> Dict:
        """Return error result"""
        return {
            "error": error_message,
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "recommendations": ["Run with administrator privileges for full analysis"]
        }


# Standalone function for quick analysis
def check_system_security() -> Dict:
    """
    Quick system security check function
    
    Returns:
        Analysis results dictionary
    """
    checker = SystemSecurityChecker()
    return checker.analyze()


if __name__ == "__main__":
    # Test the checker
    checker = SystemSecurityChecker()
    result = checker.analyze()
    
    print("=== SYSTEM SECURITY CHECK RESULT ===\n")
    print(f"Windows Defender: {'Enabled' if result.get('defender_status', {}).get('enabled') else 'Disabled'}")
    print(f"Firewall: {'Enabled' if result.get('firewall_status', {}).get('enabled') else 'Disabled'}")
    print(f"UAC: {'Enabled' if result.get('uac_status', {}).get('enabled') else 'Disabled'}")
    print(f"Risk Score: {result.get('risk_score', 0)}/100")
    print(f"Risk Level: {result.get('risk_level', 'UNKNOWN')}")
    print(f"\nExplanation: {result.get('explanation', 'N/A')}")
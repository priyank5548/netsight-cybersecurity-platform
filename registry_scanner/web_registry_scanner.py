"""
Web interface for Registry Security Scanner.
"""
from .registry_scanner import RegistryScanner


def scan_registry_for_web():
    """
    Perform registry security scan and return results formatted for web display.
    """
    try:
        scanner = RegistryScanner()
        results = scanner.perform_full_scan()

        return {
            'status': 'success',
            'statistics': results['statistics'],
            'startup_programs': results['startup_programs'],
            'autostart_folders': results['autostart_folders'],
            'browser_settings': results['browser_settings'],
            'winlogon': results['winlogon'],
            'services': results['services'],
            'suspicious_entries': results['suspicious_entries'],
            'appinit_dlls': results['appinit_dlls'],
            'ifeo_debuggers': results['ifeo_debuggers'],
            'safeboot': results['safeboot'],
            'lsa_packages': results['lsa_packages'],
            'session_manager': results['session_manager'],
            'appcert_dlls': results['appcert_dlls'],
            'file_associations': results['file_associations'],
            'print_monitors': results['print_monitors'],
            'anomaly_summary': results['anomaly_summary'],
            'errors': results['errors'],
        }

    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'statistics': {},
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
            'anomaly_summary': {},
            'errors': [str(e)],
        }

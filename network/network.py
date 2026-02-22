import socket
import psutil
import requests
import ipaddress
import subprocess
import re
import nmap
import dns
from pysnmp.hlapi import *

COMMON_PORTS = "21,22,23,80,443,445,3389,161"

# ---------------- BASIC INFO ---------------- #

def get_interface_network():
    interfaces = psutil.net_if_addrs()

    for interface_name, addrs in interfaces.items():

        # Look specifically for Wi-Fi adapter
        if "wi-fi" in interface_name.lower() or "wireless" in interface_name.lower():

            for addr in addrs:
                if addr.family == socket.AF_INET:

                    ip = addr.address

                    # Skip loopback & APIPA
                    if ip.startswith("127.") or ip.startswith("169.254"):
                        continue

                    network = ipaddress.IPv4Network(
                        f"{ip}/{addr.netmask}",
                        strict=False
                    )

                    return ip, network


    return None, None


def get_public_info():
    try:
        return requests.get("https://ipinfo.io/json", timeout=3).json()
    except:
        return {}


def parse_dhcp_dns():
    output = subprocess.check_output("ipconfig /all", shell=True).decode(errors="ignore")
    dhcp = re.findall(r"DHCP Server.*?:\s+([\d\.]+)", output)
    dns = re.findall(r"DNS Servers.*?:\s+([\d\.]+)", output)
    return list(set(dhcp)), list(set(dns))


# ---------------- HOST DISCOVERY (UPDATED) ---------------- #

def discover_hosts_with_nmap(network):
    hosts = []
    try:
        nm = nmap.PortScanner(nmap_search_path=(
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ))

        # -sn = host discovery only
        nm.scan(hosts=str(network), arguments="-sn")

        for host in nm.all_hosts():
            hosts.append(host)

    except Exception:
        pass

    return hosts


# ---------------- OS GUESS ---------------- #

def ttl_guess_from_nmap(nmap_data):
    if "osmatch" in nmap_data and nmap_data["osmatch"]:
        return nmap_data["osmatch"][0]["name"]
    return "Unknown"


# ---------------- NMAP PORT SCAN ---------------- #

def nmap_scan(ip):
    try:
        nm = nmap.PortScanner(nmap_search_path=(
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ))

        nm.scan(ip, arguments=f"-sS -sV -O -Pn -p {COMMON_PORTS}")

        return nm[ip] if ip in nm.all_hosts() else {}
    except:
        return {}


# ---------------- SNMP ---------------- #

def snmp_sysdesc(ip):
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData('public'),
            UdpTransportTarget((ip, 161), timeout=1, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if not errorIndication and not errorStatus:
            for varBind in varBinds:
                return str(varBind[1])
    except:
        pass
    return None


# ---------------- NETBIOS ---------------- #

def netbios_name(ip):
    try:
        output = subprocess.check_output(
            f"nbtstat -A {ip}",
            shell=True
        ).decode(errors="ignore")

        match = re.search(r"(\w+)\s+<00>", output)
        if match:
            return match.group(1)
    except:
        pass
    return None


# ---------------- MAIN ---------------- #

def main():
    print("\n===== NETWORK ENGINEERING ANALYZER v5 =====\n")

    local_ip, network = get_interface_network()
    if not network:
        print("No active interface found.")
        return

    print("NETWORK SUMMARY")
    print("---------------")
    print(f"Local IP: {local_ip}")
    print(f"Network Range: {network}")

    dhcp, dns = parse_dhcp_dns()
    print(f"DHCP Server(s): {dhcp}")
    print(f"DNS Server(s): {dns}")

    public_info = get_public_info()
    if public_info:
        print(f"ISP: {public_info.get('org')}")
        print(f"ASN: {public_info.get('asn')}")

    print("\nDEVICE DISCOVERY")
    print("----------------")


    devices = []

    # 🔥 NEW DISCOVERY METHOD
    alive_hosts = discover_hosts_with_nmap(network)


    for ip_str in alive_hosts:
 
        print(f"\nScanning {ip_str} ...")


        nmap_data = nmap_scan(ip_str)

        open_ports = []
        if 'tcp' in nmap_data:
            open_ports = [
                port for port in nmap_data['tcp']
                if nmap_data['tcp'][port]['state'] == 'open'
            ]

        os_guess = ttl_guess_from_nmap(nmap_data)
        snmp_info = snmp_sysdesc(ip_str)
        netbios = netbios_name(ip_str)

        device = {
            "ip": ip_str,
            "os_guess": os_guess,
            "ports": open_ports,
            "snmp": snmp_info,
            "netbios": netbios
        }

        devices.append(device)

        print(f"IP: {ip_str}")
        print(f"OS Guess: {os_guess}")
        print(f"Open Ports: {open_ports}")

        if snmp_info:
            print(f"SNMP Info: {snmp_info}")

        if netbios:
            print(f"NetBIOS Name: {netbios}")

    print("\nScan Complete.")
    print(f"Total Devices Found: {len(devices)}")


if __name__ == "__main__":
    main()

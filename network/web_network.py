import socket
from .network import (
    get_interface_network,
    get_public_info,
    parse_dhcp_dns,
    discover_hosts_with_nmap,
    nmap_scan,
    snmp_sysdesc,
    netbios_name,
    ttl_guess_from_nmap
)

# -------- NETWORK INFO ENDPOINT -------- #

def get_network_info():
    """
    Get network information only (fast response)
    """
    result = {
        "status": "success",
        "network_info": {},
        "error": None
    }
    
    try:
        local_ip, network = get_interface_network()
        if not network:
            result["status"] = "error"
            result["error"] = "No active network interface found"
            return result
        
        dhcp, dns = parse_dhcp_dns()
        public_info = get_public_info()
        
        result["network_info"] = {
            "local_ip": local_ip,
            "network_range": str(network),
            "dhcp_servers": dhcp,
            "dns_servers": dns,
            "public_ip": public_info.get('ip', 'N/A'),
            "isp": public_info.get('org', 'N/A'),
            "asn": public_info.get('asn', 'N/A'),
            "city": public_info.get('city', 'N/A'),
            "region": public_info.get('region', 'N/A'),
            "country": public_info.get('country', 'N/A')
        }
        
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result


def discover_devices_generator():
    """
    Generator that yields devices as they're discovered
    Yields dictionaries with device info
    """
    try:
        local_ip, network = get_interface_network()
        if not network:
            yield {"error": "No active network interface found"}
            return
        
        # Get list of hosts to scan
        alive_hosts = discover_hosts_with_nmap(network)
        
        # Yield total count first
        yield {"total": len(alive_hosts)}
        
        # Yield each device as discovered
        for ip_str in alive_hosts:
            hostname = "Unknown"
            try:
                hostname = socket.gethostbyaddr(ip_str)[0]
            except:
                pass
            
            nmap_data = nmap_scan(ip_str)
            open_ports = []
            services = {}
            
            if 'tcp' in nmap_data:
                for port, port_data in nmap_data['tcp'].items():
                    open_ports.append(port)
                    services[port] = {
                        "name": port_data.get('name', 'unknown'),
                        "product": port_data.get('product', ''),
                        "version": port_data.get('version', '')
                    }
            
            os_guess = ttl_guess_from_nmap(nmap_data)
            snmp_info = snmp_sysdesc(ip_str)
            netbios = netbios_name(ip_str)
            
            device = {
                "ip": ip_str,
                "hostname": hostname,
                "os_guess": os_guess,
                "open_ports": open_ports,
                "services": services,
                "snmp_info": snmp_info,
                "netbios_name": netbios
            }
            
            yield device
            
    except Exception as e:
        yield {"error": str(e)}

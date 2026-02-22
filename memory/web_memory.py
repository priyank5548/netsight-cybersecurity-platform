import psutil
import platform
import time
from statistics import mean
import re
from datetime import datetime


def bytes_to_gb(value):
    """Convert bytes to GB"""
    return round(value / (1024 ** 3), 2)


def bytes_to_mb(value):
    """Convert bytes to MB"""
    return round(value / (1024 ** 2), 2)


def get_system_summary():
    """Get overall system information"""
    return {
        'os': f"{platform.system()} {platform.release()}",
        'architecture': platform.architecture()[0],
        'cpu_logical': psutil.cpu_count(logical=True),
        'cpu_physical': psutil.cpu_count(logical=False),
        'total_ram': bytes_to_gb(psutil.virtual_memory().total),
        'uptime_hours': round((time.time() - psutil.boot_time()) / 3600, 2)
    }


def get_ram_details():
    """Get detailed RAM information"""
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()

    return {
        'total': bytes_to_gb(vm.total),
        'available': bytes_to_gb(vm.available),
        'used': bytes_to_gb(vm.used),
        'free': bytes_to_gb(vm.free),
        'percent': vm.percent,
        'active': bytes_to_gb(getattr(vm, 'active', 0)),
        'inactive': bytes_to_gb(getattr(vm, 'inactive', 0)),
        'buffers': bytes_to_gb(getattr(vm, 'buffers', 0)),
        'cached': bytes_to_gb(getattr(vm, 'cached', 0)),
        'shared': bytes_to_gb(getattr(vm, 'shared', 0)),
        'swap_total': bytes_to_gb(swap.total),
        'swap_used': bytes_to_gb(swap.used),
        'swap_free': bytes_to_gb(swap.free),
        'swap_percent': swap.percent
    }


def get_memory_pressure_status():
    """Determine memory pressure level"""
    percent = psutil.virtual_memory().percent

    if percent < 60:
        return "HEALTHY", "success"
    elif percent < 80:
        return "MODERATE", "warning"
    else:
        return "HIGH PRESSURE", "danger"


def get_memory_health_analysis():
    """Analyze memory health and provide warnings"""
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    
    status, level = get_memory_pressure_status()
    
    warnings = []
    
    if vm.percent > 80:
        warnings.append("High RAM usage detected")
    if swap.percent > 20:
        warnings.append("Swap usage rising — possible memory stress")
    if vm.available < (vm.total * 0.1):
        warnings.append("Available memory critically low")
    
    return {
        'ram_usage': vm.percent,
        'swap_usage': swap.percent,
        'pressure': status,
        'level': level,
        'warnings': warnings if warnings else ['System memory is healthy']
    }


def get_memory_sampling(duration=5):
    """Sample memory usage over time"""
    samples = []
    
    for _ in range(duration):
        samples.append(psutil.virtual_memory().percent)
        time.sleep(1)
    
    return {
        'peak': max(samples),
        'average': round(mean(samples), 2),
        'lowest': min(samples),
        'samples': samples
    }


def get_top_memory_processes(limit=10):
    """Get top memory-consuming processes"""
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            mem = proc.info['memory_info'].rss
            mem_percent = proc.memory_percent()
            
            processes.append({
                'pid': proc.info['pid'],
                'name': proc.info['name'],
                'memory_mb': bytes_to_mb(mem),
                'memory_percent': round(mem_percent, 2)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
            continue
    
    processes.sort(key=lambda x: x['memory_mb'], reverse=True)
    return processes[:limit]


def calculate_suspicion(process):
    """Calculate suspicion score for a process"""
    score = 0
    
    try:
        cpu = process.cpu_percent(interval=0.1)
        memory = process.memory_percent()
        exe_path = process.exe()
        name = process.name()
        
        # High CPU
        if cpu > 50:
            score += 20
        
        # High memory
        if memory > 10:
            score += 20
        
        # Suspicious location
        if exe_path and any(folder in exe_path.lower() for folder in ["temp", "appdata", "downloads"]):
            score += 30
        
        # Random-looking name
        if re.match(r'^[a-zA-Z0-9]{10,}\.exe$', name):
            score += 10
        
        # Unsigned executable (basic heuristic)
        if exe_path and "program files" not in exe_path.lower():
            score += 10
    
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0, "UNKNOWN"
    
    # Determine level
    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"
    
    return score, level


def scan_suspicious_processes(limit=20):
    """Scan processes and identify suspicious ones"""
    suspicious_processes = []
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            score, level = calculate_suspicion(proc)
            
            if score >= 30:  # Only include medium or high risk
                suspicious_processes.append({
                    'pid': proc.pid,
                    'name': proc.name(),
                    'score': score,
                    'risk': level
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    suspicious_processes.sort(key=lambda x: x['score'], reverse=True)
    return suspicious_processes[:limit]


def get_all_processes_paginated(page=0, page_size=10):
    """Get all processes in pages for progressive loading"""
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent']):
        try:
            mem = proc.info['memory_info'].rss
            mem_percent = proc.memory_percent()
            cpu = proc.cpu_percent(interval=0)
            
            processes.append({
                'pid': proc.info['pid'],
                'name': proc.info['name'],
                'memory_mb': bytes_to_mb(mem),
                'memory_percent': round(mem_percent, 2),
                'cpu_percent': round(cpu, 2)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
            continue
    
    # Sort by memory
    processes.sort(key=lambda x: x['memory_mb'], reverse=True)
    
    # Paginate
    start = page * page_size
    end = start + page_size
    page_data = processes[start:end]
    
    return {
        'processes': page_data,
        'page': page,
        'total': len(processes),
        'has_more': end < len(processes)
    }


def get_process_tree(pid):
    """Get parent and child processes for a given PID"""
    try:
        process = psutil.Process(pid)
        
        # Get parent process
        parent_info = None
        try:
            parent = process.parent()
            if parent:
                parent_info = {
                    'pid': parent.pid,
                    'name': parent.name(),
                    'memory_mb': bytes_to_mb(parent.memory_info().rss),
                    'cpu_percent': round(parent.cpu_percent(interval=0), 2)
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            parent_info = None
        
        # Get current process info
        current_info = {
            'pid': process.pid,
            'name': process.name(),
            'memory_mb': bytes_to_mb(process.memory_info().rss),
            'cpu_percent': round(process.cpu_percent(interval=0), 2),
            'status': process.status(),
            'create_time': datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Get child processes
        children_info = []
        try:
            children = process.children(recursive=False)
            for child in children:
                try:
                    children_info.append({
                        'pid': child.pid,
                        'name': child.name(),
                        'memory_mb': bytes_to_mb(child.memory_info().rss),
                        'cpu_percent': round(child.cpu_percent(interval=0), 2)
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            children_info = []
        
        return {
            'parent': parent_info,
            'current': current_info,
            'children': children_info
        }
    
    except psutil.NoSuchProcess:
        return {'error': f'Process with PID {pid} not found'}
    except psutil.AccessDenied:
        return {'error': f'Access denied to process {pid}'}
    except Exception as e:
        return {'error': str(e)}


def analyze_memory_for_web():
    """
    Main function to gather all memory analysis data for web display
    """
    results = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'system_summary': get_system_summary(),
        'ram_details': get_ram_details(),
        'memory_health': get_memory_health_analysis(),
        'top_processes': get_top_memory_processes(10),
        'suspicious_processes': scan_suspicious_processes(15)
    }
    
    return results

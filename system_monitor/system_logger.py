import os
import psutil
import time
import threading
from datetime import datetime
from pathlib import Path

class SystemActivityLogger:
    """
    Monitors system activity and logs everything to a plain text file.
    Tracks: processes, network, files, and system events.
    """
    
    def __init__(self, log_file="system_activity.log"):
        self.log_file = log_file
        self.running = False
        self.monitor_thread = None
        
        # Track previous states
        self.previous_processes = {}
        self.previous_connections = set()
        self.previous_files = {}
        
        # Flag to skip logging on first scan
        self.initial_scan_done = False
        
        # Ensure log file exists
        Path(self.log_file).touch()
        
    def log(self, event_type, message):
        """Write log entry with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{event_type}] {message}\n"
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Error writing log: {e}")
    
    def monitor_processes(self):
        """Monitor process creation and termination"""
        try:
            current_processes = {}
            for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline']):
                try:
                    info = proc.info
                    pid = info['pid']
                    current_processes[pid] = info
                    
                    # New process detected (only log if not initial scan)
                    if pid not in self.previous_processes and self.initial_scan_done:
                        exe = info.get('exe', 'Unknown')
                        name = info.get('name', 'Unknown')
                        user = info.get('username', 'Unknown')
                        cmdline = ' '.join(info.get('cmdline', [])) if info.get('cmdline') else ''
                        
                        self.log("PROCESS_START", f"PID={pid} | Name={name} | User={user} | Path={exe} | CMD={cmdline}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Detect terminated processes (only log if not initial scan)
            if self.initial_scan_done:
                for pid in self.previous_processes:
                    if pid not in current_processes:
                        info = self.previous_processes[pid]
                        name = info.get('name', 'Unknown')
                        self.log("PROCESS_STOP", f"PID={pid} | Name={name}")
            
            self.previous_processes = current_processes
        except Exception as e:
            self.log("ERROR", f"Monitor processes error: {e}")
    
    def monitor_network(self):
        """Monitor network connections"""
        try:
            current_connections = set()
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    try:
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        proc_name = proc.name() if proc else 'Unknown'
                        
                        local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "Unknown"
                        remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Unknown"
                        
                        conn_key = (conn.pid, local, remote)
                        current_connections.add(conn_key)
                        
                        # New connection detected (only log if not initial scan)
                        if conn_key not in self.previous_connections and self.initial_scan_done:
                            self.log("NETWORK_CONNECT", f"Process={proc_name} | PID={conn.pid} | Local={local} | Remote={remote}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            
            # Detect closed connections (only log if not initial scan)
            if self.initial_scan_done:
                for conn_key in self.previous_connections:
                    if conn_key not in current_connections:
                        pid, local, remote = conn_key
                        self.log("NETWORK_DISCONNECT", f"PID={pid} | Local={local} | Remote={remote}")
            
            self.previous_connections = current_connections
        except Exception as e:
            self.log("ERROR", f"Monitor network error: {e}")
    
    def monitor_files(self, watch_dirs=None):
        """Monitor file system changes in specific directories"""
        if watch_dirs is None:
            # Default: monitor Downloads, Desktop, Documents
            home = Path.home()
            watch_dirs = [
                home / "Downloads",
                home / "Desktop",
                home / "Documents"
            ]
        
        try:
            for watch_dir in watch_dirs:
                if not watch_dir.exists():
                    continue
                
                # Get all files in directory (non-recursive for performance)
                current_files = {}
                for file_path in watch_dir.glob('*'):
                    if file_path.is_file():
                        try:
                            stat = file_path.stat()
                            current_files[str(file_path)] = {
                                'size': stat.st_size,
                                'mtime': stat.st_mtime
                            }
                        except:
                            continue
                
                # Check for new or modified files
                for file_path, info in current_files.items():
                    if file_path not in self.previous_files:
                        # New file detected
                        if self.initial_scan_done:  # Only log if not initial scan
                            size = info['size']
                            # Get actual file creation/modification time
                            mtime = datetime.fromtimestamp(info['mtime']).strftime("%Y-%m-%d %H:%M:%S")
                            self.log("FILE_CREATE", f"Path={file_path} | Size={size} bytes | Modified={mtime}")
                    elif self.previous_files[file_path]['mtime'] != info['mtime']:
                        # Modified file
                        old_size = self.previous_files[file_path]['size']
                        new_size = info['size']
                        mtime = datetime.fromtimestamp(info['mtime']).strftime("%Y-%m-%d %H:%M:%S")
                        self.log("FILE_MODIFY", f"Path={file_path} | Old Size={old_size} | New Size={new_size} | Modified={mtime}")
                
                # Check for deleted files
                for file_path in self.previous_files:
                    if file_path not in current_files and str(watch_dir) in file_path:
                        if self.initial_scan_done:  # Only log if not initial scan
                            self.log("FILE_DELETE", f"Path={file_path}")
                
                self.previous_files.update(current_files)
        except Exception as e:
            self.log("ERROR", f"Monitor files error: {e}")
    
    def monitor_system_resources(self):
        """Monitor CPU, RAM, and Disk usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            ram = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Log only if there are significant changes or high usage
            if cpu_percent > 80:
                self.log("SYSTEM_ALERT", f"High CPU Usage: {cpu_percent}%")
            
            if ram.percent > 85:
                self.log("SYSTEM_ALERT", f"High RAM Usage: {ram.percent}% | Available: {ram.available / (1024**3):.2f} GB")
            
            if disk.percent > 90:
                self.log("SYSTEM_ALERT", f"High Disk Usage: {disk.percent}% | Free: {disk.free / (1024**3):.2f} GB")
        except Exception as e:
            self.log("ERROR", f"Monitor resources error: {e}")
    
    def monitoring_loop(self):
        """Main monitoring loop"""
        self.log("SYSTEM", "System monitoring started")
        
        # Initial snapshot (don't log existing files/processes/connections)
        self.monitor_processes()
        self.monitor_network()
        self.monitor_files()  # Build initial file list without logging
        
        # Mark initial scan as complete
        self.initial_scan_done = True
        
        cycle_count = 0
        
        while self.running:
            try:
                # Monitor processes every cycle (5 seconds)
                self.monitor_processes()
                
                # Monitor network every cycle
                self.monitor_network()
                
                # Monitor files every 3rd cycle (15 seconds)
                if cycle_count % 3 == 0:
                    self.monitor_files()
                
                # Monitor system resources every 6th cycle (30 seconds)
                if cycle_count % 6 == 0:
                    self.monitor_system_resources()
                
                cycle_count += 1
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                self.log("ERROR", f"Monitoring loop error: {e}")
        
        self.log("SYSTEM", "System monitoring stopped")
    
    def start(self):
        """Start monitoring in background thread"""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
            self.monitor_thread.start()
            print(f"[*] System monitoring started. Logging to: {self.log_file}")
            return True
        return False
    
    def stop(self):
        """Stop monitoring"""
        if self.running:
            self.running = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=10)
            print("[*] System monitoring stopped")
            return True
        return False


# Global logger instance
_logger_instance = None

def get_logger():
    """Get the global logger instance"""
    global _logger_instance
    if _logger_instance is None:
        log_path = os.path.join(os.path.dirname(__file__), '..', 'system_activity.log')
        _logger_instance = SystemActivityLogger(log_path)
    return _logger_instance


if __name__ == "__main__":
    # Test the logger
    logger = SystemActivityLogger("test_system_activity.log")
    logger.start()
    
    try:
        print("Monitoring system activity. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.stop()
        print("\nMonitoring stopped.")

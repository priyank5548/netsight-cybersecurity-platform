# System Activity Monitor

## Overview
The System Activity Monitor is a powerful feature that logs all system activities in real-time to a plain text file. It tracks processes, network connections, file system changes, and system resource usage.

## Features

### 1. **Activity Logging**
Automatically logs the following events:
- **Process Monitoring**
  - Process creation (PID, name, user, executable path, command line)
  - Process termination
  
- **Network Monitoring**
  - New network connections (local/remote addresses, ports)
  - Connection terminations
  - Process-to-connection mapping
  
- **File System Monitoring**
  - File creation in Downloads, Desktop, Documents
  - File modifications
  - File deletions
  
- **System Resource Monitoring**
  - High CPU usage alerts (>80%)
  - High RAM usage alerts (>85%)
  - High disk usage alerts (>90%)

### 2. **Web Dashboard**
Access the dashboard at `/system-monitor` to:
- View real-time statistics
- Filter logs by event type
- Search logs by keyword
- Set time ranges (1 hour to 1 week)
- Auto-refresh every 10 seconds
- View up to 1000 recent events

### 3. **Log Format**
Plain text format:
```
[YYYY-MM-DD HH:MM:SS] [EVENT_TYPE] message
```

Example:
```
[2026-02-19 14:30:45] [PROCESS_START] PID=1234 | Name=chrome.exe | User=Admin | Path=C:\Program Files\Google\Chrome\chrome.exe
[2026-02-19 14:30:46] [NETWORK_CONNECT] Process=chrome.exe | PID=1234 | Local=192.168.1.100:54321 | Remote=142.250.80.46:443
[2026-02-19 14:31:00] [FILE_CREATE] Path=C:\Users\Admin\Downloads\document.pdf | Size=2048576 bytes
```

## Event Types

| Event Type | Description |
|------------|-------------|
| `SYSTEM` | System monitoring start/stop |
| `PROCESS_START` | New process created |
| `PROCESS_STOP` | Process terminated |
| `NETWORK_CONNECT` | Network connection established |
| `NETWORK_DISCONNECT` | Network connection closed |
| `FILE_CREATE` | New file created |
| `FILE_MODIFY` | File modified |
| `FILE_DELETE` | File deleted |
| `SYSTEM_ALERT` | High resource usage warning |
| `ERROR` | Monitoring error |

## Usage

### Starting the Monitor
The monitor starts automatically when you run the Flask app:
```bash
python app.py
```

You'll see:
```
[*] System Activity Logger started - logging to system_activity.log
```

### Viewing Logs

**Via Web Interface:**
1. Navigate to http://127.0.0.1:5000/system-monitor
2. View statistics and recent activity
3. Use filters to find specific events
4. Enable auto-refresh for live monitoring

**Via Log File:**
Open `system_activity.log` in any text editor

### Analyzing Logs

**Search for specific process:**
```
Search: "chrome.exe"
```

**Filter by event type:**
```
Event Type: NETWORK_CONNECT
```

**View recent activity:**
```
Time Range: Last Hour
```

## Configuration

### Monitored Directories
By default, these directories are monitored for file changes:
- `~/Downloads`
- `~/Desktop`
- `~/Documents`

To add more directories, edit `system_monitor/system_logger.py`:
```python
watch_dirs = [
    home / "Downloads",
    home / "Desktop",
    home / "Documents",
    home / "YourCustomFolder"  # Add your folder
]
```

### Monitoring Intervals
- Processes & Network: Every 5 seconds
- File System: Every 15 seconds
- System Resources: Every 30 seconds

Adjust in `system_monitor/system_logger.py`:
```python
time.sleep(5)  # Change to your preferred interval
```

### Alert Thresholds
Edit thresholds in `system_monitor/system_logger.py`:
```python
if cpu_percent > 80:  # Change to 90 for less alerts
if ram.percent > 85:  # Change to 95 for less alerts
if disk.percent > 90:  # Change to 95 for less alerts
```

## Performance Impact

The monitor is designed to be lightweight:
- **CPU Usage**: <1% on average
- **RAM Usage**: ~20-30 MB
- **Disk I/O**: Minimal (append-only writes)
- **Log File Size**: ~1-5 MB per day (varies by activity)

## Security Considerations

⚠️ **Important:**
- Log files may contain sensitive information (file paths, usernames, network connections)
- Store logs securely
- Implement log rotation for long-term use
- Consider encrypting logs if storing sensitive data

## Troubleshooting

**Monitor not starting:**
- Check if log file is writable
- Verify permissions on the directory

**No events logged:**
- Monitor only tracks changes after it starts
- Some events require elevated privileges (run as administrator)

**High disk usage:**
- Implement log rotation
- Reduce monitoring frequency
- Filter out verbose event types

## Advanced Usage

### Export Filtered Logs
Use the log analyzer programmatically:
```python
from system_monitor.log_analyzer import LogAnalyzer

analyzer = LogAnalyzer("system_activity.log")

# Export last 24 hours of network events
from datetime import datetime, timedelta
end = datetime.now()
start = end - timedelta(hours=24)

analyzer.export_logs(
    "network_events.txt",
    event_type="NETWORK_CONNECT",
    start_time=start,
    end_time=end
)
```

### Get Statistics
```python
stats = analyzer.get_statistics()
print(f"Total events: {stats['total_events']}")
print(f"Processes started: {stats['processes_started']}")
```

## No API Keys or LLMs Used

This feature is completely local and offline:
- ✅ No external API keys required
- ✅ No cloud services
- ✅ No LLM/AI models
- ✅ All data stays on your machine
- ✅ Plain text logging
- ✅ Simple and transparent

## Files Created

```
final_project/
├── system_activity.log          # Main log file (auto-created)
├── system_monitor/
│   ├── __init__.py              # Module initializer
│   ├── system_logger.py         # Core logging engine
│   ├── log_analyzer.py          # Log parsing & analysis
│   └── web_system_monitor.py   # Web API integration
└── templates/
    └── system_monitor.html      # Web dashboard
```

## Future Enhancements

Potential improvements:
- Log rotation (daily/weekly)
- Email alerts for critical events
- Export logs to CSV/JSON
- Process behavior analysis
- Anomaly detection
- Historical timeline graphs
- Filter presets for common searches

---

**Ready to use!** Start the Flask app and visit `/system-monitor` to see your system activity logs.

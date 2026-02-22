import os
import re
from datetime import datetime, timedelta
from collections import defaultdict

class LogAnalyzer:
    """
    Analyzes system activity logs.
    Provides filtering, searching, and statistics.
    """
    
    def __init__(self, log_file="system_activity.log"):
        self.log_file = log_file
    
    def parse_log_line(self, line):
        """Parse a single log line into structured data"""
        # Format: [YYYY-MM-DD HH:MM:SS] [EVENT_TYPE] message
        pattern = r'\[([\d\-: ]+)\] \[([^\]]+)\] (.+)'
        match = re.match(pattern, line)
        
        if match:
            timestamp_str, event_type, message = match.groups()
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            
            return {
                'timestamp': timestamp,
                'event_type': event_type,
                'message': message,
                'raw': line.strip()
            }
        return None
    
    def read_logs(self, limit=None, reverse=True):
        """Read logs from file"""
        if not os.path.exists(self.log_file):
            return []
        
        logs = []
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
                if reverse:
                    lines = reversed(lines)
                
                for line in lines:
                    if line.strip():
                        parsed = self.parse_log_line(line)
                        if parsed:
                            logs.append(parsed)
                            if limit and len(logs) >= limit:
                                break
        except Exception as e:
            print(f"Error reading logs: {e}")
        
        return logs
    
    def filter_logs(self, event_type=None, search_text=None, start_time=None, end_time=None, limit=1000):
        """Filter logs by various criteria"""
        logs = self.read_logs(reverse=True)
        filtered = []
        
        for log in logs:
            # Filter by event type
            if event_type and log['event_type'] != event_type:
                continue
            
            # Filter by search text
            if search_text and search_text.lower() not in log['message'].lower():
                continue
            
            # Filter by time range
            if start_time and log['timestamp'] < start_time:
                continue
            if end_time and log['timestamp'] > end_time:
                continue
            
            filtered.append(log)
            
            if len(filtered) >= limit:
                break
        
        return filtered
    
    def get_recent_activity(self, minutes=60, limit=100):
        """Get activity from the last N minutes"""
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=minutes)
        return self.filter_logs(start_time=start_time, end_time=end_time, limit=limit)
    
    def get_statistics(self):
        """Get statistics about logged events"""
        logs = self.read_logs()
        
        stats = {
            'total_events': len(logs),
            'event_counts': defaultdict(int),
            'first_event': None,
            'last_event': None,
            'processes_started': 0,
            'processes_stopped': 0,
            'network_connections': 0,
            'files_created': 0,
            'files_modified': 0,
            'files_deleted': 0,
            'alerts': 0,
            'errors': 0
        }
        
        if not logs:
            return stats
        
        for log in logs:
            event_type = log['event_type']
            stats['event_counts'][event_type] += 1
            
            # Count specific events
            if event_type == 'PROCESS_START':
                stats['processes_started'] += 1
            elif event_type == 'PROCESS_STOP':
                stats['processes_stopped'] += 1
            elif event_type == 'NETWORK_CONNECT':
                stats['network_connections'] += 1
            elif event_type == 'FILE_CREATE':
                stats['files_created'] += 1
            elif event_type == 'FILE_MODIFY':
                stats['files_modified'] += 1
            elif event_type == 'FILE_DELETE':
                stats['files_deleted'] += 1
            elif event_type == 'SYSTEM_ALERT':
                stats['alerts'] += 1
            elif event_type == 'ERROR':
                stats['errors'] += 1
        
        # First and last events (logs are reversed)
        stats['last_event'] = logs[0]['timestamp'] if logs else None
        stats['first_event'] = logs[-1]['timestamp'] if logs else None
        
        return stats
    
    def get_timeline(self, hours=24):
        """Get timeline of events for the last N hours"""
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        logs = self.filter_logs(start_time=start_time, end_time=end_time, limit=5000)
        
        # Group by hour
        timeline = defaultdict(lambda: defaultdict(int))
        
        for log in logs:
            hour_key = log['timestamp'].strftime("%Y-%m-%d %H:00")
            timeline[hour_key][log['event_type']] += 1
        
        # Convert to sorted list
        result = []
        for hour, events in sorted(timeline.items()):
            result.append({
                'hour': hour,
                'events': dict(events),
                'total': sum(events.values())
            })
        
        return result
    
    def search_logs(self, query, limit=100):
        """Search logs by text query"""
        return self.filter_logs(search_text=query, limit=limit)
    
    def get_event_types(self):
        """Get list of all event types in the log"""
        logs = self.read_logs()
        event_types = set()
        for log in logs:
            event_types.add(log['event_type'])
        return sorted(list(event_types))
    
    def export_logs(self, output_file, event_type=None, search_text=None, start_time=None, end_time=None):
        """Export filtered logs to a file"""
        logs = self.filter_logs(
            event_type=event_type,
            search_text=search_text,
            start_time=start_time,
            end_time=end_time,
            limit=10000
        )
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for log in reversed(logs):  # Write in chronological order
                    f.write(log['raw'] + '\n')
            return True, len(logs)
        except Exception as e:
            return False, str(e)


if __name__ == "__main__":
    # Test the analyzer
    analyzer = LogAnalyzer("system_activity.log")
    
    print("=== Log Statistics ===")
    stats = analyzer.get_statistics()
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"{key}:")
            for k, v in value.items():
                print(f"  {k}: {v}")
        else:
            print(f"{key}: {value}")
    
    print("\n=== Recent Activity (Last 10 Events) ===")
    recent = analyzer.get_recent_activity(minutes=60, limit=10)
    for log in recent:
        print(f"{log['timestamp']} [{log['event_type']}] {log['message'][:80]}")

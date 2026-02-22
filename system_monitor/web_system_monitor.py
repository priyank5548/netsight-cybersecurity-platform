from .log_analyzer import LogAnalyzer
from datetime import datetime, timedelta

def get_logs_for_web(event_type=None, search_text=None, hours=24, limit=500):
    """Get logs formatted for web display"""
    analyzer = LogAnalyzer("system_activity.log")
    
    # Calculate time range
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=hours) if hours else None
    
    # Filter logs
    logs = analyzer.filter_logs(
        event_type=event_type,
        search_text=search_text,
        start_time=start_time,
        end_time=end_time,
        limit=limit
    )
    
    # Format for web
    formatted_logs = []
    for log in logs:
        formatted_logs.append({
            'timestamp': log['timestamp'].strftime("%Y-%m-%d %H:%M:%S"),
            'event_type': log['event_type'],
            'message': log['message'],
            'severity': get_severity(log['event_type'])
        })
    
    return formatted_logs

def get_severity(event_type):
    """Determine severity level for color coding"""
    if event_type in ['ERROR', 'SYSTEM_ALERT']:
        return 'danger'
    elif event_type in ['PROCESS_START', 'NETWORK_CONNECT', 'FILE_CREATE']:
        return 'info'
    elif event_type in ['PROCESS_STOP', 'NETWORK_DISCONNECT', 'FILE_DELETE']:
        return 'warning'
    else:
        return 'normal'

def get_dashboard_stats():
    """Get statistics for dashboard display"""
    analyzer = LogAnalyzer("system_activity.log")
    stats = analyzer.get_statistics()
    
    # Get recent activity (last hour)
    recent = analyzer.get_recent_activity(minutes=60, limit=1000)
    recent_count = len(recent)
    
    # Count by event type in last hour
    recent_by_type = {}
    for log in recent:
        event_type = log['event_type']
        recent_by_type[event_type] = recent_by_type.get(event_type, 0) + 1
    
    return {
        'total_events': stats['total_events'],
        'processes_started': stats['processes_started'],
        'processes_stopped': stats['processes_stopped'],
        'network_connections': stats['network_connections'],
        'files_created': stats['files_created'],
        'files_modified': stats['files_modified'],
        'files_deleted': stats['files_deleted'],
        'alerts': stats['alerts'],
        'errors': stats['errors'],
        'recent_hour_count': recent_count,
        'recent_by_type': recent_by_type,
        'first_event': stats['first_event'].strftime("%Y-%m-%d %H:%M:%S") if stats['first_event'] else 'N/A',
        'last_event': stats['last_event'].strftime("%Y-%m-%d %H:%M:%S") if stats['last_event'] else 'N/A'
    }

def get_event_types_list():
    """Get list of all event types"""
    analyzer = LogAnalyzer("system_activity.log")
    return analyzer.get_event_types()

def search_logs_web(query, limit=200):
    """Search logs for web display"""
    analyzer = LogAnalyzer("system_activity.log")
    logs = analyzer.search_logs(query, limit=limit)
    
    formatted_logs = []
    for log in logs:
        formatted_logs.append({
            'timestamp': log['timestamp'].strftime("%Y-%m-%d %H:%M:%S"),
            'event_type': log['event_type'],
            'message': log['message'],
            'severity': get_severity(log['event_type'])
        })
    
    return formatted_logs

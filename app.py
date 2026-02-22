from flask import Flask, render_template, request, jsonify
import os
import json
import hashlib
import psutil
import socket
from werkzeug.utils import secure_filename
from file_analysis.web_analyzer import analyze_file_for_web
from memory.web_memory import analyze_memory_for_web
from system_monitor import get_logger
from system_monitor.web_system_monitor import (
    get_logs_for_web, 
    get_dashboard_stats, 
    get_event_types_list,
    search_logs_web
)
from vulnerability_scanner.web_vulnerability_scanner import scan_for_web
from registry_scanner.web_registry_scanner import scan_registry_for_web

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'exe', 'dll', 'pdf', 'doc', 'docx', 'zip', 'txt', 'bin', 'sys'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename or True  # Allow all files for analysis

# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("index.html")

# ---------------- FILE ANALYSIS ----------------
@app.route("/file-analysis", methods=["GET", "POST"])
def file_analysis():
    analysis_results = None
    error = None
    
    if request.method == "POST":
        if 'file' not in request.files:
            error = "No file uploaded"
        else:
            file = request.files["file"]
            if file and file.filename:
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                try:
                    file.save(filepath)
                    # Analyze the file
                    analysis_results = analyze_file_for_web(filepath)
                    
                    # Clean up the uploaded file after analysis
                    # Uncomment the line below if you want to delete files after analysis
                    # os.remove(filepath)
                except Exception as e:
                    error = f"Analysis error: {str(e)}"
                    if os.path.exists(filepath):
                        os.remove(filepath)
            else:
                error = "No file selected"
    
    return render_template("file_analysis.html", results=analysis_results, error=error)

# ---------------- FIREWALL STATUS (Basic Check) ----------------
@app.route("/firewall-status")
def firewall_status():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return render_template("firewall_status.html", ip=ip_address)

# ---------------- PASSWORD STRENGTH CHECK ----------------
@app.route("/password-analysis", methods=["GET", "POST"])
def password_analysis():
    strength = None
    if request.method == "POST":
        password = request.form["password"]
        score = 0
        if len(password) >= 8:
            score += 1
        if any(char.isdigit() for char in password):
            score += 1
        if any(char.isupper() for char in password):
            score += 1
        if any(char in "!@#$%^&*" for char in password):
            score += 1

        levels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
        strength = levels[score]

    return render_template("password_analysis.html", strength=strength)

# ---------------- RAM MONITOR ----------------
@app.route("/ram")
def ram():
    return render_template("ram.html")

# API endpoint for basic system info (fast)
@app.route("/api/ram/basic")
def ram_basic():
    try:
        from memory.web_memory import get_system_summary, get_ram_details, get_memory_health_analysis
        from datetime import datetime
        
        data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'system_summary': get_system_summary(),
            'ram_details': get_ram_details(),
            'memory_health': get_memory_health_analysis()
        }
        return data
    except Exception as e:
        return {'error': str(e)}, 500

# API endpoint for top processes
@app.route("/api/ram/top-processes")
def ram_top_processes():
    try:
        from memory.web_memory import get_top_memory_processes
        return {'top_processes': get_top_memory_processes(10)}
    except Exception as e:
        return {'error': str(e)}, 500

# API endpoint for all processes (paginated)
@app.route("/api/ram/all-processes")
def ram_all_processes():
    try:
        from memory.web_memory import get_all_processes_paginated
        page = int(request.args.get('page', 0))
        data = get_all_processes_paginated(page)
        return data
    except Exception as e:
        return {'error': str(e)}, 500

# API endpoint for memory sampling
@app.route("/api/ram/sampling")
def ram_sampling():
    try:
        from memory.web_memory import get_memory_sampling
        duration = int(request.args.get('duration', 10))
        
        def generate():
            import json
            samples = []
            for i in range(duration):
                sample = psutil.virtual_memory().percent
                samples.append(sample)
                yield f"data: {json.dumps({'sample': sample, 'index': i+1, 'total': duration})}\n\n"
                if i < duration - 1:
                    import time
                    time.sleep(1)
            
            result = {
                'peak': max(samples),
                'average': round(sum(samples) / len(samples), 2),
                'lowest': min(samples),
                'samples': samples,
                'complete': True
            }
            yield f"data: {json.dumps(result)}\n\n"
        
        return app.response_class(generate(), mimetype='text/event-stream')
    except Exception as e:
        return {'error': str(e)}, 500

# API endpoint for process tree
@app.route("/api/ram/process-tree/<int:pid>")
def process_tree(pid):
    try:
        from memory.web_memory import get_process_tree
        data = get_process_tree(pid)
        return data
    except Exception as e:
        return {'error': str(e)}, 500

# ---------------- URL SCAN ----------------
@app.route("/url-scan", methods=["GET"])
def url_scan():
    return render_template("url_scan.html")

# API endpoint for URL scanning
@app.route("/api/url-scan", methods=["POST"])
def url_scan_api():
    try:
        from url_scan.web_url_scan import scan_url_for_web
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return {'status': 'error', 'error': 'URL is required'}, 400
        
        result = scan_url_for_web(url)
        return result
    except Exception as e:
        return {'status': 'error', 'error': str(e)}, 500


@app.route("/network")
def network():  
    return render_template("network.html")

# API endpoint for network info (fast response)
@app.route("/api/network/info")
def network_info():
    try:
        from network.web_network import get_network_info
        result = get_network_info()
        return result
    except Exception as e:
        return {'status': 'error', 'error': str(e)}, 500

# API endpoint for device discovery (streaming response)
@app.route("/api/network/devices")
def network_devices():
    try:
        from network.web_network import discover_devices_generator
        
        def generate():
            for device in discover_devices_generator():
                yield f"data: {json.dumps(device)}\n\n"
        
        return generate(), 200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache'
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}, 500

# Legacy endpoint for backward compatibility
@app.route("/api/network/scan")
def network_scan():
    try:
        from network.web_network import get_network_info, discover_devices_generator
        
        info_result = get_network_info()
        devices = list(discover_devices_generator())
        
        # Filter out the total count item
        total = devices[0].get('total', 0) if devices else 0
        devices = [d for d in devices if 'ip' in d]
        
        return {
            'status': info_result.get('status'),
            'network_info': info_result.get('network_info', {}),
            'devices': devices,
            'total_devices': total,
            'error': info_result.get('error')
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}, 500


# ---------------- SYSTEM ACTIVITY MONITOR ----------------
@app.route("/system-monitor")
def system_monitor():
    return render_template("system_monitor.html")

# API endpoint for log statistics
@app.route("/api/system-monitor/stats")
def system_monitor_stats():
    try:
        stats = get_dashboard_stats()
        return jsonify(stats)
    except Exception as e:
        return {'status': 'error', 'error': str(e)}, 500

# API endpoint for getting logs
@app.route("/api/system-monitor/logs")
def system_monitor_logs():
    try:
        event_type = request.args.get('event_type', None)
        search_text = request.args.get('search', None)
        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 500))
        
        logs = get_logs_for_web(
            event_type=event_type if event_type else None,
            search_text=search_text if search_text else None,
            hours=hours,
            limit=limit
        )
        
        return jsonify({
            'status': 'success',
            'logs': logs,
            'count': len(logs)
        })
    except Exception as e:
        return {'status': 'error', 'error': str(e)}, 500

# API endpoint for event types
@app.route("/api/system-monitor/event-types")
def system_monitor_event_types():
    try:
        event_types = get_event_types_list()
        return jsonify({
            'status': 'success',
            'event_types': event_types
        })
    except Exception as e:
        return {'status': 'error', 'error': str(e)}, 500


# ---------------- SOFTWARE VULNERABILITY SCANNER ----------------
@app.route("/vulnerability-scanner")
def vulnerability_scanner():
    return render_template("vulnerability_scanner.html")


@app.route("/api/vulnerability-scanner/scan")
def vulnerability_scanner_scan():
    try:
        result = scan_for_web()
        return jsonify(result)
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


# ---------------- REGISTRY SECURITY SCANNER ----------------
@app.route("/registry-scanner")
def registry_scanner():
    return render_template("registry_scanner.html")


@app.route("/api/registry-scanner/scan")
def registry_scanner_scan():
    try:
        result = scan_registry_for_web()
        return jsonify(result)
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


if __name__ == "__main__":
    # Start system activity monitoring
    logger = get_logger()
    logger.start()
    print("[*] System Activity Logger started - logging to system_activity.log")
    
    try:
        app.run(host="127.0.0.1", port=5000)
    finally:
        # Stop monitoring when app closes
        logger.stop()

#!/usr/bin/env python3
"""
AutoSOC NDR - Complete Backend with Analysis State
"""

import os
import json
import shutil
import tempfile
import subprocess
import threading
import time
import re
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='static')
CORS(app)

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FOLDER = os.path.join(PROJECT_ROOT, 'output')

print(f"PROJECT_ROOT: {PROJECT_ROOT}")
print(f"OUTPUT_FOLDER: {OUTPUT_FOLDER}")

# ============================================
# ANALYSIS STATE - CRITICAL FOR EMPTY STATE
# ============================================
analysis_ready = False

# Global status for processing page
current_status = {
    "progress": 0,
    "stage": "idle",
    "phase": "idle",
    "metrics": {
        "packets": 0, "flows": 0, "ips": 0, "domains": 0,
        "urls": 0, "alerts": 0, "api_calls": 0, "scan_rate": 0
    },
    "logs": []
}

def add_log(message, level="INFO"):
    timestamp = time.strftime("%H:%M:%S")
    current_status["logs"].append({
        "time": timestamp,
        "level": level,
        "message": message
    })
    if len(current_status["logs"]) > 100:
        current_status["logs"] = current_status["logs"][-100:]

def is_analysis_ready():
    """Check if analysis results exist"""
    alerts_path = os.path.join(OUTPUT_FOLDER, 'alerts.json')
    return os.path.exists(alerts_path) and os.path.getsize(alerts_path) > 10

def clear_old_results():
    """Clear previous analysis results before new upload"""
    global analysis_ready
    
    if os.path.exists(OUTPUT_FOLDER):
        # Delete all files in output folder
        for file in os.listdir(OUTPUT_FOLDER):
            file_path = os.path.join(OUTPUT_FOLDER, file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(f"Error deleting {file_path}: {e}")
    else:
        os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    
    analysis_ready = False
    add_log("Cleared previous analysis results", "INFO")

def get_alerts_data():
    """Return alerts data or empty list if not ready"""
    if not is_analysis_ready():
        return []
    alerts_path = os.path.join(OUTPUT_FOLDER, 'alerts.json')
    try:
        with open(alerts_path, 'r') as f:
            return json.load(f)
    except:
        return []

def get_timeline_data():
    """Return timeline data or empty list if not ready"""
    if not is_analysis_ready():
        return []
    
    timeline_path = os.path.join(OUTPUT_FOLDER, 'timeline.json')
    print(f"[DEBUG] Looking for timeline at: {timeline_path}")
    print(f"[DEBUG] File exists: {os.path.exists(timeline_path)}")
    
    if os.path.exists(timeline_path):
        try:
            with open(timeline_path, 'r') as f:
                data = json.load(f)
            
            # Handle both formats: list OR dict with 'events' key
            if isinstance(data, list):
                print(f"[DEBUG] Found {len(data)} timeline events (list format)")
                return data
            elif isinstance(data, dict) and 'events' in data:
                print(f"[DEBUG] Found {len(data['events'])} timeline events (dict format)")
                return data['events']
            else:
                print(f"[DEBUG] Unknown timeline format: {type(data)}")
                return []
        except Exception as e:
            print(f"[DEBUG] Error reading timeline: {e}")
            return []
    
    alerts = get_alerts_data()
    return build_timeline_from_alerts(alerts)

def build_timeline_from_alerts(alerts):
    """Build a chronological timeline when timeline.json is not available."""
    events = []
    for index, alert in enumerate(alerts):
        timestamp = alert.get('timestamp') or alert.get('first_seen') or alert.get('last_seen') or 0
        events.append({
            'event_id': index + 1,
            'timestamp': timestamp,
            'time': timestamp,
            'rule': alert.get('rule') or alert.get('event_type') or 'security_event',
            'event_type': alert.get('event_type') or alert.get('rule') or 'security_event',
            'severity': alert.get('severity', 'LOW'),
            'src_ip': alert.get('src_ip') or alert.get('source_ip') or 'N/A',
            'dst_ip': alert.get('dst_ip') or alert.get('destination_ip') or 'N/A',
            'reason': alert.get('reason') or alert.get('description') or alert.get('explanation') or 'No details provided',
            'risk_score': alert.get('risk_score', 0),
        })

    return sorted(events, key=lambda event: event.get('timestamp') or 0)

def get_campaigns_data():
    """Generate campaigns from alerts"""
    alerts = get_alerts_data()
    if not alerts:
        return []
    
    campaign_map = {}
    for alert in alerts:
        src_ip = alert.get('src_ip', 'unknown')
        if src_ip not in campaign_map:
            campaign_map[src_ip] = {
                'id': f"CAMP-{len(campaign_map)+1:03d}",
                'severity': alert.get('severity', 'MEDIUM'),
                'attack_chain': get_attack_chain(alert.get('rule', '')),
                'affected_ips': [src_ip],
                'total_events': 0,
                'iocs': {'ips': 1, 'domains': 0}
            }
        campaign_map[src_ip]['total_events'] += 1
        if alert.get('dst_ip'):
            campaign_map[src_ip]['affected_ips'].append(alert.get('dst_ip'))
    
    return list(campaign_map.values())[:10]

def get_attack_chain(rule):
    if rule == 'c2_beaconing':
        return '🔍 Reconnaissance → 📡 C2'
    elif rule == 'high_packet_rate':
        return '📡 C2 → 💾 Exfiltration'
    elif rule == 'http_anomaly':
        return '🎣 Initial Access → ⚡ Execution'
    elif rule == 'phishing':
        return '🎣 Initial Access'
    elif rule == 'ddos_flood':
        return '💥 Impact'
    else:
        return '🔍 Reconnaissance → 💥 Impact'

def get_dashboard_data():
    """Return dashboard summary or empty if not ready"""
    alerts = get_alerts_data()
    if not alerts:
        return {
            "total_alerts": 0,
            "aggregated_events": 0,
            "active_campaigns": 0,
            "critical_threats": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        }
    
    severity_counts = {
        'CRITICAL': sum(1 for a in alerts if a.get('severity') == 'CRITICAL'),
        'HIGH': sum(1 for a in alerts if a.get('severity') == 'HIGH'),
        'MEDIUM': sum(1 for a in alerts if a.get('severity') == 'MEDIUM'),
        'LOW': sum(1 for a in alerts if a.get('severity') == 'LOW')
    }
    
    return {
        "total_alerts": len(alerts),
        "aggregated_events": len([a for a in alerts if a.get('event_type')]),
        "active_campaigns": len(set(a.get('src_ip') for a in alerts if a.get('src_ip'))),
        "critical_threats": severity_counts.get('CRITICAL', 0),
        "severity_counts": severity_counts
    }

def get_analytics_data():
    """Return analytics data or empty if not ready"""
    alerts = get_alerts_data()
    if not alerts:
        return {"protocols": {}, "top_talkers": []}
    
    # Protocol distribution
    protocols = {}
    for alert in alerts:
        proto = alert.get('protocol', 'Unknown')
        protocols[proto] = protocols.get(proto, 0) + 1
    
    # Top talkers
    src_counts = {}
    for alert in alerts:
        src = alert.get('src_ip', 'unknown')
        src_counts[src] = src_counts.get(src, 0) + 1
    top_talkers = [{'ip': ip, 'packets': count} for ip, count in list(src_counts.items())[:5]]
    
    return {"protocols": protocols, "top_talkers": top_talkers}

def run_analysis(filepath):
    """Run detection engine"""
    global current_status, analysis_ready
    
    add_log(f"Starting analysis on {os.path.basename(filepath)}", "INFO")
    current_status["stage"] = "detection"
    current_status["phase"] = "detection"
    current_status["progress"] = 50
    
    try:
        engine_path = os.path.join(PROJECT_ROOT, 'detection', 'engine.py')
        
        add_log(f"Running: python {engine_path}", "INFO")
        
        result = subprocess.run(
            ['python', engine_path, filepath],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=PROJECT_ROOT
        )
        
        output = result.stdout
        print(f"Engine stdout: {output[:500]}")
        
        # Parse metrics
        match = re.search(r'Packets\s*:\s*(\d+)', output)
        if match:
            current_status["metrics"]["packets"] = int(match.group(1))
            add_log(f"Parsed {current_status['metrics']['packets']} packets", "SUCCESS")
        
        match = re.search(r'Flows\s*:\s*(\d+)', output)
        if match:
            current_status["metrics"]["flows"] = int(match.group(1))
        
        match = re.search(r'Alerts\s*:\s*(\d+)', output)
        if match:
            current_status["metrics"]["alerts"] = int(match.group(1))
            add_log(f"Generated {current_status['metrics']['alerts']} alerts", "SUCCESS")
        
        # Mark analysis as ready
        analysis_ready = True
        
        current_status["progress"] = 100
        current_status["stage"] = "complete"
        current_status["phase"] = "complete"
        add_log("Analysis complete! Dashboard ready.", "SUCCESS")
        
    except subprocess.TimeoutExpired:
        add_log("Analysis timed out", "ERROR")
        current_status["stage"] = "error"
    except Exception as e:
        add_log(f"Error: {str(e)}", "ERROR")
        current_status["stage"] = "error"
        print(f"Exception: {e}")

# ============================================
# API ENDPOINTS
# ============================================

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/status')
def get_status():
    return jsonify({
        "progress": current_status["progress"],
        "stage": current_status["stage"],
        "phase": current_status["phase"],
        "metrics": current_status["metrics"],
        "logs": current_status["logs"]
    })

@app.route('/upload', methods=['POST'])
def upload_pcap():
    global current_status, analysis_ready
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # CLEAR OLD RESULTS - CRITICAL
    clear_old_results()
    
    # Reset status
    current_status = {
        "progress": 0,
        "stage": "upload",
        "phase": "upload",
        "metrics": {
            "packets": 0, "flows": 0, "ips": 0, "domains": 0,
            "urls": 0, "alerts": 0, "api_calls": 0, "scan_rate": 0
        },
        "logs": []
    }
    
    # Save to temp file
    fd, temp_path = tempfile.mkstemp(suffix='.pcap')
    os.close(fd)
    file.save(temp_path)
    
    # Start background thread
    thread = threading.Thread(target=run_analysis, args=(temp_path,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': 'Analysis started'})

# API Endpoints - Return EMPTY when no analysis done
@app.route('/api/alerts')
def get_alerts():
    return jsonify(get_alerts_data())

@app.route('/api/analytics')
def get_analytics():
    return jsonify(get_analytics_data())

@app.route('/api/campaigns')
def get_campaigns():
    return jsonify(get_campaigns_data())

@app.route('/api/timeline')
def get_timeline():
    return jsonify(get_timeline_data())

@app.route('/api/dashboard')
def get_dashboard():
    return jsonify(get_dashboard_data())

@app.route('/api/summary')
def get_summary():
    return jsonify(get_dashboard_data())

@app.route('/api/events')
def get_events():
    return jsonify(get_alerts_data())

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

if __name__ == '__main__':
    # Start with empty state
    clear_old_results()
    
    print("\n" + "=" * 60)
    print("  AutoSOC NDR - Complete Backend")
    print("  http://localhost:5000")
    print("  API Endpoints ready")
    print("  Starting with EMPTY state - Upload a PCAP to see data")
    print("=" * 60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)

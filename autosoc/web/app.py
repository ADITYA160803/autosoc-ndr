#!/usr/bin/env python3
"""
AutoSOC NDR - Complete Backend with API Endpoints
"""

import os
import json
import hashlib
import tempfile
import subprocess
import threading
import time
import re
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='static')
CORS(app)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_FOLDER = os.path.join(PROJECT_ROOT, 'output')

print(f"PROJECT_ROOT: {PROJECT_ROOT}")
print(f"OUTPUT_FOLDER: {OUTPUT_FOLDER}")

os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# ============================================
# STORAGE FOR LATEST ANALYSIS RESULTS
# ============================================
analysis_results = {
    "alerts": [],
    "analytics": {
        "protocols": {},
        "top_talkers": []
    },
    "campaigns": [],
    "timeline": [],
    "dashboard": {
        "total_alerts": 0,
        "aggregated_events": 0,
        "active_campaigns": 0,
        "critical_threats": 0,
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    }
}

# Global status for processing page
current_status = {
    "progress": 0,
    "stage": "idle",
    "phase": "idle",
    "completed": False,
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

def refresh_analysis_results():
    """Refresh analysis_results from output files"""
    global analysis_results
    
    alerts_path = os.path.join(OUTPUT_FOLDER, 'alerts.json')
    timeline_path = os.path.join(OUTPUT_FOLDER, 'timeline.json')
    
    # Load alerts
    if os.path.exists(alerts_path):
        with open(alerts_path, 'r') as f:
            alerts = json.load(f)
        analysis_results["alerts"] = alerts
        
        # Calculate severity counts
        severity_counts = {
            'CRITICAL': sum(1 for a in alerts if a.get('severity') == 'CRITICAL'),
            'HIGH': sum(1 for a in alerts if a.get('severity') == 'HIGH'),
            'MEDIUM': sum(1 for a in alerts if a.get('severity') == 'MEDIUM'),
            'LOW': sum(1 for a in alerts if a.get('severity') == 'LOW')
        }
        
        # Build campaigns from alerts (group by source IP)
        campaign_map = {}
        for alert in alerts:
            src_ip = alert.get('src_ip', 'unknown')
            if src_ip not in campaign_map:
                campaign_map[src_ip] = {
                    'id': f"CAMP-{len(campaign_map)+1:03d}",
                    'severity': alert.get('severity', 'MEDIUM'),
                    'attack_chain': _get_attack_chain(alert.get('rule', '')),
                    'affected_ips': [src_ip],
                    'total_events': 0,
                    'iocs': {'ips': 1, 'domains': 0}
                }
            campaign_map[src_ip]['total_events'] += 1
            if alert.get('dst_ip'):
                campaign_map[src_ip]['affected_ips'].append(alert.get('dst_ip'))
        
        analysis_results["campaigns"] = list(campaign_map.values())[:10]
        
        # Calculate protocol distribution from alerts
        protocols = {}
        for alert in alerts:
            proto = alert.get('protocol', 'Unknown')
            protocols[proto] = protocols.get(proto, 0) + 1
        analysis_results["analytics"]["protocols"] = protocols
        
        # Calculate top talkers
        src_counts = {}
        for alert in alerts:
            src = alert.get('src_ip', 'unknown')
            src_counts[src] = src_counts.get(src, 0) + 1
        top_talkers = [{'ip': ip, 'packets': count} for ip, count in list(src_counts.items())[:5]]
        analysis_results["analytics"]["top_talkers"] = top_talkers
        
        # Dashboard summary
        analysis_results["dashboard"] = {
            "total_alerts": len(alerts),
            "aggregated_events": len([a for a in alerts if a.get('event_type')]),
            "active_campaigns": len(campaign_map),
            "critical_threats": severity_counts.get('CRITICAL', 0),
            "severity_counts": severity_counts
        }
    
    # Load timeline
    if os.path.exists(timeline_path):
        with open(timeline_path, 'r') as f:
            timeline_data = json.load(f)
        events = timeline_data.get('events', [])
        analysis_results["timeline"] = events[:100]

def _get_attack_chain(rule):
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

def run_analysis(filepath):
    """Run detection engine"""
    global current_status
    
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
        
        print(f"Engine stdout: {result.stdout[:500]}")
        if result.stderr:
            print(f"Engine stderr: {result.stderr[:500]}")
        
        output = result.stdout
        
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
        
        # Refresh analysis results from output files
        refresh_analysis_results()
        
        current_status["progress"] = 100
        current_status["stage"] = "complete"
        current_status["phase"] = "complete"
        current_status["completed"] = True
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
    "completed": current_status.get("completed", False),  # ✅ ADD
    "metrics": current_status["metrics"],
    "logs": current_status["logs"]
})

@app.route('/upload', methods=['POST'])
def upload_pcap():
    global current_status
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
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

# API Endpoints for Frontend
@app.route('/api/alerts')
def get_alerts():
    refresh_analysis_results()
    return jsonify(analysis_results["alerts"])

@app.route('/api/analytics')
def get_analytics():
    refresh_analysis_results()
    return jsonify({
        "protocols": analysis_results["analytics"]["protocols"],
        "top_talkers": analysis_results["analytics"]["top_talkers"]
    })

@app.route('/api/campaigns')
def get_campaigns():
    refresh_analysis_results()
    return jsonify(analysis_results["campaigns"])

@app.route('/api/timeline')
def get_timeline():
    refresh_analysis_results()
    return jsonify(analysis_results["timeline"])

@app.route('/api/dashboard')
def get_dashboard():
    refresh_analysis_results()
    return jsonify(analysis_results["dashboard"])

@app.route('/api/summary')
def get_summary():
    refresh_analysis_results()
    return jsonify(analysis_results["dashboard"])

@app.route('/api/events')
def get_events():
    refresh_analysis_results()
    return jsonify(analysis_results["alerts"])

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

if __name__ == '__main__':
    # Initial refresh
    refresh_analysis_results()
    
    print("\n" + "=" * 60)
    print("  🔍 AutoSOC NDR - Complete Backend")
    print("  🌐 http://localhost:5000")
    print("  📡 API Endpoints: /api/alerts, /api/analytics, /api/campaigns, /api/timeline, /api/dashboard")
    print("=" * 60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
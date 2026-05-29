#!/usr/bin/env python3
"""
Alert Aggregation Agent
Groups duplicate alerts into meaningful security events
"""

from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any

# Aggregation window in seconds
AGGREGATION_WINDOW = 10

# Severity mapping based on scale
def get_severity_for_ddos(unique_sources: int) -> str:
    """Determine DDoS severity based on number of unique sources"""
    if unique_sources > 5000:
        return "CRITICAL"
    elif unique_sources > 1000:
        return "HIGH"
    elif unique_sources > 100:
        return "MEDIUM"
    else:
        return "LOW"

def get_severity_for_scan(unique_targets: int) -> str:
    """Determine scan severity based on number of unique targets"""
    if unique_targets > 100:
        return "HIGH"
    elif unique_targets > 50:
        return "MEDIUM"
    else:
        return "LOW"

def calculate_confidence(unique_ips: int, enrichment_hits: int = 0, is_multi_pillar: bool = False) -> tuple:
    """
    Calculate confidence level and score (0-100)
    Based on scale and evidence
    """
    score = 50  # Base confidence
    
    # Scale bonus
    if unique_ips > 1000:
        score += 30
    elif unique_ips > 100:
        score += 20
    elif unique_ips > 20:
        score += 10
        
    # Evidence bonuses
    if enrichment_hits > 0:
        score += 15
    if is_multi_pillar:
        score += 10
        
    score = min(100, score)
    
    if score >= 90:
        level = "CRITICAL"
    elif score >= 75:
        level = "HIGH"
    elif score >= 50:
        level = "MEDIUM"
    else:
        level = "LOW"
        
    return level, score

def aggregate_alerts(raw_alerts: List[Dict]) -> List[Dict]:
    """
    Group duplicate alerts into aggregated events
    
    Raw alerts: per-flow alerts (could be thousands)
    Returns: Aggregated events (1 per attack)
    """
    
    # Group by attack type and target
    ddos_attacks = defaultdict(lambda: {
        "sources": set(),
        "total_flows": 0,
        "first_seen": None,
        "last_seen": None,
        "dst_ip": None,
        "enrichment_hits": 0,
        "multi_pillar": False
    })
    
    scan_attacks = defaultdict(lambda: {
        "targets": set(),
        "total_flows": 0,
        "first_seen": None,
        "last_seen": None,
        "src_ip": None,
        "enrichment_hits": 0
    })
    
    beaconing_patterns = defaultdict(lambda: {
        "flows": [],
        "first_seen": None,
        "last_seen": None,
        "src_ip": None,
        "dst_ip": None
    })
    
    for alert in raw_alerts:
        rule = alert.get("rule", "")
        timestamp = alert.get("timestamp", 0)
        src_ip = alert.get("src_ip", "")
        dst_ip = alert.get("dst_ip", "")
        severity = alert.get("severity", "LOW")
        
        # Group DDoS attacks (many sources → one destination)
        if rule == "ddos_flood":
            key = f"ddos_{dst_ip}"
            ddos_attacks[key]["sources"].add(src_ip)
            ddos_attacks[key]["total_flows"] += 1
            ddos_attacks[key]["dst_ip"] = dst_ip
            if ddos_attacks[key]["first_seen"] is None or timestamp < ddos_attacks[key]["first_seen"]:
                ddos_attacks[key]["first_seen"] = timestamp
            if ddos_attacks[key]["last_seen"] is None or timestamp > ddos_attacks[key]["last_seen"]:
                ddos_attacks[key]["last_seen"] = timestamp
            if severity == "HIGH" or severity == "CRITICAL":
                ddos_attacks[key]["enrichment_hits"] += 1
        
        # Group Scan attacks (one source → many destinations)
        elif rule == "dos_scanning":
            key = f"scan_{src_ip}"
            scan_attacks[key]["targets"].add(dst_ip)
            scan_attacks[key]["total_flows"] += 1
            scan_attacks[key]["src_ip"] = src_ip
            if scan_attacks[key]["first_seen"] is None or timestamp < scan_attacks[key]["first_seen"]:
                scan_attacks[key]["first_seen"] = timestamp
            if scan_attacks[key]["last_seen"] is None or timestamp > scan_attacks[key]["last_seen"]:
                scan_attacks[key]["last_seen"] = timestamp
            if severity == "HIGH":
                scan_attacks[key]["enrichment_hits"] += 1
        
        # Group Beaconing patterns (repeated communication)
        elif rule == "c2_beaconing":
            key = f"beacon_{src_ip}_{dst_ip}"
            beaconing_patterns[key]["flows"].append(alert)
            beaconing_patterns[key]["src_ip"] = src_ip
            beaconing_patterns[key]["dst_ip"] = dst_ip
            if beaconing_patterns[key]["first_seen"] is None or timestamp < beaconing_patterns[key]["first_seen"]:
                beaconing_patterns[key]["first_seen"] = timestamp
            if beaconing_patterns[key]["last_seen"] is None or timestamp > beaconing_patterns[key]["last_seen"]:
                beaconing_patterns[key]["last_seen"] = timestamp
    
    aggregated = []
    
    # Create DDoS aggregated events
    for key, data in ddos_attacks.items():
        unique_sources = len(data["sources"])
        severity = get_severity_for_ddos(unique_sources)
        conf_level, conf_score = calculate_confidence(unique_sources, data["enrichment_hits"])
        
        if unique_sources > 10:  # Minimum threshold
            # schema compatible with engine.py
            event = {
                "timestamp": data["first_seen"],
                "rule": "ddos_flood",
                "event_type": "ddos_attack",
                "severity": severity,
                "src_ip": "multiple",
                "dst_ip": data["dst_ip"],
                "unique_sources": unique_sources,
                "total_flows": data["total_flows"],
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "duration_seconds": round(data["last_seen"] - data["first_seen"], 2) if data["first_seen"] and data["last_seen"] else 0,
                "top_sources": list(data["sources"])[:10],
                "confidence_level": conf_level,
                "confidence_score": conf_score,
                "reason": f"DDoS attack detected: {unique_sources} unique sources targeting {data['dst_ip']} with {data['total_flows']} flows",
                "risk_score": None, # to be filled by engine
                "explanation": None,
                "protocol": "multiple"
            }
            aggregated.append(event)
    
    # Create Scan aggregated events
    for key, data in scan_attacks.items():
        unique_targets = len(data["targets"])
        severity = get_severity_for_scan(unique_targets)
        conf_level, conf_score = calculate_confidence(unique_targets, data["enrichment_hits"])
        
        if unique_targets > 20:
            aggregated.append({
                "timestamp": data["first_seen"],
                "rule": "dos_scanning",
                "event_type": "scan_attack",
                "severity": severity,
                "src_ip": data["src_ip"],
                "dst_ip": "multiple",
                "unique_targets": unique_targets,
                "total_flows": data["total_flows"],
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "duration_seconds": round(data["last_seen"] - data["first_seen"], 2) if data["first_seen"] and data["last_seen"] else 0,
                "top_targets": list(data["targets"])[:10],
                "confidence_level": conf_level,
                "confidence_score": conf_score,
                "reason": f"Port/host scan detected: {data['src_ip']} contacted {unique_targets} unique destinations",
                "risk_score": None,
                "explanation": None,
                "protocol": "multiple"
            })
    
    # Create Beaconing aggregated events
    for key, data in beaconing_patterns.items():
        flow_count = len(data["flows"])
        if flow_count > 5:
            conf_level, conf_score = calculate_confidence(flow_count/10) # scaled
            aggregated.append({
                "timestamp": data["first_seen"],
                "rule": "c2_beaconing",
                "event_type": "c2_beaconing",
                "severity": "HIGH",
                "src_ip": data["src_ip"],
                "dst_ip": data["dst_ip"],
                "total_flows": flow_count,
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "duration_seconds": round(data["last_seen"] - data["first_seen"], 2) if data["first_seen"] and data["last_seen"] else 0,
                "confidence_level": conf_level,
                "confidence_score": conf_score,
                "reason": f"C2 beaconing detected: {data['src_ip']} → {data['dst_ip']} with {flow_count} repeated flows",
                "risk_score": None,
                "explanation": None,
                "protocol": "multiple"
            })
    
    # Sort by severity (CRITICAL first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    aggregated.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 4))
    
    return aggregated


def print_aggregated_summary(raw_count: int, aggregated_events: List[Dict]) -> None:
    """Print summary of aggregated events"""
    if not aggregated_events:
        print(f"\n  Checked {raw_count} raw alerts. No aggregated events detected.\n")
        return
    
    print("\n" + "=" * 70)
    print("  🚨 AGGREGATED SECURITY EVENTS")
    print("=" * 70)
    
    for event in aggregated_events:
        event_type = event.get("event_type", "unknown").upper()
        severity = event.get("severity", "MEDIUM")
        conf_level = event.get("confidence_level", "MEDIUM")
        conf_score = event.get("confidence_score", 0)
        
        print(f"\n  [{severity}] {event_type}")
        print(f"    Confidence: {conf_level} ({conf_score}%)")
        
        if event_type == "DDOS_ATTACK":
            print(f"    Target: {event.get('dst_ip')}")
            print(f"    Unique Sources: {event.get('unique_sources')}")
            print(f"    Total Flows: {event.get('total_flows')}")
            print(f"    Duration: {event.get('duration_seconds')}s")
            print(f"    Top Sources: {', '.join(event.get('top_sources', [])[:5])}")
        
        elif event_type == "SCAN_ATTACK":
            print(f"    Source: {event.get('src_ip')}")
            print(f"    Unique Targets: {event.get('unique_targets')}")
            print(f"    Total Flows: {event.get('total_flows')}")
            print(f"    Duration: {event.get('duration_seconds')}s")
        
        elif event_type == "C2_BEACONING":
            print(f"    Source: {event.get('src_ip')} → Destination: {event.get('dst_ip')}")
            print(f"    Total Flows: {event.get('total_flows')}")
            print(f"    Duration: {event.get('duration_seconds')}s")
        
        print(f"    📝 {event.get('reason')}")
        print(f"    {'-' * 60}")
    
    print("\n" + "=" * 70)
    print(f"  Total Aggregated Events: {len(aggregated_events)}")
    print(f"  Raw Alerts Processed   : {raw_count}")
    reduction = ((raw_count - len(aggregated_events)) / max(1, raw_count)) * 100
    print(f"  Noise Reduction        : {reduction:.1f}%")
    print("=" * 70 + "\n")

#!/usr/bin/env python3
"""
Step 6: Attack Timeline Builder (Enhanced)
Reconstructs a chronological attack narrative from alerts, flows, and IOC data.

Features:
  - Evidence linking (packet numbers, timestamps)
  - DNS query and HTTP request tracking
  - Connection mapping between related events
  - Kill-chain phase classification
  - Human-readable attack story

Produces:
  - timeline_events: ordered list of events with evidence
  - attack_phases:   summary of kill-chain phases observed
  - narrative:       human-readable attack story with connections
"""

from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Any, Optional

# ── Kill-chain phase mapping ─────────────────────────────────────────────────

RULE_TO_PHASE = {
    "phishing":            "Initial Access",
    "suspicious_tld":      "Reconnaissance",
    "dns_tunneling":       "Exfiltration",
    "c2_beaconing":        "Command & Control",
    "malicious_ip":        "Command & Control",
    "http_anomaly":        "Delivery / Execution",
    "multi_pillar_attack": "Full Compromise",
}

PHASE_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Delivery / Execution",
    "Command & Control",
    "Exfiltration",
    "Full Compromise",
]

PHASE_ICONS = {
    "Reconnaissance":       "🔍",
    "Initial Access":       "🎣",
    "Delivery / Execution": "📦",
    "Command & Control":    "📡",
    "Exfiltration":         "💾",
    "Full Compromise":      "💀",
}

# ── Helper: Format timestamp ─────────────────────────────────────────────────

def format_timestamp(ts: float) -> str:
    """Convert Unix timestamp to readable time string with milliseconds."""
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%H:%M:%S") + f".{int(dt.microsecond / 1000):03d}"


# ── Enhanced narrative builder with evidence links ──────────────────────────

def build_attack_narrative(
    alerts: List[Dict],
    flows: List[Dict],
    iocs: Dict,
    packet_map: Optional[Dict] = None
) -> Dict:
    """
    Build chronological narrative with evidence links and connections.
    Includes time-window grouping for dense events.
    """
    all_events = []
    
    # Configuration for timeline precision
    TIME_WINDOW = 5  # Group events within 5 seconds for narrative flow
    
    # ── 1. Add DNS queries from IOCs ────────────────────────────────────────
    for domain in iocs.get('domains', []):
        flow_info = _find_domain_flow(domain, flows)
        ts = flow_info.get('first_seen', 0) if flow_info else 0
        event = {
            'time': ts,
            'event_time': int(ts / TIME_WINDOW) * TIME_WINDOW, # User's suggested windowing
            'time_str': format_timestamp(ts) if ts else '',
            'event': f"DNS query to {domain}",
            'type': 'dns',
            'ioc': domain,
            'severity': 'INFO',
            'evidence': flow_info.get('evidence', 'N/A') if flow_info else 'N/A',
            'packet_num': flow_info.get('packet_num') if flow_info else None,
            'src_ip': flow_info.get('src_ip', 'unknown') if flow_info else 'unknown',
            'dst_ip': flow_info.get('dst_ip', 'unknown') if flow_info else 'unknown',
        }
        all_events.append(event)

    # ── 2. Add HTTP requests from IOCs ──────────────────────────────────────
    for url in iocs.get('urls', []):
        flow_info = _find_url_flow(url, flows)
        ts = flow_info.get('first_seen', 0) if flow_info else 0
        event = {
            'time': ts,
            'event_time': int(ts / TIME_WINDOW) * TIME_WINDOW,
            'time_str': format_timestamp(ts) if ts else '',
            'event': f"HTTP request: {url}",
            'type': 'http',
            'ioc': url,
            'severity': 'INFO',
            'evidence': flow_info.get('evidence', 'N/A') if flow_info else 'N/A',
            'packet_num': flow_info.get('packet_num') if flow_info else None,
            'src_ip': flow_info.get('src_ip', 'unknown') if flow_info else 'unknown',
            'dst_ip': flow_info.get('dst_ip', 'unknown') if flow_info else 'unknown',
        }
        all_events.append(event)

    # ── 3. Add alerts from detection engine ─────────────────────────────────
    for alert in alerts:
        ts = alert.get('timestamp', 0)
        event = {
            'time': ts,
            'event_time': int(ts / TIME_WINDOW) * TIME_WINDOW,
            'time_str': format_timestamp(ts) if ts else '',
            'event': f"[{alert.get('severity', 'INFO')}] {alert.get('rule', 'unknown')}: {alert.get('reason', '')[:80]}",
            'type': 'alert',
            'rule': alert.get('rule'),
            'severity': alert.get('severity', 'MEDIUM'),
            'risk_score': alert.get('risk_score', 0),
            'explanation': alert.get('explanation', ''),
            'src_ip': alert.get('src_ip', 'unknown'),
            'dst_ip': alert.get('dst_ip', 'unknown'),
            'evidence': f"Flow from {alert.get('src_ip')} to {alert.get('dst_ip')}",
        }
        all_events.append(event)

    # ── 4. Sort all events by timestamp ─────────────────────────────────────
    all_events.sort(key=lambda x: x['time'])

    # ── 5. Build timeline with connections ──────────────────────────────────
    timeline_lines = []
    structured_events = []
    domain_to_ip_map = _build_domain_ip_map(flows)
    ip_to_domain_map = {v: k for k, v in domain_to_ip_map.items()}

    for i, event in enumerate(all_events):
        # Format the line
        time_str = event['time_str'] if event['time_str'] else '??:??:??'
        line = f"[{time_str}] {event['event']}"
        
        if event.get('evidence') and event['evidence'] != 'N/A':
            line += f"\n         └─ Evidence: {event['evidence']}"
        
        # Add connection if this event relates to previous
        connection = _find_connection(event, all_events[:i], domain_to_ip_map, ip_to_domain_map)
        if connection:
            line += f"\n         └─ 🔗 Connected: {connection}"
            connections.append({
                'from_event': i,
                'to_event': connection['to_idx'],
                'relationship': connection['desc']
            })
        
        timeline_lines.append(line)
        
        structured_events.append({
            'index': i,
            'time': event['time'],
            'time_str': time_str,
            'type': event['type'],
            'description': event['event'],
            'severity': event.get('severity', 'INFO'),
            'src_ip': event.get('src_ip'),
            'dst_ip': event.get('dst_ip'),
            'evidence': event.get('evidence'),
            'connection': connection.get('desc') if connection else None,
        })

    # ── 6. Build phase summary ──────────────────────────────────────────────
    phase_summary = _build_phase_summary(alerts)

    # ── 7. Generate attack story ────────────────────────────────────────────
    narrative = _generate_attack_story(structured_events, phase_summary, alerts, domain_to_ip_map)

    return {
        'timeline': timeline_lines,
        'events': structured_events,
        'connections': connections,
        'phase_summary': phase_summary,
        'narrative': narrative,
        'stats': {
            'total_events': len(all_events),
            'dns_queries': sum(1 for e in all_events if e['type'] == 'dns'),
            'http_requests': sum(1 for e in all_events if e['type'] == 'http'),
            'alerts': sum(1 for e in all_events if e['type'] == 'alert'),
            'critical_alerts': sum(1 for e in all_events if e.get('severity') == 'CRITICAL'),
            'high_alerts': sum(1 for e in all_events if e.get('severity') == 'HIGH'),
        }
    }


# ── Helper: Find flow containing a domain ───────────────────────────────────

def _find_domain_flow(domain: str, flows: List[Dict]) -> Optional[Dict]:
    """Find the flow that contains a DNS query for the given domain."""
    for flow in flows:
        if flow.get('protocol') != 'UDP' or flow.get('dst_port') != 53:
            continue
        for pkt in flow.get('packets', []):
            try:
                from scapy.all import DNS, DNSQR
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname.decode(errors='replace').rstrip('.')
                    if qname == domain:
                        return {
                            'first_seen': flow.get('start_time'),
                            'evidence': f"DNS flow {flow.get('flow_id')}",
                            'packet_num': _get_packet_number(pkt),
                            'src_ip': flow.get('src_ip'),
                            'dst_ip': flow.get('dst_ip'),
                        }
            except Exception:
                continue
    return None


def _find_url_flow(url: str, flows: List[Dict]) -> Optional[Dict]:
    """Find the flow that contains an HTTP request for the given URL."""
    for flow in flows:
        if flow.get('protocol') != 'TCP' or flow.get('dst_port') != 80:
            continue
        for pkt in flow.get('packets', []):
            try:
                from scapy.all import Raw
                if pkt.haslayer(Raw):
                    payload = pkt[Raw].load.decode(errors='replace')
                    if url in payload:
                        return {
                            'first_seen': flow.get('start_time'),
                            'evidence': f"HTTP flow {flow.get('flow_id')}",
                            'packet_num': _get_packet_number(pkt),
                            'src_ip': flow.get('src_ip'),
                            'dst_ip': flow.get('dst_ip'),
                        }
            except Exception:
                continue
    return None


def _get_packet_number(packet) -> str:
    """Try to extract packet number from Scapy packet."""
    try:
        if hasattr(packet, 'number'):
            return f"packet #{packet.number}"
    except Exception:
        pass
    return "unknown packet"


# ── Build domain → IP mapping from flows ────────────────────────────────────

def _build_domain_ip_map(flows: List[Dict]) -> Dict[str, str]:
    """Map domains to their resolved IPs from DNS responses."""
    mapping = {}
    for flow in flows:
        if flow.get('protocol') != 'UDP' or flow.get('dst_port') != 53:
            continue
        for pkt in flow.get('packets', []):
            try:
                from scapy.all import DNS, DNSRR
                if pkt.haslayer(DNS) and pkt.haslayer(DNSRR):
                    for i in range(pkt[DNS].ancount):
                        rr = pkt[DNSRR]
                        if rr.type == 1:  # A record
                            domain = rr.rrname.decode(errors='replace').rstrip('.')
                            ip = rr.rdata
                            mapping[domain] = ip
            except Exception:
                continue
    return mapping


# ── Find connections between events ─────────────────────────────────────────

def _find_connection(event: Dict, previous_events: List[Dict], 
                     domain_to_ip: Dict, ip_to_domain: Dict) -> Optional[Dict]:
    """Find if current event connects to any previous event."""
    
    # Case 1: Alert about malicious IP, and we saw a DNS query to that IP's domain
    if event['type'] == 'alert' and 'ip' in event.get('event', '').lower():
        for idx, prev in enumerate(previous_events):
            if prev['type'] == 'dns':
                # Check if DNS domain resolves to this IP
                domain = prev.get('ioc')
                if domain and domain_to_ip.get(domain) == event.get('dst_ip'):
                    return {
                        'to_idx': idx,
                        'desc': f"DNS query to '{domain}' resolved to malicious IP {event.get('dst_ip')}"
                    }
    
    # Case 2: Alert about domain, and we saw DNS query for it
    if event['type'] == 'alert' and 'domain' in event.get('event', '').lower():
        for idx, prev in enumerate(previous_events):
            if prev['type'] == 'dns':
                if prev.get('ioc') in event.get('event', ''):
                    return {
                        'to_idx': idx,
                        'desc': f"DNS query for '{prev.get('ioc')}' preceded this alert"
                    }
    
    # Case 3: HTTP request following DNS resolution
    if event['type'] == 'http':
        for idx, prev in enumerate(previous_events):
            if prev['type'] == 'dns':
                domain = prev.get('ioc')
                if domain and domain in event.get('event', ''):
                    return {
                        'to_idx': idx,
                        'desc': f"HTTP request to domain that was just resolved via DNS"
                    }
    
    return None


# ── Phase summary builder ───────────────────────────────────────────────────

def _build_phase_summary(alerts: List[Dict]) -> List[Dict]:
    """Build kill-chain phase summary from alerts."""
    phase_events = defaultdict(list)
    
    for alert in alerts:
        phase = RULE_TO_PHASE.get(alert.get('rule', ''), 'Unknown')
        phase_events[phase].append(alert)
    
    summary = []
    for phase in PHASE_ORDER:
        if phase in phase_events:
            events = phase_events[phase]
            summary.append({
                'phase': phase,
                'icon': PHASE_ICONS.get(phase, '❓'),
                'count': len(events),
                'severities': list(set(e.get('severity') for e in events)),
                'risk_scores': [e.get('risk_score', 0) for e in events if e.get('risk_score')],
            })
    
    return summary


# ── Attack story generator ──────────────────────────────────────────────────

def _generate_attack_story(events: List[Dict], phase_summary: List[Dict], 
                           alerts: List[Dict], domain_to_ip: Dict) -> str:
    """Generate a human-readable attack story."""
    lines = []
    
    if not events:
        return "No suspicious activity detected."
    
    # Time window
    first_time = events[0]['time_str'] if events else 'unknown'
    last_time = events[-1]['time_str'] if events else 'unknown'
    
    lines.append(f"📅 Attack timeline: {first_time} → {last_time}")
    lines.append("")
    
    # Kill-chain progression
    if phase_summary:
        phases_str = " → ".join([f"{p['icon']} {p['phase']}" for p in phase_summary])
        lines.append(f"🔗 Kill-chain progression: {phases_str}")
        lines.append("")
    
    # Critical findings
    critical_alerts = [e for e in events if e.get('severity') == 'CRITICAL']
    if critical_alerts:
        lines.append("⚠️ CRITICAL FINDINGS:")
        for alert in critical_alerts[:3]:
            lines.append(f"   • {alert['description'][:100]}")
        lines.append("")
    
    # Domain to IP mappings (evidence)
    if domain_to_ip:
        lines.append("🔗 Domain → IP resolutions (evidence):")
        for domain, ip in list(domain_to_ip.items())[:5]:
            lines.append(f"   • {domain} → {ip}")
        lines.append("")
    
    # Recommendations
    if critical_alerts:
        lines.append("💡 RECOMMENDATION: Immediate isolation required. Block all IOCs and contain affected hosts.")
    elif any(e.get('severity') == 'HIGH' for e in events):
        lines.append("💡 RECOMMENDATION: Investigate urgently. Review affected systems for compromise indicators.")
    else:
        lines.append("💡 RECOMMENDATION: Monitor traffic. No immediate action required.")
    
    return "\n".join(lines)


# ── Legacy compatibility function (original interface) ──────────────────────

def build_timeline(alerts: List[Dict]) -> Dict:
    """
    Original build_timeline function for backward compatibility.
    Returns simplified timeline without flow/IOC data.
    """
    if not alerts:
        return {
            "events": [],
            "phases": {},
            "phase_summary": [],
            "narrative": "No alerts detected — traffic appears benign.",
            "stats": {
                "total_events": 0,
                "duration_seconds": 0,
                "unique_sources": 0,
                "unique_destinations": 0,
                "rules_triggered": [],
                "severity_counts": {},
            },
        }

    sorted_alerts = sorted(alerts, key=lambda a: a["timestamp"])
    
    events = []
    for i, alert in enumerate(sorted_alerts):
        phase = RULE_TO_PHASE.get(alert["rule"], "Unknown")
        events.append({
            "event_id":    i + 1,
            "timestamp":   alert["timestamp"],
            "time_str":    format_timestamp(alert["timestamp"]),
            "src_ip":      alert["src_ip"],
            "dst_ip":      alert["dst_ip"],
            "protocol":    alert.get("protocol", ""),
            "rule":        alert["rule"],
            "severity":    alert["severity"],
            "phase":       phase,
            "phase_icon":  PHASE_ICONS.get(phase, "❓"),
            "reason":      alert.get("reason", ""),
            "risk_score":  alert.get("risk_score"),
            "explanation": alert.get("explanation", ""),
        })

    phases = defaultdict(list)
    for ev in events:
        phases[ev["phase"]].append(ev)

    phase_summary = []
    for phase in PHASE_ORDER:
        if phase in phases:
            phase_events = phases[phase]
            phase_summary.append({
                "phase":      phase,
                "icon":       PHASE_ICONS.get(phase, "❓"),
                "count":      len(phase_events),
                "first_seen": min(e["time_str"] for e in phase_events),
                "last_seen":  max(e["time_str"] for e in phase_events),
                "severities": list(set(e["severity"] for e in phase_events)),
            })

    timestamps = [a["timestamp"] for a in sorted_alerts]
    stats = {
        "total_events":        len(events),
        "duration_seconds":    round(max(timestamps) - min(timestamps), 2),
        "unique_sources":      len(set(a["src_ip"] for a in sorted_alerts)),
        "unique_destinations": len(set(a["dst_ip"] for a in sorted_alerts)),
        "rules_triggered":     list(set(a["rule"] for a in sorted_alerts)),
        "severity_counts":     dict(defaultdict(int, [(a["severity"], 0) for a in sorted_alerts])),
    }
    
    for a in sorted_alerts:
        stats["severity_counts"][a["severity"]] = stats["severity_counts"].get(a["severity"], 0) + 1

    narrative = _build_simple_narrative(events, phase_summary, stats)

    return {
        "events":        events,
        "phases":        dict(phases),
        "phase_summary": phase_summary,
        "narrative":     narrative,
        "stats":         stats,
    }


def _build_simple_narrative(events, phase_summary, stats):
    """Simple narrative for legacy compatibility."""
    lines = []
    
    first = events[0] if events else None
    last = events[-1] if events else None
    
    if first and last:
        lines.append(
            f"Attack activity detected between {first['time_str']} and "
            f"{last['time_str']} ({stats['duration_seconds']:.0f}s window)."
        )
        lines.append(
            f"A total of {stats['total_events']} security events were recorded "
            f"across {stats['unique_sources']} source(s) and "
            f"{stats['unique_destinations']} destination(s)."
        )

    if phase_summary:
        phases_seen = [p["phase"] for p in phase_summary]
        lines.append(f"\nKill-chain phases observed: {', '.join(phases_seen)}.")

    sev = stats.get("severity_counts", {})
    if sev.get("CRITICAL", 0) > 0:
        lines.append(
            f"\n⚠️  {sev['CRITICAL']} CRITICAL alert(s) detected — "
            "immediate response recommended."
        )

    return "\n".join(lines)


# ── Main entry point for testing ────────────────────────────────────────────

if __name__ == "__main__":
    # Test with sample data
    import json
    
    print("Attack Timeline Builder (Enhanced)")
    print("=" * 50)
    print("This module provides timeline reconstruction with evidence linking.")
    print("Import and use with your alerts, flows, and IOCs.")
    
    # Example usage:
    # from timeline.builder import build_attack_narrative
    # result = build_attack_narrative(alerts, flows, iocs)
    # for line in result['timeline']:
    #     print(line)
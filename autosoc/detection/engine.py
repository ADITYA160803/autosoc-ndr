#!/usr/bin/env python3
"""
AutoSOC NDR - Detection Engine (Final)
Complete pipeline: PCAP → Flows → IOCs → Detection → Aggregation → Enrichment → Risk → Timeline
"""

import sys
import os
import json
import time
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# FAST MODE - Skip deep parsing for DDoS detection
FAST_MODE = os.environ.get('FAST_MODE', 'false').lower() == 'true'

# ── Severity ordering ─────────────────────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_ICONS = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED]", "LOW": "[LOW]"}
DEDUP_WINDOW = 60.0


# ── Core detection ────────────────────────────────────────────────────────────

def run_detection(flows: list[dict], iocs: dict) -> list[dict]:
    """Run every rule against every flow. Returns raw alerts."""
    from detection.rules import ALL_RULES

    raw_alerts = []

    for flow in flows:
        for rule_fn in ALL_RULES:
            try:
                result = rule_fn(flow, iocs, flows)
            except Exception as exc:
                # print(f"  [engine] Rule '{rule_fn.__name__}' raised: {exc}", file=sys.stderr)
                result = None

            if result is None:
                continue

            raw_alerts.append({
                "timestamp": flow["start_time"],
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "protocol": flow["protocol"],
                "rule": result["rule"],
                "severity": result.get("severity", "MEDIUM"),
                "reason": result.get("reason", ""),
                "risk_score": None,
                "explanation": None,
            })

    return _deduplicate(raw_alerts)


def _deduplicate(alerts: list[dict]) -> list[dict]:
    """Remove duplicate alerts within DEDUP_WINDOW seconds."""
    last_seen = {}
    kept = []

    for alert in sorted(alerts, key=lambda a: a["timestamp"]):
        key = (alert["src_ip"], alert["dst_ip"], alert["rule"])
        ts = alert["timestamp"]
        if key not in last_seen or (ts - last_seen[key]) > DEDUP_WINDOW:
            kept.append(alert)
            last_seen[key] = ts

    return kept

def detect_ddos_fast(flows: list[dict]) -> list[dict]:
    """
    Pre-aggregate DDoS attacks without processing each flow individually.
    Reduces 7,000 flows to 1 aggregated result instantly.
    """
    from collections import defaultdict
    
    # Count sources per destination
    target_counts = defaultdict(lambda: {'sources': set(), 'total_packets': 0, 'first_seen': None, 'last_seen': None})
    
    for flow in flows:
        dst = flow['dst_ip']
        src = flow['src_ip']
        ts = flow.get('start_time', 0)
        target_counts[dst]['sources'].add(src)
        target_counts[dst]['total_packets'] += flow.get('packet_count', 1)
        if target_counts[dst]['first_seen'] is None or ts < target_counts[dst]['first_seen']:
            target_counts[dst]['first_seen'] = ts
        if target_counts[dst]['last_seen'] is None or ts > target_counts[dst]['last_seen']:
            target_counts[dst]['last_seen'] = ts
    
    # Find DDoS attacks
    ddos_alerts = []
    for dst, data in target_counts.items():
        unique_sources = len(data['sources'])
        if unique_sources > 100:  # DDoS threshold
            severity = "CRITICAL" if unique_sources > 5000 else "HIGH" if unique_sources > 1000 else "MEDIUM"
            ddos_alerts.append({
                'event_type': 'ddos_attack',
                'rule': 'ddos_flood',
                'severity': severity,
                'target_ip': dst,
                'unique_sources': unique_sources,
                'total_flows': data['total_packets'],
                'first_seen': data['first_seen'],
                'last_seen': data['last_seen'],
                'duration_seconds': round(data['last_seen'] - data['first_seen'], 2) if data['first_seen'] and data['last_seen'] else 0,
                'reason': f"DDoS attack: {unique_sources} sources targeting {dst}"
            })
    
    return ddos_alerts


# ── Enrichment & Scoring ──────────────────────────────────────────────────────

def enrich_and_score(alerts: list[dict], iocs: dict) -> list[dict]:
    """Enrich IOCs and calculate risk scores for each alert."""
    from enrichment.service import enrich_iocs
    from scoring.risk import calculate_risk_score, generate_explanation

    print("  Enriching IOCs ...", end="", flush=True)
    enriched = enrich_iocs(iocs)
    print(f" done ({_enrichment_stats(enriched)})")

    for alert in alerts:
        score = calculate_risk_score(alert, enriched)
        alert["risk_score"] = score
        alert["explanation"] = generate_explanation(alert, enriched, score)

    return alerts


def build_frontend_timeline(alerts: list[dict]) -> list[dict]:
    """Create timeline events for the frontend from final alerts/events."""
    timeline = []
    for index, alert in enumerate(alerts):
        timestamp = alert.get("timestamp") or alert.get("first_seen") or alert.get("last_seen") or 0
        timeline.append({
            "event_id": index + 1,
            "timestamp": timestamp,
            "time": timestamp,
            "rule": alert.get("rule") or alert.get("event_type") or "security_event",
            "event_type": alert.get("event_type") or alert.get("rule") or "security_event",
            "severity": alert.get("severity", "LOW"),
            "src_ip": alert.get("src_ip") or alert.get("source_ip") or "N/A",
            "dst_ip": alert.get("dst_ip") or alert.get("destination_ip") or "N/A",
            "reason": alert.get("reason") or alert.get("description") or alert.get("explanation") or "No details provided",
            "risk_score": alert.get("risk_score", 0),
        })

    return sorted(timeline, key=lambda event: event.get("timestamp") or 0)


def _enrichment_stats(enriched: dict) -> str:
    ips = len(enriched.get("ips", {}))
    doms = len(enriched.get("domains", {}))
    urls = len(enriched.get("urls", {}))
    return f"{ips} IPs, {doms} domains, {urls} URLs"


# ── Alert Aggregation ────────────────────────

def aggregate_alerts(raw_alerts: list[dict]) -> list[dict]:
    """Group duplicate alerts into meaningful security events."""
    from collections import defaultdict

    ddos_attacks = defaultdict(lambda: {
        "sources": set(),
        "total_flows": 0,
        "first_seen": None,
        "last_seen": None,
        "dst_ip": None,
        "enrichment_hits": 0
    })

    scan_attacks = defaultdict(lambda: {
        "targets": set(),
        "total_flows": 0,
        "first_seen": None,
        "last_seen": None,
        "src_ip": None
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

        # Count enrichment hits from reason text
        reason = alert.get("reason", "")
        enrichment_hits = 0
        if "VirusTotal" in reason:
            enrichment_hits += 1
        if "AbuseIPDB" in reason:
            enrichment_hits += 1
        if "URLhaus" in reason:
            enrichment_hits += 1

        if rule == "ddos_flood":
            key = f"ddos_{dst_ip}"
            ddos_attacks[key]["sources"].add(src_ip)
            ddos_attacks[key]["total_flows"] += 1
            ddos_attacks[key]["dst_ip"] = dst_ip
            ddos_attacks[key]["enrichment_hits"] = max(ddos_attacks[key]["enrichment_hits"], enrichment_hits)
            if ddos_attacks[key]["first_seen"] is None or timestamp < ddos_attacks[key]["first_seen"]:
                ddos_attacks[key]["first_seen"] = timestamp
            if ddos_attacks[key]["last_seen"] is None or timestamp > ddos_attacks[key]["last_seen"]:
                ddos_attacks[key]["last_seen"] = timestamp

        elif rule == "dos_scanning":
            key = f"scan_{src_ip}"
            scan_attacks[key]["targets"].add(dst_ip)
            scan_attacks[key]["total_flows"] += 1
            scan_attacks[key]["src_ip"] = src_ip
            if scan_attacks[key]["first_seen"] is None or timestamp < scan_attacks[key]["first_seen"]:
                scan_attacks[key]["first_seen"] = timestamp
            if scan_attacks[key]["last_seen"] is None or timestamp > scan_attacks[key]["last_seen"]:
                scan_attacks[key]["last_seen"] = timestamp

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

    # DDoS aggregation
    for key, data in ddos_attacks.items():
        unique_sources = len(data["sources"])
        if unique_sources > 5000:
            severity = "CRITICAL"
        elif unique_sources > 1000:
            severity = "HIGH"
        elif unique_sources > 100:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        if unique_sources > 10:
            aggregated.append({
                "event_type": "ddos_attack",
                "severity": severity,
                "target_ip": data["dst_ip"],
                "unique_sources": unique_sources,
                "total_flows": data["total_flows"],
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "duration_seconds": round(data["last_seen"] - data["first_seen"], 2) if data["first_seen"] and data["last_seen"] else 0,
                "top_sources": list(data["sources"])[:10],
                "reason": f"DDoS attack: {unique_sources} sources targeting {data['dst_ip']} with {data['total_flows']} flows"
            })

    # Scan aggregation
    for key, data in scan_attacks.items():
        unique_targets = len(data["targets"])
        if unique_targets > 50:
            severity = "HIGH"
        elif unique_targets > 20:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        if unique_targets > 10:
            aggregated.append({
                "event_type": "scan_attack",
                "severity": severity,
                "source_ip": data["src_ip"],
                "unique_targets": unique_targets,
                "total_flows": data["total_flows"],
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "duration_seconds": round(data["last_seen"] - data["first_seen"], 2) if data["first_seen"] and data["last_seen"] else 0,
                "reason": f"Scan attack: {data['src_ip']} contacted {unique_targets} unique destinations"
            })

    # Beaconing aggregation
    for key, data in beaconing_patterns.items():
        flow_count = len(data["flows"])
        if flow_count > 5:
            aggregated.append({
                "event_type": "c2_beaconing",
                "severity": "HIGH",
                "source_ip": data["src_ip"],
                "destination_ip": data["dst_ip"],
                "total_flows": flow_count,
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "duration_seconds": round(data["last_seen"] - data["first_seen"], 2) if data["first_seen"] and data["last_seen"] else 0,
                "reason": f"C2 beaconing: {data['src_ip']} → {data['dst_ip']} with {flow_count} repeated flows"
            })

    return aggregated


def print_aggregated_summary(raw_count: int, aggregated: list[dict]) -> None:
    """Print aggregated events summary with reduction stats."""
    if not aggregated:
        print("\n  No aggregated events detected.\n")
        return

    reduction_percent = (len(aggregated) / raw_count) * 100 if raw_count > 0 else 0

    print("\n" + "=" * 70)
    print("  🚨 AGGREGATED SECURITY EVENTS")
    print("=" * 70)

    for event in aggregated:
        event_type = event.get("event_type", "unknown").upper()
        severity = event.get("severity", "MEDIUM")

        print(f"\n  [{severity}] {event_type}")

        if event_type == "DDOS_ATTACK":
            print(f"    Target: {event.get('target_ip')}")
            print(f"    Unique Sources: {event.get('unique_sources')}")
            print(f"    Total Flows: {event.get('total_flows')}")
            print(f"    Duration: {event.get('duration_seconds')}s")
            # print(f"    Top Sources: {', '.join(event.get('top_sources', [])[:5])}")

        elif event_type == "SCAN_ATTACK":
            print(f"    Source: {event.get('source_ip')}")
            print(f"    Unique Targets: {event.get('unique_targets')}")
            print(f"    Total Flows: {event.get('total_flows')}")
            print(f"    Duration: {event.get('duration_seconds')}s")

        elif event_type == "C2_BEACONING":
            print(f"    Source: {event.get('source_ip')} → Destination: {event.get('destination_ip')}")
            print(f"    Total Flows: {event.get('total_flows')}")
            print(f"    Duration: {event.get('duration_seconds')}s")

        print(f"    📝 {event.get('reason')}")
        print(f"    {'-' * 60}")

    print("\n" + "=" * 70)
    print(f"  Raw Alerts: {raw_count}")
    print(f"  Aggregated Events: {len(aggregated)}")
    print(f"  Reduction: {raw_count} → {len(aggregated)} ({reduction_percent:.1f}% of original)")
    print("=" * 70 + "\n")


# ── Attack Chain Linking ───────────────────────────────────

def build_attack_chains(aggregated_events: list[dict]) -> list[dict]:
    """Link related events into attack campaigns."""
    from collections import defaultdict

    campaigns = []
    campaign_id = 1
    used_events = set()

    for i, event in enumerate(aggregated_events):
        if i in used_events:
            continue

        # Start new campaign
        campaign = {
            "campaign_id": f"CAMP-{campaign_id:03d}",
            "events": [event],
            "affected_ips": set(),
            "stages": set(),
            "severity": event.get("severity", "MEDIUM"),
            "start_time": event.get("first_seen"),
            "end_time": event.get("last_seen")
        }

        # Add IPs from this event
        if "target_ip" in event:
            campaign["affected_ips"].add(event["target_ip"])
        if "source_ip" in event:
            campaign["affected_ips"].add(event["source_ip"])
        if "destination_ip" in event:
            campaign["affected_ips"].add(event["destination_ip"])

        # Add stage
        event_type = event.get("event_type", "")
        if "scan" in event_type:
            campaign["stages"].add("reconnaissance")
        elif "ddos" in event_type:
            campaign["stages"].add("impact")
        elif "beaconing" in event_type:
            campaign["stages"].add("c2")

        # Find related events
        for j, other in enumerate(aggregated_events):
            if j == i or j in used_events:
                continue

            # Check if shares any IP
            other_ips = set()
            if "target_ip" in other:
                other_ips.add(other["target_ip"])
            if "source_ip" in other:
                other_ips.add(other["source_ip"])
            if "destination_ip" in other:
                other_ips.add(other["destination_ip"])

            if campaign["affected_ips"].intersection(other_ips):
                used_events.add(j)
                campaign["events"].append(other)
                campaign["affected_ips"].update(other_ips)

                # Update severity
                other_sev = other.get("severity", "MEDIUM")
                if other_sev == "CRITICAL" or campaign["severity"] == "CRITICAL":
                    campaign["severity"] = "CRITICAL"
                elif other_sev == "HIGH" or campaign["severity"] == "HIGH":
                    campaign["severity"] = "HIGH"

                # Update time range
                if other.get("first_seen") and (campaign["start_time"] is None or other["first_seen"] < campaign["start_time"]):
                    campaign["start_time"] = other["first_seen"]
                if other.get("last_seen") and (campaign["end_time"] is None or other["last_seen"] > campaign["end_time"]):
                    campaign["end_time"] = other["last_seen"]

        campaigns.append(campaign)
        campaign_id += 1

    # Format campaigns for output
    result = []
    for campaign in campaigns:
        stages = list(campaign["stages"])
        chain_parts = []
        if "reconnaissance" in stages:
            chain_parts.append("🔍 Reconnaissance")
        if "c2" in stages:
            chain_parts.append("📡 C2")
        if "impact" in stages:
            chain_parts.append("💥 Impact")

        attack_chain = " → ".join(chain_parts) if chain_parts else "Single Event"

        result.append({
            "campaign_id": campaign["campaign_id"],
            "severity": campaign["severity"],
            "attack_chain": attack_chain,
            "stages": stages,
            "affected_ips": list(campaign["affected_ips"]),
            "total_events": len(campaign["events"]),
            "duration_seconds": round(campaign["end_time"] - campaign["start_time"], 2) if campaign["start_time"] and campaign["end_time"] else 0,
            "recommendation": _get_recommendation(campaign["severity"], stages)
        })

    return result


def _get_recommendation(severity: str, stages: list) -> str:
    """Generate recommendation based on attack severity."""
    if severity == "CRITICAL":
        return "Immediately isolate affected hosts. Block all related IPs. Initiate incident response."
    elif severity == "HIGH":
        return "Investigate urgently. Review affected systems for compromise. Block malicious IPs."
    elif "c2" in stages:
        return "Check for data exfiltration. Reset credentials. Run full antivirus scan."
    else:
        return "Monitor traffic. Review logs for additional indicators."


def print_campaign_summary(campaigns: list[dict]) -> None:
    """Print attack campaign summary."""
    if not campaigns:
        # print("\n  No attack campaigns detected.\n")
        return

    print("\n" + "=" * 70)
    print("  🎯 ATTACK CAMPAIGNS (Linked Attack Chains)")
    print("=" * 70)

    for campaign in campaigns:
        print(f"\n  [{campaign['severity']}] {campaign['campaign_id']}")
        print(f"    Attack Chain: {campaign['attack_chain']}")
        print(f"    Affected IPs: {', '.join(campaign['affected_ips'][:5])}")
        print(f"    Total Events: {campaign['total_events']}")
        print(f"    Duration: {campaign['duration_seconds']}s")
        print(f"    📝 Recommendation: {campaign['recommendation']}")
        print(f"    {'-' * 60}")

    print("\n" + "=" * 70 + "\n")


# ── Display Functions ─────────────────────────────────────────────────────────

def print_alerts_summary(alerts: list[dict], sample_per_severity: int = 3) -> None:
    """Print severity counts and sample alerts."""
    if not alerts:
        print("\n  No alerts detected.\n")
        return

    from collections import Counter
    counts = Counter(a.get("severity", "LOW") for a in alerts)

    print("\n" + "=" * 68)
    print("  DETECTION SUMMARY")
    print("=" * 68)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev in counts:
            print(f"  {SEVERITY_ICONS.get(sev, sev):<8} {counts[sev]:>4} alert(s)")
    print(f"  {'-' * 40}")
    print(f"     TOTAL{' ' * 8}{len(alerts):>4} alert(s)\n")


def print_risk_summary(alerts: list[dict], top_n: int = 5) -> None:
    """Print top N alerts by risk score."""
    scored = [a for a in alerts if a.get("risk_score") is not None]
    if not scored:
        # print("\n  (No risk scores available)\n")
        return

    top = sorted(scored, key=lambda a: a["risk_score"], reverse=True)[:top_n]

    print("\n" + "=" * 68)
    print(f"  TOP {top_n} HIGHEST-RISK ALERTS")
    print("=" * 68)

    for rank, alert in enumerate(top, start=1):
        score = alert["risk_score"]
        bar = "[" + "#" * int(score / 10) + "." * (10 - int(score / 10)) + "]"
        
        # Handle both raw alerts (timestamp) and aggregated events (first_seen)
        if "timestamp" in alert:
            ts = datetime.fromtimestamp(alert["timestamp"]).strftime("%H:%M:%S")
        elif "first_seen" in alert:
            ts = datetime.fromtimestamp(alert["first_seen"]).strftime("%H:%M:%S")
        else:
            ts = "N/A"
        
        # Get source/destination based on event type
        src = alert.get("src_ip", alert.get("source_ip", "N/A"))
        dst = alert.get("dst_ip", alert.get("target_ip", alert.get("destination_ip", "N/A")))
        rule = alert.get("rule", alert.get("event_type", "unknown"))
        
        print(f"\n  #{rank}  {bar}  {score:>3}/100  [{alert['severity']}]  {ts}")
        print(f"       {src} -> {dst}  rule: {rule}")


# ── Main Pipeline ────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) != 2:
        sys.exit(f"Usage: python {sys.argv[0]} <pcap_file>")

    filepath = sys.argv[1]
    
    # Check cache
    try:
        from storage.cache import get_cached_result, cache_result
        cached = get_cached_result(filepath)
        if cached:
            print(f"  [+] CACHE HIT - Returning previous results for {os.path.basename(filepath)}")
            # Output for web app to parse
            print(f"Packets : {cached.get('metadata', {}).get('packets', 0)}")
            print(f"Flows   : {cached.get('metadata', {}).get('flows', 0)}")
            print(f"IOCs    : {cached.get('metadata', {}).get('ips', 0)} IPs | {cached.get('metadata', {}).get('domains', 0)} domains | {cached.get('metadata', {}).get('urls', 0)} URLs")
            print(f"Alerts  : {len(cached.get('alerts', []))}")
            
            # Save to output/alerts.json (web app looks here)
            os.makedirs('output', exist_ok=True)
            with open('output/alerts.json', 'w') as f:
                json.dump(cached.get('alerts', []), f, indent=2, default=str)
            with open('output/timeline.json', 'w') as f:
                json.dump(build_frontend_timeline(cached.get('alerts', [])), f, indent=2, default=str)
            print("\nAnalysis complete (cached)!\n")
            return
    except Exception:
        pass

    print(f"Loading : {filepath}")

    try:
        from scapy.all import rdpcap
        from pcap.aggregator import aggregate_flows
        from pcap.extractor import extract_iocs_from_flows
        from pcap.parallel_parser import parse_pcap_parallel
    except ImportError as exc:
        sys.exit(f"Import error: {exc}\nRun from project root.")

    if FAST_MODE:
        print("  [+] FAST MODE ENABLED - Using optimized detection")
        # In fast mode we skip scapy for everything
        flows_basic = parse_pcap_parallel(filepath)
        # Convert simple results to pseudo-flows for detect_ddos_fast
        ddos_events = detect_ddos_fast(flows_basic)
        
        print(f"Packets : {len(flows_basic)}")
        print(f"Flows   : {len(flows_basic)}")
        print(f"IOCs    : 0 IPs | 0 domains | 0 URLs")
        print(f"Alerts  : {len(ddos_events)}")
        
        # Save results
        os.makedirs('output', exist_ok=True)
        with open('output/alerts.json', 'w') as f:
            json.dump(ddos_events, f, indent=2, default=str)
        with open('output/timeline.json', 'w') as f:
            json.dump(build_frontend_timeline(ddos_events), f, indent=2, default=str)
        
        # Cache results
        try:
            cache_result(filepath, {
                'alerts': ddos_events,
                'metadata': {'packets': len(flows_basic), 'flows': len(flows_basic), 'ips': 0, 'domains': 0, 'urls': 0}
            })
        except: pass
        
        print("\nAnalysis complete!\n")
        return

    try:
        packets = rdpcap(filepath)
    except FileNotFoundError:
        sys.exit(f"Error: file not found -- {filepath}")
    except Exception as exc:
        sys.exit(f"Error reading PCAP: {exc}")

    print(f"Packets : {len(packets)}")

    flows = aggregate_flows(packets)
    print(f"Flows   : {len(flows)}")

    iocs = extract_iocs_from_flows(flows)
    print(f"IOCs    : {len(iocs['ips'])} IPs | {len(iocs['domains'])} domains | {len(iocs['urls'])} URLs")

    # Step 1: Raw detection
    raw_alerts = run_detection(flows, iocs)
    print(f"Raw Alerts  : {len(raw_alerts)}")

    # Step 2: ALERT AGGREGATION
    aggregated_events = aggregate_alerts(raw_alerts)
    print_aggregated_summary(len(raw_alerts), aggregated_events)

    # Step 3: Use aggregated events for further processing
    alerts = aggregated_events if aggregated_events else raw_alerts

    # Step 4: Enrichment and scoring
    alerts = enrich_and_score(alerts, iocs)

    # Step 5: Attack chain linking
    campaigns = build_attack_chains(aggregated_events if aggregated_events else [])
    print_campaign_summary(campaigns)

    # Step 6: Output
    print_alerts_summary(alerts)
    # print_risk_summary(alerts, top_n=5)

    # Save results
    os.makedirs('output', exist_ok=True)
    with open('output/alerts.json', 'w') as f:
        json.dump(alerts, f, indent=2, default=str)

    with open('output/campaigns.json', 'w') as f:
        json.dump(campaigns, f, indent=2, default=str)

    with open('output/timeline.json', 'w') as f:
        json.dump(build_frontend_timeline(alerts), f, indent=2, default=str)

    # Cache results
    try:
        cache_result(filepath, {
            'alerts': alerts,
            'campaigns': campaigns,
            'metadata': {
                'packets': len(packets),
                'flows': len(flows),
                'ips': len(iocs['ips']),
                'domains': len(iocs['domains']),
                'urls': len(iocs['urls'])
            }
        })
    except: pass

    print("\nAnalysis complete!\n")


if __name__ == "__main__":
    main()

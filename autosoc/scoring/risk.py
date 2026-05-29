#!/usr/bin/env python3
"""
Step 5b: Risk Scoring (Updated for Aggregated Events)
Converts a raw alert or aggregated event into a 0–100 risk score
and a human-readable explanation.
"""

# ── Score constants ───────────────────────────────────────────────────────────

BASE_SCORES = {
    "CRITICAL": 90,
    "HIGH":     70,
    "MEDIUM":   40,
    "LOW":      10,
}

BONUS_ENRICHMENT_MALICIOUS = 10
BONUS_MULTI_IOC            = 5
SCORE_CAP                  = 100

_ACTIONS = {
    range(80, 101): "Block immediately and isolate the host.",
    range(50,  80): "Investigate urgently — treat as confirmed threat.",
    range(20,  50): "Review manually — possible false positive.",
    range(0,   20): "Monitor; low confidence.",
}


def _recommended_action(score: int) -> str:
    for r, action in _ACTIONS.items():
        if score in r:
            return action
    return "Monitor."


def _get_ip_from_alert(alert: dict) -> str:
    """Extract IP address from raw alert or aggregated event."""
    # Raw alert format
    if "dst_ip" in alert:
        return alert["dst_ip"]
    # Aggregated DDoS event format
    if "target_ip" in alert:
        return alert["target_ip"]
    # Aggregated scan event format
    if "source_ip" in alert:
        return alert["source_ip"]
    # Aggregated beaconing format
    if "destination_ip" in alert:
        return alert["destination_ip"]
    return None


def _get_enrichment_for_alert(alert: dict, enriched: dict) -> dict:
    """
    Pull all enrichment results that are relevant to this alert.
    Handles both raw alerts and aggregated events.
    """
    ip_data = None
    domain_data = None
    url_data = None
    
    # Get IP from alert (handles different formats)
    ip = _get_ip_from_alert(alert)
    if ip:
        ip_data = enriched.get("ips", {}).get(ip)
    
    # For aggregated events, check reason text for domains/URLs
    reason = alert.get("reason", "")
    for domain, data in enriched.get("domains", {}).items():
        if domain in reason:
            domain_data = data
            break
    for url, data in enriched.get("urls", {}).items():
        if url in reason:
            url_data = data
            break
    
    return {"ip_data": ip_data, "domain_data": domain_data, "url_data": url_data}


def calculate_risk_score(alert: dict, enriched: dict) -> int:
    """
    Return an integer risk score 0–100.
    Works with both raw alerts and aggregated events.
    """
    severity = alert.get("severity", "LOW")
    base_score = BASE_SCORES.get(severity, 10)
    score = base_score
    
    ctx = _get_enrichment_for_alert(alert, enriched)
    
    any_malicious = any(
        (ctx[k] or {}).get("is_malicious", False)
        for k in ("ip_data", "domain_data", "url_data")
    )
    if any_malicious:
        score += BONUS_ENRICHMENT_MALICIOUS
    
    # Check for multi-pillar (domain + IP)
    if ctx.get("domain_data") and ctx.get("ip_data"):
        if ctx["domain_data"].get("is_malicious") and ctx["ip_data"].get("is_malicious"):
            score += BONUS_MULTI_IOC
    
    # Bonus for aggregated DDoS with many sources
    if alert.get("event_type") == "ddos_attack":
        unique_sources = alert.get("unique_sources", 0)
        if unique_sources > 5000:
            score += 15
        elif unique_sources > 1000:
            score += 10
        elif unique_sources > 100:
            score += 5
    
    # Bonus for scan with many targets
    if alert.get("event_type") == "scan_attack":
        unique_targets = alert.get("unique_targets", 0)
        if unique_targets > 100:
            score += 10
        elif unique_targets > 50:
            score += 5
    
    return min(score, SCORE_CAP)


def generate_explanation(alert: dict, enriched: dict, score: int) -> str:
    """
    Return a human-readable explanation with:
      - the score
      - key evidence from the alert and enrichment
      - a recommended action
    """
    parts = [f"Score {score}/100:"]
    
    ctx = _get_enrichment_for_alert(alert, enriched)
    event_type = alert.get("event_type", "")
    
    # DDoS Attack (aggregated)
    if event_type == "ddos_attack":
        target = alert.get("target_ip", "unknown")
        sources = alert.get("unique_sources", 0)
        flows = alert.get("total_flows", 0)
        parts.append(f"DDoS attack detected: {sources} unique sources targeting {target} with {flows} flows.")
        
        if ctx["ip_data"] and ctx["ip_data"].get("abuse_score", 0) > 0:
            parts.append(f"AbuseIPDB abuse score: {ctx['ip_data']['abuse_score']}/100.")
        
        if sources > 5000:
            parts.append("Critical-scale attack requiring immediate response.")
    
    # Scan Attack (aggregated)
    elif event_type == "scan_attack":
        source = alert.get("source_ip", "unknown")
        targets = alert.get("unique_targets", 0)
        parts.append(f"Port/host scan detected: {source} contacted {targets} unique destinations.")
    
    # C2 Beaconing (aggregated)
    elif event_type == "c2_beaconing":
        src = alert.get("source_ip", "unknown")
        dst = alert.get("destination_ip", "unknown")
        flows = alert.get("total_flows", 0)
        parts.append(f"C2 beaconing detected: {src} → {dst} with {flows} repeated flows.")
        
        if ctx["ip_data"] and ctx["ip_data"].get("abuse_score", 0) > 0:
            parts.append(f"Destination IP abuse score: {ctx['ip_data']['abuse_score']}/100.")
    
    # Raw alerts (fallback)
    else:
        rule = alert.get("rule", "unknown")
        reason = alert.get("reason", "")
        parts.append(reason if reason else f"Rule triggered: {rule}")
        
        if ctx["ip_data"] and ctx["ip_data"].get("abuse_score", 0) > 0:
            parts.append(f"AbuseIPDB score: {ctx['ip_data']['abuse_score']}/100.")
        if ctx["domain_data"] and ctx["domain_data"].get("malicious_votes", 0) > 0:
            mv = ctx["domain_data"]["malicious_votes"]
            tv = ctx["domain_data"]["total_votes"]
            parts.append(f"VirusTotal: {mv}/{tv} detections.")
    
    parts.append(f"[{alert.get('severity', 'MEDIUM')}]")
    parts.append(f"Recommended: {_recommended_action(score)}")
    
    return " ".join(parts)
#!/usr/bin/env python3
"""
Step 4a: Detection Rules (Enhanced with DoS/DDoS Detection)
Eleven rule functions, each with the signature:

    rule_fn(flow: dict, iocs: dict, all_flows: list[dict]) -> dict | None

Returning a dict means the rule fired; None means clean.

Each returned alert dict contains:
    rule, severity, reason
(timestamp, src_ip, dst_ip are added by the engine.)

Detection Categories:
  - Reconnaissance: suspicious_tld
  - Initial Access: phishing, dos_scanning
  - Delivery/Execution: http_anomaly
  - Command & Control: c2_beaconing, malicious_ip, ddos_flood
  - Exfiltration: dns_tunneling
  - Full Compromise: multi_pillar_attack
"""

import math
from collections import Counter
from scapy.all import TCP, Raw

# ── Configurable constants ────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {".cyou", ".top", ".xyz", ".ru", ".su", ".tk", ".ml", ".ga"}

# Extend this list with real bad IPs from your Lumma PCAP
KNOWN_BAD_IPS: set[str] = {
    # "1.2.3.4",   ← add malicious IPs here
    "45.156.87.83",  # Lumma Stealer C2 from your PCAP
    "104.21.36.177", # whooptm.cyou resolved IP
}

SUSPICIOUS_PATH_TOKENS = {".exe", ".dll", ".scr", ".bat", ".ps1",
                           "/update", "/gateway", "/payload", "/drop"}

BEACONING_THRESHOLD  = 3     # min flows for same src→dst pair to flag
DNS_TUNNELING_LENGTH = 40    # characters in domain label
DNS_TUNNELING_ENTROPY = 3.8  # bits — typical English text ≈ 3.1, random ≈ 4.5

# DoS/DDoS thresholds
DOS_SCAN_THRESHOLD = 50      # unique destinations from one source
DDOS_FLOOD_THRESHOLD = 100   # unique sources to one destination
DOS_PACKET_RATE_THRESHOLD = 500  # packets per second (approximate)


# ── Shared utilities ──────────────────────────────────────────────────────────

def _domain_from_flow(flow: dict) -> str | None:
    """Return the DNS domain queried in this flow, or None."""
    if flow["protocol"] != "UDP" or flow["dst_port"] != 53:
        return None
    for pkt in flow["packets"]:
        try:
            from scapy.all import DNS, DNSQR
            if pkt.haslayer(DNSQR):
                return pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
        except Exception:
            continue
    return None


def _tld(domain: str) -> str:
    """Return the TLD including the leading dot, e.g. '.xyz'."""
    parts = domain.rsplit(".", 1)
    return f".{parts[-1]}" if len(parts) == 2 else ""


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy (bits) for a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in counts.values()
    )


def _http_first_line(flow: dict) -> str | None:
    """Return the first line of an HTTP request payload, or None."""
    if flow["protocol"] != "TCP" or flow["dst_port"] != 80:
        return None
    for pkt in flow["packets"]:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                first_line = pkt[Raw].load.decode(errors="replace").split("\r\n")[0]
                if any(first_line.startswith(m) for m in
                       ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS",
                        "PATCH", "CONNECT", "TRACE")):
                    return first_line
            except Exception:
                continue
    return None


def _full_http_headers(flow: dict) -> str | None:
    """Return the full header block of the first HTTP request, or None."""
    if flow["protocol"] != "TCP" or flow["dst_port"] != 80:
        return None
    for pkt in flow["packets"]:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                return pkt[Raw].load.decode(errors="replace")
            except Exception:
                continue
    return None


def _calculate_packet_rate(flow: dict) -> float:
    """Calculate packets per second for a flow."""
    duration = flow.get("end_time", 0) - flow.get("start_time", 0)
    if duration <= 0:
        return 0
    return flow.get("packet_count", 0) / duration


# ── Rule 1: Phishing ──────────────────────────────────────────────────────────

def phishing_rule(flow: dict, iocs: dict, all_flows: list) -> dict | None:
    """
    Flag DNS flows querying a domain with a suspicious TLD.
    (Proxy for 'newly registered domain' until WHOIS enrichment is added.)
    """
    domain = _domain_from_flow(flow)
    if not domain:
        return None
    if domain not in iocs.get("domains", []):
        return None

    tld = _tld(domain)
    if tld in SUSPICIOUS_TLDS:
        return {
            "rule":     "phishing",
            "severity": "HIGH",
            "reason":   f"Suspicious domain '{domain}' uses phishing-associated TLD '{tld}'",
        }
    return None


# ── Rule 2: C2 Beaconing ──────────────────────────────────────────────────────

def beaconing_rule(flow: dict, iocs: dict, all_flows: list) -> dict | None:
    """
    Flag src→dst pairs that appear in more than BEACONING_THRESHOLD flows,
    indicating periodic check-in / C2 beaconing behaviour.
    """
    src, dst = flow["src_ip"], flow["dst_ip"]
    count = sum(
        1 for f in all_flows
        if f["src_ip"] == src and f["dst_ip"] == dst
    )
    if count > BEACONING_THRESHOLD:
        return {
            "rule":     "c2_beaconing",
            "severity": "HIGH",
            "reason":   (
                f"Repeated communications {src} → {dst} "
                f"across {count} separate flows (threshold: {BEACONING_THRESHOLD})"
            ),
        }
    return None


# ── Rule 3: DNS Tunneling ─────────────────────────────────────────────────────

def dns_tunneling_rule(flow: dict, iocs: dict, all_flows: list) -> dict | None:
    """
    Flag DNS queries with unusually long labels or high character entropy —
    hallmarks of data exfiltration via DNS.
    """
    domain = _domain_from_flow(flow)
    if not domain:
        return None

    # Check the longest label (subdomain), not the full FQDN, to avoid
    # penalising legitimate long apex domains like 'verylong-company-name.com'
    labels  = domain.split(".")
    longest = max(labels, key=len)

    if len(longest) > DNS_TUNNELING_LENGTH:
        return {
            "rule":     "dns_tunneling",
            "severity": "HIGH",
            "reason":   (
                f"Unusually long DNS label ({len(longest)} chars) "
                f"in '{domain}' — possible exfiltration"
            ),
        }

    entropy = _shannon_entropy(longest)
    if entropy > DNS_TUNNELING_ENTROPY:
        return {
            "rule":     "dns_tunneling",
            "severity": "HIGH",
            "reason":   (
                f"High-entropy DNS label (H={entropy:.2f} bits) "
                f"in '{domain}' — possible exfiltration"
            ),
        }

    return None


# ── Rule 4: Suspicious TLD ────────────────────────────────────────────────────

def suspicious_tld_rule(flow: dict, iocs: dict, all_flows: list) -> dict | None:
    """
    Flag any DNS query whose TLD appears in the SUSPICIOUS_TLDS blocklist.
    Lower severity than phishing_rule — acts as a broad trip-wire.
    """
    domain = _domain_from_flow(flow)
    if not domain:
        return None

    tld = _tld(domain)
    if tld in SUSPICIOUS_TLDS:
        return {
            "rule":     "suspicious_tld",
            "severity": "MEDIUM",
            "reason":   f"Domain '{domain}' uses suspicious TLD '{tld}'",
        }
    return None


# ── Rule 5: Malicious IP ──────────────────────────────────────────────────────

def malicious_ip_rule(flow: dict, iocs: dict, all_flows: list) -> dict | None:
    """
    Flag any flow whose destination IP appears in KNOWN_BAD_IPS.
    Populate KNOWN_BAD_IPS at the top of this file with IPs from your PCAP.
    """
    dst = flow["dst_ip"]
    if dst in KNOWN_BAD_IPS:
        return {
            "rule":     "malicious_ip",
            "severity": "HIGH",
            "reason":   f"Destination IP '{dst}' is on the known-malicious blocklist",
        }
    return None


# ── Rule 6: HTTP Anomaly ──────────────────────────────────────────────────────

def http_anomaly_rule(flow: dict, iocs: dict, all_flows: list) -> dict | None:
    """
    Flag HTTP flows with:
      - Missing User-Agent header (common in malware HTTP stagers)
      - URL path containing a suspicious token (.exe, /update, etc.)
    """
    first_line = _http_first_line(flow)
    if not first_line:
        return None

    parts = first_line.split()
    path  = parts[1] if len(parts) >= 2 else "/"

    # Check suspicious path tokens
    path_lower = path.lower()
    for token in SUSPICIOUS_PATH_TOKENS:
        if token in path_lower:
            return {
                "rule":     "http_anomaly",
                "severity": "MEDIUM",
                "reason":   f"HTTP request to suspicious path '{path}' (matched '{token}')",
            }

    # Check for missing User-Agent
    headers = _full_http_headers(flow) or ""
    if "user-agent:" not in headers.lower():
        return {
            "rule":     "http_anomaly",
            "severity": "MEDIUM",
            "reason":   f"HTTP request to '{path}' has no User-Agent header (malware indicator)",
        }

    return None


# ── Rule 7: Multi-Pillar Attack ───────────────────────────────────────────────

def multi_pillar_rule(flow: dict, iocs: dict, all_flows: list) -> dict | None:
    """
    Escalate to CRITICAL when a flow triggers BOTH a domain-based signal
    (phishing or suspicious TLD) AND the destination IP is in the blocklist.
    Combining two independent signals drastically reduces false positives.
    """
    dst = flow["dst_ip"]
    if dst not in KNOWN_BAD_IPS:
        return None

    domain = _domain_from_flow(flow)
    tld    = _tld(domain) if domain else ""

    domain_suspicious = bool(
        domain and (
            tld in SUSPICIOUS_TLDS
            or (domain in iocs.get("domains", []) and tld in SUSPICIOUS_TLDS)
        )
    )

    if domain_suspicious:
        return {
            "rule":     "multi_pillar_attack",
            "severity": "CRITICAL",
            "reason":   (
                f"Flow to known-malicious IP '{dst}' also queries "
                f"suspicious domain '{domain}' — high-confidence threat"
            ),
        }
    return None


# ── Rule 8: DoS Scanning (NEW) ────────────────────────────────────────────────

def dos_scanning_rule(flow: dict, iocs: dict, all_flows: list) -> dict | None:
    """
    Detect potential DoS scanning patterns:
    - Single source contacting many unique destinations (port scan / host scan)
    - Indicates reconnaissance phase before attack
    """
    # Get all flows from same source IP
    same_src = [f for f in all_flows if f['src_ip'] == flow['src_ip']]
    
    # Many destinations from one source (scanning)
    unique_dsts = set(f['dst_ip'] for f in same_src)
    if len(unique_dsts) > DOS_SCAN_THRESHOLD:
        return {
            "rule": "dos_scanning",
            "severity": "MEDIUM",
            "reason": f"Source {flow['src_ip']} contacted {len(unique_dsts)} unique destinations (possible port/host scan)"
        }
    
    return None


# ── Rule 9: DDoS Flood (NEW) ──────────────────────────────────────────────────

def ddos_flood_rule(flow: dict, iocs: dict, all_flows: list) -> dict | None:
    """
    Detect potential DDoS patterns:
    - Many sources targeting a single destination (flood attack)
    - High packet rate from multiple sources to one destination
    """
    # Get all flows to same destination
    same_dst = [f for f in all_flows if f['dst_ip'] == flow['dst_ip']]
    
    # Many sources to same destination (DDoS)
    unique_srcs = set(f['src_ip'] for f in same_dst)
    if len(unique_srcs) > DDOS_FLOOD_THRESHOLD:
        # Check if packet rate is also high
        total_packets = sum(f.get('packet_count', 0) for f in same_dst)
        avg_packet_rate = total_packets / max(1, len(same_dst))
        
        severity = "HIGH" if avg_packet_rate > DOS_PACKET_RATE_THRESHOLD else "MEDIUM"
        
        return {
            "rule": "ddos_flood",
            "severity": severity,
            "reason": (
                f"Destination {flow['dst_ip']} received traffic from {len(unique_srcs)} unique sources"
                f" with avg packet rate {avg_packet_rate:.1f}/s (possible DDoS)"
            ) if avg_packet_rate > DOS_PACKET_RATE_THRESHOLD else (
                f"Destination {flow['dst_ip']} received traffic from {len(unique_srcs)} unique sources (possible DDoS)"
            )
        }
    
    return None


# ── Rule 10: High Packet Rate Anomaly (NEW) ───────────────────────────────────

def high_packet_rate_rule(flow: dict, iocs: dict, all_flows: list) -> dict | None:
    """
    Detect flows with abnormally high packet rates.
    Indicates potential flooding, DoS tools, or data exfiltration.
    """
    rate = _calculate_packet_rate(flow)
    
    if rate > DOS_PACKET_RATE_THRESHOLD:
        return {
            "rule": "high_packet_rate",
            "severity": "MEDIUM",
            "reason": (
                f"Flow {flow['src_ip']} → {flow['dst_ip']} has high packet rate: "
                f"{rate:.1f} packets/sec (threshold: {DOS_PACKET_RATE_THRESHOLD})"
            )
        }
    
    return None


# ── Rule 11: Port Scan Detection (NEW) ────────────────────────────────────────

def port_scan_rule(flow: dict, iocs: dict, all_flows: list) -> dict | None:
    """
    Detect port scanning behavior:
    - Single source contacting many different ports on same destination
    """
    # Get all flows from same source to same destination
    same_pair = [
        f for f in all_flows 
        if f['src_ip'] == flow['src_ip'] and f['dst_ip'] == flow['dst_ip']
    ]
    
    # Count unique destination ports
    unique_ports = set()
    for f in same_pair:
        if f.get('dst_port'):
            unique_ports.add(f['dst_port'])
    
    # Port scan threshold (typical port scanners hit many ports)
    if len(unique_ports) > 20:
        return {
            "rule": "port_scan",
            "severity": "MEDIUM",
            "reason": (
                f"Source {flow['src_ip']} contacted {len(unique_ports)} different ports "
                f"on destination {flow['dst_ip']} (possible port scan)"
            )
        }
    
    return None


# ── Rule registry (ordered: most severe first) ────────────────────────────────

ALL_RULES = [
    multi_pillar_rule,    # CRITICAL — check first; most authoritative
    phishing_rule,        # HIGH
    beaconing_rule,       # HIGH
    dns_tunneling_rule,   # HIGH
    malicious_ip_rule,    # HIGH
    ddos_flood_rule,      # HIGH (when severe)
    dos_scanning_rule,    # MEDIUM
    http_anomaly_rule,    # MEDIUM
    suspicious_tld_rule,  # MEDIUM — broadest
    high_packet_rate_rule, # MEDIUM
    port_scan_rule,       # MEDIUM
]
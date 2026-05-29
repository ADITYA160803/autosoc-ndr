#!/usr/bin/env python3
"""
Step 3: IOC Extractor
Extracts Indicators of Compromise from a list of aggregated flows.

Produces three IOC categories:
  - ips     : unique src/dst IPs seen across all flows
  - domains : unique domains queried via DNS (UDP/53)
  - urls    : unique URL paths from HTTP requests (TCP/80)

Usage (standalone test):
    python extractor.py <path/to/file.pcap>
"""

import sys
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw


# ── Per-packet extractors ────────────────────────────────────────────────────

def _extract_dns_domain(packet) -> str | None:
    """
    Return the queried domain from a DNS query packet, or None.

    Checks:
      - UDP with dport 53  (outbound query)
      - DNS layer present with at least one question record (DNSQR)
    """
    if not (packet.haslayer(UDP) and packet[UDP].dport == 53):
        return None
    if not (packet.haslayer(DNS) and packet.haslayer(DNSQR)):
        return None
    try:
        raw_name = packet[DNSQR].qname          # bytes, e.g. b'example.com.'
        return raw_name.decode(errors="replace").rstrip(".")
    except Exception:
        return None


def _extract_http_url(packet) -> str | None:
    """
    Return the URL path from an HTTP request packet, or None.

    Looks for TCP dport 80 with a Raw payload whose first line matches a
    recognised HTTP method.  Extracts the path token (second field).

    Example: b'GET /login HTTP/1.1\\r\\n...' → '/login'
    """
    if not (packet.haslayer(TCP) and packet[TCP].dport == 80):
        return None
    if not packet.haslayer(Raw):
        return None

    HTTP_METHODS = (
        "GET", "POST", "PUT", "DELETE",
        "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
    )

    try:
        first_line = packet[Raw].load.decode(errors="replace").split("\r\n")[0]
        parts      = first_line.split()          # ['GET', '/path', 'HTTP/1.1']
        if len(parts) >= 2 and parts[0] in HTTP_METHODS:
            return parts[1]                      # the URL path token
    except Exception:
        pass

    return None


# ── Flow-level traversal ─────────────────────────────────────────────────────

def _is_dns_flow(flow: dict) -> bool:
    """True when this flow carries DNS traffic (UDP, dst-port 53)."""
    return flow["protocol"] == "UDP" and flow["dst_port"] == 53


def _is_http_flow(flow: dict) -> bool:
    """True when this flow carries plain HTTP traffic (TCP, dst-port 80)."""
    return flow["protocol"] == "TCP" and flow["dst_port"] == 80


# ── Main extraction function ─────────────────────────────────────────────────

def extract_iocs_from_flows(flows: list[dict]) -> dict:
    """
    Walk every flow and return a dict of unique IOCs.

    Parameters
    ----------
    flows : list of flow dicts produced by aggregate_flows()

    Returns
    -------
    {
        "ips":     sorted list of unique IP strings,
        "domains": sorted list of unique domain strings,
        "urls":    sorted list of unique URL path strings,
    }
    """
    ips:     set[str] = set()
    domains: set[str] = set()
    urls:    set[str] = set()

    for flow in flows:
        # ── IPs: always collect from flow metadata (no packet scan needed) ──
        ips.add(flow["src_ip"])
        ips.add(flow["dst_ip"])

        # ── DNS domains: only scan packets in DNS flows ──────────────────────
        if _is_dns_flow(flow):
            for pkt in flow["packets"]:
                domain = _extract_dns_domain(pkt)
                if domain:
                    domains.add(domain)

        # ── HTTP URLs: only scan packets in HTTP flows ───────────────────────
        elif _is_http_flow(flow):
            for pkt in flow["packets"]:
                url = _extract_http_url(pkt)
                if url:
                    urls.add(url)

    return {
        "ips":     sorted(ips),
        "domains": sorted(domains),
        "urls":    sorted(urls),
    }


# ── Display ───────────────────────────────────────────────────────────────────

def print_iocs_summary(iocs: dict, sample_size: int = 5) -> None:
    """
    Print a compact IOC summary with counts and short samples.

    Example output:
        === IOC SUMMARY ===
        IPs      : 12 unique
        Domains  :  3 unique
        URLs     :  5 unique

        Sample domains : ['whooptm.cyou', 'example.com', ...]
        Sample URLs    : ['/login', '/api/collect', ...]
    """
    ips     = iocs.get("ips",     [])
    domains = iocs.get("domains", [])
    urls    = iocs.get("urls",    [])

    print("\n=== IOC SUMMARY ===")
    print(f"  IPs      : {len(ips):>4} unique")
    print(f"  Domains  : {len(domains):>4} unique")
    print(f"  URLs     : {len(urls):>4} unique")

    if domains:
        sample = domains[:sample_size]
        suffix = ", …" if len(domains) > sample_size else ""
        print(f"\n  Sample domains : {sample}{suffix}")

    if urls:
        sample = urls[:sample_size]
        suffix = ", …" if len(urls) > sample_size else ""
        print(f"  Sample URLs    : {sample}{suffix}")

    if not domains and not urls:
        print("\n  (No DNS or HTTP IOCs found in these flows.)")

    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f"Usage: python {sys.argv[0]} <pcap_file>")

    filepath = sys.argv[1]

    # ── Inline import avoids a hard coupling to aggregator.py's file path ──
    try:
        from pcap.aggregator import aggregate_flows, print_flows_summary
    except ImportError:
        sys.exit(
            "Error: could not import aggregator.py.\n"
            "Make sure aggregator.py is in the same directory."
        )

    print(f"Loading: {filepath}")
    try:
        packets = rdpcap(filepath)
    except FileNotFoundError:
        sys.exit(f"Error: file not found — {filepath}")
    except Exception as exc:
        sys.exit(f"Error reading PCAP: {exc}")

    print(f"Packets read: {len(packets)}")

    flows = aggregate_flows(packets)
    print_flows_summary(flows, limit=5)

    iocs = extract_iocs_from_flows(flows)
    print_iocs_summary(iocs)

    # Verbose dump for debugging (first 20 of each category)
    print("── Full IP list (first 20) ──────────────────────────────────────")
    for ip in iocs["ips"][:20]:
        print(f"  {ip}")
    if len(iocs["ips"]) > 20:
        print(f"  … and {len(iocs['ips']) - 20} more")

    if iocs["domains"]:
        print("\n── All domains ──────────────────────────────────────────────────")
        for d in iocs["domains"]:
            print(f"  {d}")

    if iocs["urls"]:
        print("\n── All URLs ─────────────────────────────────────────────────────")
        for u in iocs["urls"]:
            print(f"  {u}")


if __name__ == "__main__":
    main()
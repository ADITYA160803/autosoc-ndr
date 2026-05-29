# Read PCAP (Scapy)
#!/usr/bin/env python3
"""
Step 1: PCAP Parser — packet summary printer.
Usage: python pcap_parser.py <path/to/file.pcap>
"""

import sys
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw


MAX_PACKETS = 20


def get_protocol_name(packet) -> str:
    """Return a human-readable protocol label for an IP packet."""
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    # Fallback: look up the IP protocol number
    proto_map = {1: "ICMP", 2: "IGMP", 47: "GRE", 50: "ESP", 89: "OSPF"}
    return proto_map.get(packet[IP].proto, f"IP/{packet[IP].proto}")


def parse_dns_query(packet) -> str | None:
    """Return the queried domain name if this is a DNS query packet."""
    if not (packet.haslayer(UDP) and packet[UDP].dport == 53):
        return None
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        return packet[DNSQR].qname.decode(errors="replace").rstrip(".")
    return None


def parse_http_request(packet) -> str | None:
    """Return the first line of an HTTP request if present."""
    if not (packet.haslayer(TCP) and packet[TCP].dport == 80):
        return None
    if not packet.haslayer(Raw):
        return None
    try:
        payload = packet[Raw].load.decode(errors="replace")
        first_line = payload.split("\r\n")[0].strip()
        # Sanity-check: real HTTP request lines start with a known method
        http_methods = ("GET", "POST", "PUT", "DELETE", "HEAD",
                        "OPTIONS", "PATCH", "CONNECT", "TRACE")
        if first_line.startswith(http_methods):
            return first_line
    except Exception:
        pass
    return None


def summarise_packet(index: int, packet) -> None:
    """Print a one-or-two-line summary for a single packet."""
    if not packet.haslayer(IP):
        return  # skip non-IP packets silently

    ip      = packet[IP]
    proto   = get_protocol_name(packet)
    header  = f"[{index:>3}] {ip.src} → {ip.dst} ({proto})"

    # Port info for TCP / UDP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        header += f"  |  port {tcp.sport} → {tcp.dport}"
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        header += f"  |  port {udp.sport} → {udp.dport}"

    print(header)

    # Layer-7 details (indented for readability)
    dns_query    = parse_dns_query(packet)
    http_request = parse_http_request(packet)

    if dns_query:
        print(f"       DNS query  : {dns_query}")
    if http_request:
        print(f"       HTTP       : {http_request}")


def parse_pcap(filepath: str) -> None:
    """Read a PCAP file and print summaries for the first MAX_PACKETS IP packets."""
    print(f"Reading: {filepath}\n{'─' * 60}")

    try:
        packets = rdpcap(filepath)
    except FileNotFoundError:
        sys.exit(f"Error: file not found — {filepath}")
    except Exception as exc:
        sys.exit(f"Error reading PCAP: {exc}")

    ip_count = 0

    for packet in packets:
        if not packet.haslayer(IP):
            continue                   # skip non-IP (ARP, etc.)
        ip_count += 1
        summarise_packet(ip_count, packet)
        if ip_count >= MAX_PACKETS:
            break

    print(f"{'─' * 60}")
    print(f"Showed {ip_count} IP packet(s) "
          f"(total in file: {len(packets)}).")


def read_all_packets(filepath: str):
    """Utility function to read all packets from a pcap file."""
    return rdpcap(filepath)

def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f"Usage: python {sys.argv[0]} <pcap_file>")
    parse_pcap(sys.argv[1])


if __name__ == "__main__":
    main()
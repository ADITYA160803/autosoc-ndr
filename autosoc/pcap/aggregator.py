#!/usr/bin/env python3
"""
Step 2: Flow Aggregator with BATCH PROCESSING
Groups IP packets into flows using a 5-tuple key.
BATCH_SIZE = 500 packets per batch for faster processing
"""

import sys
from scapy.all import IP, TCP, UDP
from collections import defaultdict

BATCH_SIZE = 500  # Process 500 packets at a time
FLOW_TIMEOUT = 60.0


def _extract_ports(packet) -> tuple[int, int]:
    if packet.haslayer(TCP):
        return packet[TCP].sport, packet[TCP].dport
    if packet.haslayer(UDP):
        return packet[UDP].sport, packet[UDP].dport
    return 0, 0


def _protocol_name(proto_num: int) -> str:
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, f"IP/{proto_num}")


def process_batch(batch: list, active_flows: dict, completed_flows: list, flow_id_counter: int) -> int:
    """Process a batch of packets and update flows"""
    for packet in batch:
        if not packet.haslayer(IP):
            continue

        ip = packet[IP]
        src_port, dst_port = _extract_ports(packet)
        key = (ip.src, ip.dst, src_port, dst_port, ip.proto)
        pkt_time = float(packet.time)

        if key not in active_flows:
            flow_id_counter += 1
            active_flows[key] = {
                "flow_id": flow_id_counter,
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": _protocol_name(ip.proto),
                "packet_count": 1,
                "start_time": pkt_time,
                "end_time": pkt_time,
                "packets": [packet],
            }
        else:
            existing = active_flows[key]
            gap = pkt_time - existing["end_time"]
            if gap > FLOW_TIMEOUT:
                # RETIRE OLD FLOW (Fixing bug in provided snippet)
                completed_flows.append(existing)
                
                flow_id_counter += 1
                active_flows[key] = {
                    "flow_id": flow_id_counter,
                    "src_ip": ip.src,
                    "dst_ip": ip.dst,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": _protocol_name(ip.proto),
                    "packet_count": 1,
                    "start_time": pkt_time,
                    "end_time": pkt_time,
                    "packets": [packet],
                }
            else:
                existing["packet_count"] += 1
                existing["end_time"] = pkt_time
                existing["packets"].append(packet)

    return flow_id_counter


def aggregate_flows(packets, timeout: float = FLOW_TIMEOUT) -> list[dict]:
    """Aggregate flows using BATCH PROCESSING for better performance"""
    active_flows = {}
    completed_flows = []
    flow_id_counter = 0
    
    # Process in batches
    total_packets = len(packets)
    for i in range(0, total_packets, BATCH_SIZE):
        batch = packets[i:i+BATCH_SIZE]
        flow_id_counter = process_batch(batch, active_flows, completed_flows, flow_id_counter)
        
        # Print progress every 10 batches
        if i % (BATCH_SIZE * 10) == 0 and i > 0:
            print(f"  Processed {i}/{total_packets} packets...")
    
    # Combine active and completed
    all_flows = completed_flows + list(active_flows.values())
    
    # Optional: sort by start time like original
    all_flows.sort(key=lambda f: f["start_time"])
    
    return all_flows

def print_flows_summary(flows: list[dict], limit: int = 10) -> None:
    """Print a one-line summary per flow (Restored from previous version)"""
    total = len(flows)
    display = flows[:limit]

    print(f"\n{'─' * 68}")
    print(f"  Flows found: {total}  —  showing first {min(limit, total)}")
    print(f"{'─' * 68}")

    for f in display:
        src  = f"{f['src_ip']}:{f['src_port']}"
        dst  = f"{f['dst_ip']}:{f['dst_port']}"
        dur  = f["end_time"] - f["start_time"]
        print(
            f"  Flow {f['flow_id']:>3}: "
            f"{(src):<25} → {(dst):<25} "
            f"({f['protocol']:<4}) | "
            f"{f['packet_count']:>5} pkts | "
            f"{dur:>7.2f}s"
        )

    if total > limit:
        print(f"  … and {total - limit} more flow(s) not shown.")

    print(f"{'─' * 68}\n")

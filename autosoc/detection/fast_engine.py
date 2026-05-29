#!/usr/bin/env python3
"""
Fast Detection Engine - Optimized for large PCAPs
Skips deep parsing, uses pre-aggregation
"""

import os
import json
import time
from collections import defaultdict
from datetime import datetime

# Fast mode constants
FAST_MODE = os.environ.get('FAST_MODE', 'false').lower() == 'true'
BATCH_SIZE = 5000  # Process 5000 packets at a time


def detect_threats_fast(packets) -> dict:
    """
    Fast threat detection using pre-aggregation
    - No flow reconstruction
    - No deep packet inspection
    - Direct statistical analysis
    """
    start_time = time.time()
    
    # Statistics
    ip_counts = defaultdict(int)
    port_counts = defaultdict(int)
    protocol_counts = defaultdict(int)
    src_dst_pairs = defaultdict(int)
    
    print("  🔍 Fast scanning packets...")
    
    for i, pkt in enumerate(packets):
        if not pkt.haslayer('IP'):
            continue
        
        ip = pkt['IP']
        src = ip.src
        dst = ip.dst
        
        # Count IPs
        ip_counts[dst] += 1
        
        # Count src-dst pairs
        src_dst_pairs[f"{src}->{dst}"] += 1
        
        # Count protocols
        proto = ip.proto
        protocol_counts[proto] += 1
        
        # Progress indicator
        if i > 0 and i % BATCH_SIZE == 0:
            print(f"    Scanned {i} packets...")
    
    # Detect DDoS
    ddos_alerts = []
    for dst, count in ip_counts.items():
        if count > 100:
            severity = "CRITICAL" if count > 5000 else "HIGH" if count > 1000 else "MEDIUM"
            ddos_alerts.append({
                'rule': 'ddos_flood',
                'severity': severity,
                'dst_ip': dst,
                'packet_count': count,
                'reason': f"DDoS attack: {count} packets to {dst}",
                'risk_score': 90 if count > 5000 else 70 if count > 1000 else 50
            })
    
    # Detect scanning
    scan_alerts = []
    for pair, count in src_dst_pairs.items():
        if count > 50:
            src = pair.split('->')[0]
            scan_alerts.append({
                'rule': 'port_scan',
                'severity': 'MEDIUM',
                'src_ip': src,
                'packet_count': count,
                'reason': f"Port scan detected: {count} packets from {src}",
                'risk_score': 50
            })
    
    elapsed = time.time() - start_time
    print(f"  ✅ Fast detection completed in {elapsed:.2f}s")
    
    return {
        'alerts': ddos_alerts + scan_alerts,
        'stats': {
            'total_ips': len(ip_counts),
            'total_pairs': len(src_dst_pairs),
            'protocols': dict(protocol_counts)
        }
    }


def run_fast_analysis(filepath: str) -> dict:
    """Main entry point for fast analysis"""
    from scapy.all import rdpcap
    
    print(f"\n{'='*60}")
    print(f"  🚀 FAST MODE ENABLED")
    print(f"  Analyzing: {filepath}")
    print(f"{'='*60}\n")
    
    # Read packets (fast, no deep parsing yet)
    packets = rdpcap(filepath)
    total_packets = len(packets)
    print(f"  📦 Total packets: {total_packets}")
    
    # Convert to dict for faster access
    packet_dicts = []
    for pkt in packets:
        if pkt.haslayer('IP'):
            packet_dicts.append({
                'IP': pkt['IP'],
                'time': pkt.time
            })
    
    # Run fast detection
    results = detect_threats_fast(packet_dicts)
    
    # Save results
    os.makedirs('output', exist_ok=True)
    with open('output/alerts.json', 'w') as f:
        json.dump(results['alerts'], f, indent=2)
    
    print(f"\n{'='*60}")
    print(f"  RESULTS")
    print(f"{'='*60}")
    print(f"  Alerts detected: {len(results['alerts'])}")
    print(f"  Total IPs: {results['stats']['total_ips']}")
    print(f"  Total pairs: {results['stats']['total_pairs']}")
    print(f"{'='*60}\n")
    
    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python fast_engine.py <pcap_file>")
        sys.exit(1)
    
    # Set fast mode
    os.environ['FAST_MODE'] = 'true'
    run_fast_analysis(sys.argv[1])

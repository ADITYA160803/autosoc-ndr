#!/usr/bin/env python3
"""
Optimized PCAP Parser with:
- Batch processing
- Multiprocessing support
- Minimal memory footprint
- Fast DDoS detection
"""

import os
import time
import sys
from collections import defaultdict
from multiprocessing import Pool, cpu_count
from functools import partial

# Add project root to path for config import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from scapy.all import rdpcap, IP, TCP, UDP
except ImportError:
    print("Error: scapy not installed. Run: pip install scapy")
    exit(1)

from config import BATCH_SIZE, PARALLEL_WORKERS


def process_packet_batch(batch):
    """Process a batch of packets - extract only essential data"""
    results = {
        'ip_counts': defaultdict(int),
        'flow_keys': set(),
        'packet_sizes': [],
        'packet_count': 0,
        'protocols': defaultdict(int),
        'src_dst_pairs': defaultdict(int)
    }
    
    for pkt in batch:
        if not pkt.haslayer(IP):
            continue
        
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto
        
        # Count packets per destination (DDoS detection)
        results['ip_counts'][dst] += 1
        
        # Count src-dst pairs (scan detection)
        pair_key = f"{src}|{dst}"
        results['src_dst_pairs'][pair_key] += 1
        
        # Count protocols
        results['protocols'][proto] += 1
        
        # Extract ports for flow key
        src_port = 0
        dst_port = 0
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        
        # Store flow key
        flow_key = (src, dst, src_port, dst_port, proto)
        results['flow_keys'].add(flow_key)
        
        # Track packet size
        results['packet_sizes'].append(len(pkt))
        results['packet_count'] += 1
    
    return results


def merge_batch_results(results_list):
    """Merge results from multiple batches/processes"""
    merged = {
        'ip_counts': defaultdict(int),
        'flow_keys': set(),
        'packet_sizes': [],
        'packet_count': 0,
        'protocols': defaultdict(int),
        'src_dst_pairs': defaultdict(int)
    }
    
    for r in results_list:
        for ip, count in r['ip_counts'].items():
            merged['ip_counts'][ip] += count
        
        for key in r['flow_keys']:
            merged['flow_keys'].add(key)
        
        merged['packet_sizes'].extend(r['packet_sizes'])
        merged['packet_count'] += r['packet_count']
        
        for proto, count in r['protocols'].items():
            merged['protocols'][proto] += count
        
        for pair, count in r['src_dst_pairs'].items():
            merged['src_dst_pairs'][pair] += count
    
    return merged


def parse_pcap_optimized(filepath, use_multiprocessing=True):
    """
    Parse PCAP with optimizations
    
    Returns:
        dict with aggregated statistics
    """
    print(f"\n  📁 Reading PCAP: {filepath}")
    start_time = time.time()
    
    # Read all packets
    packets = rdpcap(filepath)
    total_packets = len(packets)
    print(f"  📦 Total packets: {total_packets}")
    
    # Create batches
    batches = []
    for i in range(0, total_packets, BATCH_SIZE):
        batch = packets[i:i+BATCH_SIZE]
        batches.append(batch)
    
    print(f"  📋 Created {len(batches)} batches (batch size: {BATCH_SIZE})")
    
    if use_multiprocessing and len(batches) > 1:
        # Use multiprocessing for large files
        workers = PARALLEL_WORKERS or max(1, cpu_count() - 1)
        print(f"  🚀 Using {workers} parallel workers")
        
        with Pool(processes=workers) as pool:
            results = pool.map(process_packet_batch, batches)
    else:
        # Process sequentially
        print(f"  🔄 Processing sequentially")
        results = [process_packet_batch(batch) for batch in batches]
    
    # Merge results
    merged = merge_batch_results(results_list=results)
    
    elapsed = time.time() - start_time
    print(f"  ✅ Parsing completed in {elapsed:.2f}s")
    
    return merged


def detect_threats_from_stats(stats, config=None):
    """
    Detect threats directly from aggregated statistics
    No need for per-packet analysis
    """
    alerts = []
    
    # 1. DDoS Detection (many packets to single destination)
    from config import DDOS_CRITICAL_THRESHOLD, DDOS_HIGH_THRESHOLD, DDOS_MEDIUM_THRESHOLD
    
    for dst_ip, count in stats['ip_counts'].items():
        if count > DDOS_MEDIUM_THRESHOLD:
            if count > DDOS_CRITICAL_THRESHOLD:
                severity = "CRITICAL"
                risk_score = 95
            elif count > DDOS_HIGH_THRESHOLD:
                severity = "HIGH"
                risk_score = 80
            else:
                severity = "MEDIUM"
                risk_score = 60
            
            alerts.append({
                "rule": "ddos_flood",
                "severity": severity,
                "dst_ip": dst_ip,
                "packet_count": count,
                "risk_score": risk_score,
                "reason": f"DDoS attack detected: {count} packets to {dst_ip}"
            })
    
    # 2. Port Scan Detection (many src-dst pairs from single source)
    from collections import defaultdict
    src_activity = defaultdict(int)
    
    for pair, count in stats['src_dst_pairs'].items():
        src = pair.split('|')[0]
        src_activity[src] += 1
    
    for src, targets in src_activity.items():
        if targets > 50:
            alerts.append({
                "rule": "port_scan",
                "severity": "MEDIUM",
                "src_ip": src,
                "unique_targets": targets,
                "risk_score": 50,
                "reason": f"Port scan detected: {src} contacted {targets} unique destinations"
            })
    
    return alerts


def run_optimized_analysis(filepath):
    """Main entry point for optimized analysis"""
    from config import ENABLE_CACHE
    from storage.cache_manager import get_cached_result, cache_result
    
    # Check cache
    if ENABLE_CACHE:
        cached = get_cached_result(filepath)
        if cached:
            return cached
    
    # Parse with optimizations
    stats = parse_pcap_optimized(filepath)
    
    # Detect threats from stats
    alerts = detect_threats_from_stats(stats)
    
    # Prepare output
    output = {
        'alerts': alerts,
        'stats': {
            'total_packets': stats['packet_count'],
            'unique_flows': len(stats['flow_keys']),
            'unique_destinations': len(stats['ip_counts']),
            'protocols': dict(stats['protocols']),
            'avg_packet_size': sum(stats['packet_sizes']) / len(stats['packet_sizes']) if stats['packet_sizes'] else 0
        }
    }
    
    # Cache results
    if ENABLE_CACHE:
        cache_result(filepath, output)
    
    return output


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python optimized_parser.py <pcap_file>")
        sys.exit(1)
    
    result = run_optimized_analysis(sys.argv[1])
    
    print(f"\n{'='*60}")
    print("  RESULTS")
    print(f"{'='*60}")
    print(f"  Alerts: {len(result['alerts'])}")
    for alert in result['alerts'][:5]:
        print(f"    [{alert['severity']}] {alert['rule']}: {alert.get('reason', '')[:80]}")
    print(f"{'='*60}")

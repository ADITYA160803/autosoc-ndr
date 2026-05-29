#!/usr/bin/env python3
"""
Hybrid Detection Engine - Automatically selects optimal mode
"""

import os
import sys
import time
import json
from scapy.all import rdpcap

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import FAST_MODE, ENRICHMENT_SKIP_THRESHOLD
from storage.cache_manager import get_cached_result, cache_result, cached_analysis
from pcap.optimized_parser import run_optimized_analysis


def get_packet_count_fast(filepath: str) -> int:
    """Get packet count without full parsing"""
    try:
        from scapy.all import rdpcap
        packets = rdpcap(filepath)
        return len(packets)
    except:
        return 0


def should_use_fast_mode(packet_count: int, filepath: str = None) -> bool:
    """Determine if fast mode should be used"""
    if FAST_MODE:
        return True
    
    # Auto-detect based on file size
    if filepath and os.path.exists(filepath):
        file_size_mb = os.path.getsize(filepath) / 1024 / 1024
        if file_size_mb > 10:  # Files > 10MB
            return True
    
    if packet_count > 5000:
        return True
    
    return False


@cached_analysis
def run_hybrid_analysis(filepath: str):
    """
    Run analysis with automatic mode selection
    Results are automatically cached
    """
    print(f"\n{'='*60}")
    print(f"  [+] AutoSOC NDR - Hybrid Analysis")
    print(f"{'='*60}\n")
    
    # Get packet count
    packet_count = get_packet_count_fast(filepath)
    file_size_mb = os.path.getsize(filepath) / 1024 / 1024
    
    print(f"  Summary File Info:")
    print(f"     Size: {file_size_mb:.2f} MB")
    print(f"     Packets: {packet_count}")
    
    # Select mode
    use_fast = should_use_fast_mode(packet_count, filepath)
    
    if use_fast:
        print(f"  Mode: FAST / OPTIMIZED")
        print(f"     - Batch processing: ON")
        print(f"     - Multiprocessing: ON")
        print(f"     - Enrichment: SKIPPED (large PCAP)")
        print(f"     - Deep packet inspection: OFF")
        
        start_time = time.time()
        result = run_optimized_analysis(filepath)
        elapsed = time.time() - start_time
        
    else:
        print(f"  Mode: FULL / DEEP")
        print(f"     - Flow reconstruction: ON")
        print(f"     - Enrichment: ON")
        print(f"     - Deep packet inspection: ON")
        
        start_time = time.time()
        from detection.engine import main as run_full_main
        import subprocess
        try:
            subprocess.run(['python', os.path.join(PROJECT_ROOT, 'detection', 'engine.py'), filepath], check=True)
            with open(os.path.join(PROJECT_ROOT, 'output', 'alerts.json'), 'r') as f:
                alerts = json.load(f)
            result = {'alerts': alerts, 'stats': {'total_packets': packet_count}}
        except Exception as e:
            print(f"Error running full analysis: {e}")
            result = {'alerts': [], 'stats': {}}
            
        elapsed = time.time() - start_time
    
    print(f"\n  Analysis completed in {elapsed:.2f}s")
    
    # Print summary
    alerts = result.get('alerts', [])
    print(f"\n{'='*60}")
    print(f"  RESULTS SUMMARY")
    print(f"{'='*60}")
    print(f"  Total alerts: {len(alerts)}")
    
    # Count by severity
    severity_counts = {}
    for alert in alerts:
        sev = alert.get('severity', 'UNKNOWN')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    for sev, count in severity_counts.items():
        print(f"    {sev}: {count}")
    
    print(f"{'='*60}\n")
    
    return result


def main():
    if len(sys.argv) != 2:
        print("Usage: python hybrid_engine.py <pcap_file>")
        print("\nOptions:")
        print("  --clear-cache    Clear cached results")
        print("  --cache-stats    Show cache statistics")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    if filepath == '--clear-cache':
        from storage.cache_manager import clear_cache
        clear_cache()
        return
    
    if filepath == '--cache-stats':
        from storage.cache_manager import get_cache_stats
        stats = get_cache_stats()
        print(f"\nCache Statistics:")
        print(f"  Files: {stats['cache_files']}")
        print(f"  Size: {stats['cache_size_mb']:.2f} MB")
        print(f"  Location: {stats['cache_dir']}")
        return
    
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        sys.exit(1)
    
    run_hybrid_analysis(filepath)


if __name__ == "__main__":
    main()

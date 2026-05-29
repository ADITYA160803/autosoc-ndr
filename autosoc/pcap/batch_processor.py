#!/usr/bin/env python3
"""
Batch Processor - Process PCAP in chunks for memory efficiency
"""

from scapy.all import rdpcap
from collections import defaultdict
import time

BATCH_SIZE = 10000  # Process 10k packets per batch


class BatchProcessor:
    def __init__(self, filepath: str, batch_size: int = BATCH_SIZE):
        self.filepath = filepath
        self.batch_size = batch_size
        self.packets = None
        self.total = 0
        
    def load_packets(self):
        """Load packets from PCAP"""
        self.packets = rdpcap(self.filepath)
        self.total = len(self.packets)
        print(f"  Loaded {self.total} packets")
        return self
    
    def process_batches(self, process_func):
        """
        Process packets in batches
        process_func: function that takes a batch of packets and returns results
        """
        results = []
        start_time = time.time()
        
        for i in range(0, self.total, self.batch_size):
            batch = self.packets[i:i+self.batch_size]
            batch_result = process_func(batch, i)
            results.append(batch_result)
            
            # Progress update
            percent = min(100, int((i + len(batch)) / self.total * 100))
            print(f"    Progress: {percent}% ({i+len(batch)}/{self.total} packets)")
        
        elapsed = time.time() - start_time
        print(f"  Batch processing completed in {elapsed:.2f}s")
        
        return results
    
    def aggregate_results(self, results, aggregate_func):
        """Aggregate batch results"""
        return aggregate_func(results)


def process_ddos_batch(batch, offset):
    """Process a batch for DDoS detection"""
    ip_counts = defaultdict(int)
    
    for pkt in batch:
        if pkt.haslayer('IP'):
            dst = pkt['IP'].dst
            ip_counts[dst] += 1
    
    return {
        'offset': offset,
        'ip_counts': dict(ip_counts),
        'batch_size': len(batch)
    }


def aggregate_ddos_results(results):
    """Combine DDoS results from all batches"""
    total_counts = defaultdict(int)
    
    for r in results:
        for ip, count in r['ip_counts'].items():
            total_counts[ip] += count
    
    # Find DDoS attacks
    alerts = []
    for ip, count in total_counts.items():
        if count > 100:
            severity = "CRITICAL" if count > 5000 else "HIGH" if count > 1000 else "MEDIUM"
            alerts.append({
                'target': ip,
                'packets': count,
                'severity': severity
            })
    
    return alerts


def process_pcap_batched(filepath: str):
    """Main function for batched PCAP processing"""
    processor = BatchProcessor(filepath)
    processor.load_packets()
    
    results = processor.process_batches(process_ddos_batch)
    alerts = processor.aggregate_results(results, aggregate_ddos_results)
    
    return alerts

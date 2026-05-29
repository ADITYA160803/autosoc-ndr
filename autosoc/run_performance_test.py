#!/usr/bin/env python3
"""
Performance Test Script - Compare old vs new
"""

import os
import sys
import time
import subprocess


def run_test(filepath, mode='hybrid'):
    """Run analysis with specified mode and measure time"""
    print(f"\n{'='*60}")
    print(f"  Testing: {os.path.basename(filepath)}")
    print(f"  Mode: {mode.upper()}")
    print(f"{'='*60}")
    
    start = time.time()
    
    project_root = os.path.dirname(os.path.abspath(__file__))
    
    if mode == 'hybrid':
        cmd = ['python', 'detection/hybrid_engine.py', filepath]
    elif mode == 'fast':
        # Clear cache first to ensure measurement is for processing not IO
        cmd = ['python', 'pcap/optimized_parser.py', filepath]
    else:
        cmd = ['python', 'detection/engine.py', filepath]
    
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=project_root)
    elapsed = time.time() - start
    
    print(f"\n  Time: {elapsed:.2f}s")
    
    return elapsed


def main():
    # Make sure we are in the right directory
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)
    
    test_files = [
        'sample_data/ftp3.pcap',
        'sample_data/lumma.pcap',
        'sample_data/amp.TCP.reflection.SYNACK.pcap'
    ]
    
    # Check if files exist
    valid_files = []
    for f in test_files:
        if os.path.exists(f):
            valid_files.append(f)
        else:
            print(f"File not found: {f}")
            
    if not valid_files:
        print("No valid test files found. Check sample_data directory.")
        return

    results = {}
    
    for filepath in valid_files:
        # Test hybrid mode
        time_hybrid = run_test(filepath, 'hybrid')
        results[filepath] = {'hybrid': time_hybrid}
    
    print(f"\n{'='*60}")
    print(f"  PERFORMANCE SUMMARY")
    print(f"{'='*60}")
    
    for filepath, times in results.items():
        print(f"\n  {os.path.basename(filepath)}:")
        print(f"    Hybrid mode: {times['hybrid']:.2f}s")


if __name__ == "__main__":
    main()

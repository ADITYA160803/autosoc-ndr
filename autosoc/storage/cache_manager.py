#!/usr/bin/env python3
"""
Cache Manager - Eliminates reprocessing
"""

import hashlib
import json
import os
import pickle
import sys
from datetime import datetime, timedelta
from functools import wraps

# Add project root to path for config import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import CACHE_TTL, ENABLE_CACHE

CACHE_DIR = 'cache'
os.makedirs(CACHE_DIR, exist_ok=True)


def get_file_hash(filepath: str) -> str:
    """Calculate MD5 hash of file (fast, even for large files)"""
    hasher = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            # Read in chunks to handle large files
            for chunk in iter(lambda: f.read(65536), b''):
                hasher.update(chunk)
    except FileNotFoundError:
        return "none"
    return hasher.hexdigest()


def get_cache_path(filepath: str) -> str:
    """Get cache file path for a given PCAP"""
    file_hash = get_file_hash(filepath)
    return os.path.join(CACHE_DIR, f"{file_hash}.json")


def is_cache_valid(cache_path: str) -> bool:
    """Check if cached result is still valid"""
    if not os.path.exists(cache_path):
        return False
    
    if CACHE_TTL <= 0:
        return True
    
    mod_time = datetime.fromtimestamp(os.path.getmtime(cache_path))
    return datetime.now() - mod_time < timedelta(seconds=CACHE_TTL)


def get_cached_result(filepath: str) -> dict:
    """Retrieve cached analysis result"""
    if not ENABLE_CACHE:
        return None
    
    cache_path = get_cache_path(filepath)
    
    if is_cache_valid(cache_path):
        try:
            with open(cache_path, 'r') as f:
                cached = json.load(f)
                print(f"  [+] Cache HIT! Loading previous result...")
                return cached
        except:
            return None
    
    return None


def cache_result(filepath: str, result: dict):
    """Store analysis result in cache"""
    if not ENABLE_CACHE:
        return
    
    cache_path = get_cache_path(filepath)
    
    try:
        with open(cache_path, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"  [+] Result cached to {cache_path}")
    except Exception as e:
        print(f"Error caching result: {e}")


def cached_analysis(func):
    """Decorator for automatic caching of analysis results"""
    @wraps(func)
    def wrapper(filepath, *args, **kwargs):
        cached = get_cached_result(filepath)
        if cached:
            return cached
        result = func(filepath, *args, **kwargs)
        cache_result(filepath, result)
        return result
    return wrapper


def clear_cache(older_than_hours: int = 24):
    """Clear old cache files"""
    cutoff = datetime.now() - timedelta(hours=older_than_hours)
    deleted = 0
    
    for filename in os.listdir(CACHE_DIR):
        filepath = os.path.join(CACHE_DIR, filename)
        if not filename.endswith('.json'):
            continue
        
        mod_time = datetime.fromtimestamp(os.path.getmtime(filepath))
        if mod_time < cutoff:
            os.remove(filepath)
            deleted += 1
    
    if deleted > 0:
        print(f"  [-] Cleared {deleted} old cache files")
    return deleted


def get_cache_stats() -> dict:
    """Get cache statistics"""
    files = [f for f in os.listdir(CACHE_DIR) if f.endswith('.json')]
    total_size = sum(os.path.getsize(os.path.join(CACHE_DIR, f)) for f in files)
    
    return {
        'cache_files': len(files),
        'cache_size_mb': total_size / 1024 / 1024,
        'cache_dir': CACHE_DIR
    }

import hashlib
import json
import os
from functools import lru_cache

CACHE_DIR = 'cache'
os.makedirs(CACHE_DIR, exist_ok=True)

def get_file_hash(filepath: str) -> str:
    """Get MD5 hash of file for caching"""
    hasher = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                hasher.update(chunk)
    except FileNotFoundError:
        return "none"
    return hasher.hexdigest()

def get_cached_result(filepath: str) -> dict:
    """Return cached result if exists"""
    file_hash = get_file_hash(filepath)
    cache_path = os.path.join(CACHE_DIR, f"{file_hash}.json")
    
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    return None

def cache_result(filepath: str, result: dict):
    """Cache analysis result"""
    file_hash = get_file_hash(filepath)
    cache_path = os.path.join(CACHE_DIR, f"{file_hash}.json")
    try:
        with open(cache_path, 'w') as f:
            json.dump(result, f)
    except Exception as e:
        print(f"Error caching result: {e}")

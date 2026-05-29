# config.py - Performance Configuration

# ============================================
# PERFORMANCE SETTINGS
# ============================================

# Enable fast mode for large PCAPs (>5000 packets)
FAST_MODE = False

# Skip enrichment for PCAPs with more than this many IPs
ENRICHMENT_SKIP_THRESHOLD = 1000

# Batch size for packet processing
BATCH_SIZE = 5000

# Number of parallel workers (None = auto = CPU count - 1)
PARALLEL_WORKERS = None

# Cache TTL in seconds (3600 = 1 hour)
CACHE_TTL = 3600

# Enable caching
ENABLE_CACHE = True

# DDoS detection thresholds
DDOS_CRITICAL_THRESHOLD = 5000
DDOS_HIGH_THRESHOLD = 1000
DDOS_MEDIUM_THRESHOLD = 100

# ============================================
# API KEYS (Use environment variables in production)
# ============================================
ABUSEIPDB_API_KEY = ""
VT_API_KEY = ""

# Set to True to skip real API calls (faster testing)
MOCK_MODE = False

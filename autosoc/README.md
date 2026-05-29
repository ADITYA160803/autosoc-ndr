# 🔍 AutoSOC NDR - Network Detection & Response Platform

AutoSOC NDR is a professional-grade cybersecurity platform designed for deep network traffic analysis. It processes raw PCAP data, extracts intelligence indicators (IPs, Domains, URLs), and utilizes an agent-based architecture to detect, aggregate, and score threats in real-time.

## 🚀 Key Features

- **Pillar-Based Extraction**: Simultaneously extracts IP, Domain, and URL indicators from network flows.
- **Smart Alert Aggregation**: Reduces noise by up to 99.9% by grouping thousands of raw packet-level alerts into meaningful security events.
- **Risk Scoring Agent**: Assigns 0–100 risk scores based on severity, threat intelligence enrichment, and behavioral patterns.
- **Attack Chain Correlation**: Links isolated security events into chronological attack campaigns using connected component analysis.
- **Live SOC Dashboard**: A premium, real-time interface for monitoring analysis progress and visualizing threat data.

## 📊 Test Results

| PCAP | Packets | Raw Alerts | Aggregated | Detection |
|------|---------|------------|------------|-----------|
| FTP Scan | 301 | 81 | 1 scan | ✅ MEDIUM |
| Lumma Stealer | 10,593 | 58 | 2-4 events | ✅ HIGH |
| DDoS Reflection | 8,000 | 7,061 | 1 DDoS | ✅ CRITICAL (100/100) |

## 🛠 Project Structure

- `detection/`: Core detection engine and rule definitions.
- `aggregation/`: Agents for grouping alerts and building attack chains.
- `enrichment/`: Threat intelligence integration (AbuseIPDB, VirusTotal, URLhaus).
- `scoring/`: Risk calculation and explanation generation.
- `timeline/`: Chronological attack narrative reconstruction.
- `web/`: Flask-based dashboard frontend and backend.

## 🚦 Quick Start

### 1. Run Analysis
To analyze a PCAP file via terminal:
```bash
python detection/engine.py sample_data/lumma.pcap
```

### 2. Launch Dashboard
To start the web interface:
```bash
python web/app.py
```
Open your browser to `http://127.0.0.1:5000`.

---
*MSc Cybersecurity Project - 2026*

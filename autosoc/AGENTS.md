# 🧠 Agents Architecture - AutoSOC NDR (PCAP-Based Threat Intelligence Platform)

## 📌 Overview

AutoSOC NDR is a modular, agent-based cybersecurity platform designed to process raw network traffic (PCAP), extract intelligence using the 4 pillars (IP, Domain, URL, File Hash), and perform detection, enrichment, correlation, and risk scoring to generate actionable security insights.

Each component is implemented as an independent **agent**, responsible for a specific stage in the data pipeline.

---

# 🧩 System Flow
PCAP → Packet Agent → Session Agent → Feature Agent → Normalization →
Detection / IOC Matching / Enrichment (parallel) → Correlation → Risk → Dashboard

---

# 🔹 1. Packet Processing Agent

## 🎯 Purpose
Parse raw PCAP files into structured packet-level data.

## 📥 Input
- PCAP file (.pcap) - tested with 10,593 packets
- File upload via web dashboard

## ⚙️ Responsibilities
- Decode packet headers (Ethernet, IP, TCP/UDP)
- Extract raw packet metadata
- Identify protocol types (DNS, HTTP, TLS)
- Filter non-IP packets

## 📤 Output
```json
{
  "src_ip": "10.1.20.101",
  "dst_ip": "8.8.8.8",
  "protocol": "UDP",
  "timestamp": 1768929301.238848
}
```

## 🛠 Tools
- Scapy library
- Python 3.10+

## 📊 Performance
Processes 10,593 packets in ~2-3 seconds

---

# 🔹 2. Session Reconstruction Agent (Flow Aggregator)
## 🎯 Purpose
Reconstruct logical sessions/flows from fragmented packets.

## ⚙️ Responsibilities
Group packets by 5-tuple:
- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol
- Apply 60-second timeout window
- Build session timelines
- Track packet counts and duration

## 📤 Output
```json
{
  "flow_id": 42,
  "src_ip": "10.1.20.101",
  "dst_ip": "45.156.87.83",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "packet_count": 91,
  "start_time": 1768929301.238848,
  "end_time": 1768929361.238848
}
```

## 🔥 Importance
Enables detection of:
- Brute force attacks (multiple failed connections)
- Beaconing behavior (repeated intervals)
- Data exfiltration (high packet rates)

## 📊 Performance
10,593 packets → 407 flows in ~1-2 seconds

---

# 🔹 3. Feature Extraction Agent (4-Pillar Engine)
## 🎯 Purpose
Extract intelligence indicators from sessions using all four pillars.

## 🧱 Extracted Pillars
🌐 **IP Address**
- Source & destination IPs
- 45 unique IPs extracted from Lumma PCAP

🌍 **Domain**
- From DNS queries (UDP port 53)
- TLS SNI extraction
- 24 unique domains extracted

🔗 **URL**
- HTTP request parsing (TCP port 80)
- URI paths extraction
- 8 unique URLs extracted

🧬 **File Hash**
- Extract downloaded files from PCAP (optional)
- Generate MD5, SHA256
- (Limited by HTTPS encryption)

## 📤 Output
```json
{
  "ips": ["10.1.20.101", "45.156.87.83", "104.21.36.177"],
  "domains": ["whooptm.cyou", "accounts.google.com"],
  "urls": ["/api/collect", "/login.php"],
  "hashes": []
}
```

## 🔥 Key Feature
All four pillars are extracted simultaneously and passed downstream as a unified intelligence object.

---

# 🔹 4. Normalization Agent
## 🎯 Purpose
Standardize all extracted data into a unified schema.

## ⚙️ Responsibilities
- Convert data into consistent format
- Add metadata: timestamp, source (pcap/flow), event type
- Deduplicate IOCs

## 📤 Output
```json
{
  "ioc": "whooptm.cyou",
  "type": "domain",
  "source": "dns_query",
  "timestamp": 1768929301.238848,
  "flow_id": 42
}
```

---

# 🔹 5. Detection Agent (IOA-Based)
## 🎯 Purpose
Detect suspicious behavior using rule-based logic.

## ⚙️ Responsibilities
- Apply 11 detection rules
- Identify Indicators of Attack (IOA)
- Generate alerts with severity levels

## 📋 Detection Rules (11 Rules)
| # | Rule | Severity | Detection Logic |
|---|------|----------|-----------------|
| 1 | phishing | HIGH | Suspicious TLD (.cyou, .top, .ru) |
| 2 | c2_beaconing | HIGH | 3+ repeated flows same src→dst |
| 3 | dns_tunneling | HIGH | Domain length >40 or high entropy |
| 4 | suspicious_tld | MEDIUM | Any suspicious TLD |
| 5 | malicious_ip | HIGH | IP in known bad list |
| 6 | http_anomaly | MEDIUM | Missing User-Agent or suspicious path |
| 7 | multi_pillar_attack | CRITICAL | Domain + IP both suspicious |
| 8 | dos_scanning | MEDIUM | 50+ destinations from 1 source |
| 9 | ddos_flood | HIGH | 100+ sources to 1 destination |
| 10 | high_packet_rate | MEDIUM | >500 packets/sec |
| 11 | port_scan | MEDIUM | 20+ ports to same destination |

## 📤 Output
```json
{
  "rule": "phishing",
  "severity": "HIGH",
  "reason": "Suspicious domain 'whooptm.cyou' uses TLD '.cyou'",
  "timestamp": 1768929301.238848,
  "src_ip": "10.1.20.101",
  "dst_ip": "10.1.20.1"
}
```

## 📊 Performance
- 58 alerts generated from Lumma PCAP
- 46 HIGH, 10 MEDIUM, 2 CRITICAL

---

# 🔹 6. IOC Matching Agent
## 🎯 Purpose
Match extracted IOCs against known threat intelligence.

## ⚙️ Responsibilities
Compare IP, domain, URL against:
- Internal blocklist (KNOWN_BAD_IPS)
- External threat feeds (via enrichment)

## 📤 Output
```json
{
  "ioc": "45.156.87.83",
  "match": true,
  "source": "KNOWN_BAD_IPS",
  "confidence": "HIGH"
}
```

---

# 🔹 7. Enrichment Agent (Asynchronous)
## 🎯 Purpose
Enhance IOCs with contextual intelligence.

## ⚙️ Responsibilities
Query external APIs:
- AbuseIPDB - IP reputation (score 0-100)
- VirusTotal - Domain reputation (detection ratio)
- URLhaus - URL threat classification

Fetch:
- Reputation scores
- Country/ISP
- Threat tags
- Malicious verdicts

## ⚡ Design
- LRU caching (@lru_cache(maxsize=512))
- No duplicate API calls per session
- Graceful fallback with mock data

## 📤 Output
```json
{
  "ip": "45.156.87.83",
  "country": "RU",
  "abuse_score": 85,
  "total_reports": 12,
  "is_malicious": true,
  "source": "abuseipdb"
}
```

## 📊 Performance
- 77 API calls (45 IPs, 24 domains, 8 URLs)
- 0 duplicate calls due to caching
- ~2-5 minutes total (API bottleneck)

---

# 🔹 8. Correlation Agent
## 🎯 Purpose
Establish relationships between IOCs and build threat context.

## ⚙️ Responsibilities
Link:
- Domain → IP (DNS resolutions)
- IP → multiple domains
- Alert → evidence (packet numbers, flow IDs)
- Detect connections between related events

## 📤 Output
```json
{
  "connection": "DNS query for 'whooptm.cyou' resolved to malicious IP 104.21.36.177",
  "from_event": "dns_query",
  "to_event": "phishing_alert"
}
```

## 🔥 Key Feature
Transforms isolated alerts into attack narrative with evidence linking.

---

# 🔹 9. Risk Scoring Agent
## 🎯 Purpose
Prioritize threats based on multiple factors.

## ⚙️ Formula
```text
Base Score (from severity) + Bonuses = Final Score (0-100, capped)
```

| Severity | Base Score |
|----------|------------|
| CRITICAL | 90 |
| HIGH | 70 |
| MEDIUM | 40 |
| LOW | 10 |

## Bonuses
| Bonus | Value | Condition |
|-------|-------|-----------|
| Enrichment confirms malicious | +10 | VT/AbuseIPDB says malicious |
| Multi-pillar attack | +5 | Domain + IP both suspicious |

## 📤 Output
```json
{
  "risk_score": 80,
  "explanation": "Score 80/100: Domain 'whooptm.cyou' uses suspicious TLD '.cyou'. VirusTotal confirms malicious (22/94 detections). Recommended: Block immediately.",
  "recommended_action": "Block immediately and isolate the host"
}
```

## 📊 Examples
| Alert | Base | Enrichment | Multi | Final |
|-------|------|------------|-------|-------|
| Phishing | 70 | +10 | 0 | 80/100 |
| C2 Beaconing | 70 | 0 | 0 | 70/100 |
| Multi-Pillar | 90 | +10 | +5 | 100/100 |

---

# 🔹 10. Timeline Agent
## 🎯 Purpose
Reconstruct chronological attack narrative with evidence.

## ⚙️ Responsibilities
- Sort all events by timestamp
- Add kill-chain phase mapping (MITRE ATT&CK)
- Link related events with evidence
- Generate human-readable attack story

## 📤 Output
```json
{
  "time": "22:45:01",
  "event": "DNS query to whooptm.cyou",
  "type": "dns",
  "evidence": "packet #1234",
  "phase": "Reconnaissance"
}
```

## 🔥 Example Timeline
```text
[22:45:01] 🔍 DNS query to whooptm.cyou
         └─ Evidence: packet #1234, flow #42

[22:45:01] 🎣 [HIGH] PHISHING: Suspicious domain .cyou
         └─ 🔗 Connected: DNS query resolved to malicious IP

[22:45:02] 📡 [HIGH] C2 BEACONING to 45.156.87.83
         └─ 91 repeated flows detected
```

## 🎯 Kill-Chain Phases
- 🔍 Reconnaissance (suspicious TLD, scanning)
- 🎣 Initial Access (phishing)
- 📦 Delivery/Execution (HTTP anomalies)
- 📡 Command & Control (beaconing, malicious IP)
- 💾 Exfiltration (DNS tunneling, high packet rate)
- 💀 Full Compromise (multi-pillar attack)

---

# 🔹 11. Dashboard Agent
## 🎯 Purpose
Visualize all processed data and insights.

## ⚙️ Features
- Dark SOC-style theme with neon purple/blue glow
- Real-time pipeline progress (9 steps with animations)
- Live metrics (packets, flows, IPs, domains, alerts)
- Live log streaming with timestamps
- Interactive charts: Protocol distribution, Alert timeline, Packet length histogram
- KPI cards (CRITICAL/HIGH/MEDIUM/LOW/TOTAL)
- Filterable alerts table (severity, protocol, IPs)
- Attack timeline with evidence
- Export capabilities (JSON, CSV)
- Alert detail modal with MITRE ATT&CK mapping

## 📤 Output Formats
- Web dashboard (HTML/CSS/JS)
- JSON export (alerts.json, timeline.json)
- CSV export for reporting

## 🛠 Technologies
- Flask (Python backend)
- TailwindCSS
- Chart.js
- Vanilla JavaScript

---

# 🔹 12. Response Agent (Planned)
## 🎯 Purpose
Trigger automated or manual actions.

## ⚙️ Planned Actions
- Block IP (firewall integration)
- Generate alerts to SIEM
- Email/webhook notifications
- Auto-containment of compromised hosts

## 📤 Output (Mock)
```json
{
  "action": "BLOCK_IP",
  "target": "45.156.87.83",
  "status": "SIMULATED",
  "timestamp": "..."
}
```

---

# 🧠 Key Design Principles
| Principle | Implementation |
|-----------|----------------|
| Modular agent-based architecture | 11 independent agents with clear boundaries |
| Parallel processing | Async enrichment, polling-based status |
| Explainable detection | Human-readable risk explanations, evidence linking |
| Multi-pillar intelligence | IP, Domain, URL, Hash extraction |
| Event-driven workflow | Status polling every 1 second |
| Caching for performance | LRU cache for API calls |
| Graceful degradation | Mock data when APIs unavailable |

---

# 📊 Performance Metrics
| Metric | Value |
|--------|-------|
| Test PCAP | 10,593 packets (Lumma Stealer) |
| Processing time | 2-5 minutes |
| Flows aggregated | 407 |
| IOCs extracted | 45 IPs, 24 domains, 8 URLs |
| Alerts generated | 58 (46 HIGH, 10 MEDIUM, 2 CRITICAL) |
| API calls | 77 (cached, no duplicates) |
| Detection rules | 11 |
| Kill-chain phases | 6/6 covered |
| Dashboard refresh | 1 second polling |

---

# 🔥 Final Insight
AutoSOC NDR is not just a detection tool — it is a complete threat intelligence and network detection platform that combines:

✅ Network traffic analysis (PCAP → Flows → IOCs)
✅ Threat intelligence (4 pillars + 3 enrichment APIs)
✅ Behavioral detection (11 IOA rules)
✅ Correlation and campaign detection (evidence linking)
✅ SOC workflow simulation (alerts, timeline, risk scoring)
✅ Professional dashboard (real-time visualization)

---

# 📁 Project Structure
```text
autosoc/
├── detection/          # Detection agent (11 rules)
├── pcap/              # Packet + Session + Feature agents
├── enrichment/        # Enrichment agent (3 APIs)
├── scoring/           # Risk scoring agent
├── timeline/          # Timeline + Correlation agent
├── web/               # Dashboard agent
├── output/            # Generated results
└── sample_data/       # Test PCAP files
```

---

# 🚀 Quick Commands
```bash
# Run detection engine
python detection/engine.py sample_data/lumma.pcap

# Run dashboard
cd web && python app.py

# Open browser to http://127.0.0.1:5000
```

# 🔹 13. Alert Aggregation Agent

## 🎯 Purpose
Group thousands of duplicate alerts into meaningful security events.

## ⚙️ Responsibilities
- Group DDoS alerts by target IP
- Group Scan alerts by source IP
- Group Beaconing alerts by src→dst pair
- Count unique sources/targets
- Calculate attack duration
- Determine correct severity based on scale

## 📤 Output
```json
{
  "event_type": "ddos_attack",
  "severity": "CRITICAL",
  "target_ip": "10.10.10.10",
  "unique_sources": 7055,
  "total_flows": 7061,
  "duration_seconds": 0.5,
  "top_sources": ["107.186.78.199", "172.120.23.14"],
  "reason": "DDoS attack detected: 7055 unique sources targeting 10.10.10.10"
}
```

## 🔥 Impact
- 7,061 alerts → 1 aggregated event (99.9% reduction)
- Enables SOC triage
- Provides attack-level visibility

---
**AutoSOC NDR - Agent-Based Network Detection & Response Platform**
*MSc Cybersecurity Project - 2026*

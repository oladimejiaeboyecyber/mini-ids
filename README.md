# Mini Intrusion Detection System (IDS)

## Project Overview
A hybrid Intrusion Detection System built in Python that analyzes 
network traffic from PCAP files and detects suspicious activity 
using signature-based and anomaly-based detection.

Built as a cybersecurity portfolio project to demonstrate practical 
network security and Python skills.

---

## Features

### Signature-Based Detection
Checks network traffic against predefined rules:
- **Port Scan Detection** — flags IPs contacting more than 5 unique ports
- **Suspicious Port Detection** — flags traffic to known dangerous ports (23, 21, 3389, 445)
- **Packet Flood Detection** — flags IPs sending more than 100 packets (DoS detection)

### Anomaly-Based Detection
Uses Isolation Forest machine learning algorithm to learn normal 
traffic patterns and flag deviations from the baseline.

### Alert Engine
Generates professional formatted alerts saved to outputs/alerts.txt 
with severity levels (HIGH/MEDIUM/LOW) and timestamps.

### Evaluation
Measures IDS performance using:
- Precision
- Recall  
- F1 Score
- Confusion Matrix

### Visualizations
Generates charts showing:
- Alert severity distribution
- Top attacking IPs by packet count
- Protocol distribution (TCP/UDP/ICMP)

---

## Technology Stack
- **Python** — core programming language
- **Scapy** — packet parsing and PCAP analysis
- **Pandas** — data processing and feature extraction
- **Scikit-learn** — Isolation Forest anomaly detection
- **Matplotlib/Seaborn** — visualizations

---

## Project Structure
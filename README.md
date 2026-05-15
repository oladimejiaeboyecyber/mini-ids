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
Built a hybrid IDS from scratch that analyzes real network traffic from PCAP files using signature-based and ML-based detection
• Implemented 3 signature detection rules (port scan, packet flood, suspicious ports) that detected 17 confirmed attacks across 14,968 packets
• Integrated Isolation Forest machine learning algorithm to detect 150 network anomalies without predefined rules
• Engineered an alert engine that classifies threats as HIGH/MEDIUM/LOW severity and logs structured alerts to file
• Evaluated system performance using precision, recall, F1 score and confusion matrix achieving 100% recall on known attack traffic

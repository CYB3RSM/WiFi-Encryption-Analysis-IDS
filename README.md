# WiFi-Encryption-Analysis-IDS
Modular WiFi traffic monitoring, profiling &amp; encryption analysis system for IDS.  Analyzes encrypted vs plaintext traffic, TLS metadata, cipher suites, and detects anomalies using ML — without breaking encryption.
This repository contains the source code and dataset for  Intrusion Detection Systems

**Core Theme:** WiFi Traffic Monitoring, Profiling, and Encryption Analysis System

**Ethical Constraint:** Only metadata analysis on lab/simulated PCAP data. 
No decryption of HTTPS or private traffic.

**Modules Implemented:**
- Traffic Acquisition (PCAP / tshark / pyshark / scapy)
- Packet Parsing & Feature Extraction (IP, MAC, ports, timestamps)
- Device Identification & Profiling
- Protocol & Application Analysis (DNS, HTTP, TLS handshake)
- Encryption Detection (Encrypted vs Plaintext)
- Encryption Scheme & Strength Analysis (TLS version, cipher suite, key exchange)
- Behavioral Profiling (per-device traffic patterns)
- Anomaly Detection using Machine Learning
- Interactive Visualization Dashboard

**Dataset Features:**
- encryption_flag
- tls_version
- cipher_suite

**Deliverables:**
- Modular Python code
- Raw PCAP / processed dataset
- Technical report (20-25 pages)
- Live dashboard with encryption insights & weak encryption alerts
- Presentation + demo

**Bonus Features (if implemented):**
- TLS fingerprinting (JA3)
- Encrypted malware pattern detection
- Real-time alerts
- Explainable AI

**Technologies:** Python, Scapy, PyShark, TShark, Scikit-learn, Dash/Plotly/Matplotlib

**Program:** MS Information Systems  
**Submission Date:** 01 June 2026

# 🧱 User-Space Firewall with Real-Time Network Monitoring

## 📘 Overview
This project implements a **user-space firewall and network monitoring system** using **C/C++**.  
It captures and analyzes **live network packets** through `libpcap`, applies **rule-based filtering**, and classifies packets as **allowed, blocked, or suspicious**.  
The system also integrates a **lightweight Intrusion Detection System (IDS)** to identify repeated or potentially malicious network behaviors such as **port scanning or multiple connection attempts**.

The main goal of this project is to develop a **learning-oriented simulation** of firewall and IDS behavior that operates entirely in **user-space**, without requiring kernel-level programming.  

In the future, this project aims to evolve into a **production-level firewall and real-time monitoring system**, capable of advanced packet inspection, rule automation, and scalable network defense.

---

## 🚀 Features
- **Live Packet Capture:** Monitors real-time traffic from selected network interfaces using `libpcap`.  
- **Rule-Based Filtering:** Applies user-defined `ALLOW` or `BLOCK` rules from `rules.txt` based on IP, port, or protocol.  
- **Intrusion Detection (IDS):** Detects suspicious patterns such as repeated access or port scans.  
- **Logging System:** Records all packet activities and firewall decisions with timestamps in `firewall_log.txt`.  
- **Command-Line Interface (CLI):** Allows users to manage capture sessions, view logs, and reload rule sets.  
- **Simulation Mode:** Displays real-time firewall actions in a clear and informative terminal view.

---

## ⚙️ System Architecture
1. **Packet Capture Module** – Captures live packets and extracts relevant fields (IP, protocol, port).  
2. **Rule Matching Engine** – Compares packets against `rules.txt` entries for filtering decisions.  
3. **Simulation & Logging Module** – Displays `[ALLOW]`, `[BLOCK]`, and `[SUSPICIOUS]` packets with timestamps, and logs them.  
4. **Intrusion Detection System (IDS)** – Monitors traffic frequency from IPs and triggers alerts for repeated or abnormal access attempts.  
5. **CLI Controller** – Provides a text-based interface for managing captures, viewing logs, and reloading rules.

---

## ⚡ Future Expansion Plan
The next phase of this project will focus on transforming this simulator into a **fully functional production-grade firewall and monitoring suite**, including:
- Multi-threaded packet capture and rule processing.  
- Dynamic rule updates and real-time reconfiguration.  
- Advanced traffic analytics and visualization.  
- Encrypted log storage and blockchain-based log verification.  
- Cross-platform support and service deployment capabilities.

---

## 🛠️ Requirements
- **Programming Language:** C / C++  
- **Library:** `libpcap`  
- **Compiler:** GCC / G++  
- **Operating System:** Linux or Windows (with Npcap/WinPcap)


# 🧱 User-Space Firewall Simulator with Real Network Packet Capture and Intrusion Detection

## 📘 Overview
This project is a **user-space firewall simulator** built in **C/C++** that captures and analyzes **real network packets** and applies **rule-based filtering** to determine whether packets should be **allowed, blocked, or marked as suspicious**.  
It also integrates a **lightweight Intrusion Detection System (IDS)** to identify potential malicious behavior such as repeated access attempts or port scans.

The project focuses on **network-level understanding** of packet flow, firewall decision-making, and intrusion detection without requiring kernel-level programming. It’s designed for **learning, research, and security experimentation**.

---

## 🚀 Features
- **Real Packet Capture:** Uses `libpcap` to capture live packets from the selected network interface.  
- **Rule-Based Filtering:** Reads from a `rules.txt` file to apply `ALLOW` or `BLOCK` rules based on IP address, port, or protocol.  
- **Simulation Mode:** Displays packet flow and firewall decisions in real time.  
- **Intrusion Detection (IDS):** Detects repetitive or suspicious network behavior and raises alerts.  
- **Logging System:** Stores all firewall activities with timestamps in a log file.  
- **Command-Line Interface:** Start/stop capture, reload rules, and view logs interactively.

---

## ⚙️ Architecture Overview
1. **Packet Capture Module**  
   Captures live packets and extracts key fields such as IP, protocol, and port numbers.

2. **Rule Matching Engine**  
   Compares each packet against entries in `rules.txt`.  
   Example rule format:
     
      BLOCK IP 192.168.1.10
      ALLOW PORT 80
   
4. **Simulation & Logging Module**  
Displays `[ALLOW]`, `[BLOCK]`, or `[SUSPICIOUS]` packets in real-time and saves them to `firewall_log.txt`.

5. **Intrusion Detection System (IDS)**  
Tracks IP activity frequency.  
Alerts when the same IP performs repeated requests or port scans within a short interval.

6. **CLI Controller**  
Provides a text-based menu to manage the simulation.

---

## 📂 File Structure

firewall_simulator/
│
├── src/
│ ├── main.c / main.cpp # Main application
│ ├── packet_capture.c # Handles packet sniffing
│ ├── rule_engine.c # Parses and applies rules
│ ├── ids_module.c # Intrusion detection logic
│ └── logger.c # Logs actions and alerts
│
├── rules.txt # User-defined filtering rules
├── firewall_log.txt # Generated logs
├── Makefile # Build instructions
└── README.md # Project documentation

## 🧩 Example Output
[ALLOW] TCP 192.168.1.5:50321 -> 192.168.1.1:80
[BLOCK] TCP 192.168.1.10:22 -> 192.168.1.1:22 (Rule: BLOCK IP 192.168.1.10)
[IDS] 🚨 Suspicious repeated access detected from 192.168.1.10
Total Packets: 120 | Blocked: 12 | Allowed: 105 | Suspicious: 3


## 🛠️ Requirements
- **Language:** C / C++  
- **Library:** `libpcap`  
- **Compiler:** GCC / G++  
- **Operating System:** Linux or Windows (with Npcap/WinPcap)  

**To install `libpcap` (Linux):**
```bash
sudo apt-get install libpcap-dev

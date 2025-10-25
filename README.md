# 🧱 User-Space Firewall with Real-Time Network Monitoring

## 📘 Overview
This project is a **user-space network monitoring and firewall system** built in **C/C++**, designed to **capture, analyze, and filter network traffic in real time**.  

It provides a **production-level architecture** for packet **inspection**, **decision-making (allow, block, or suspicious)**, and **system-level network monitoring** using **rule-based filtering and pattern detection**.

The project also integrates a **lightweight Intrusion Detection System (IDS)** to identify suspicious behaviors such as repeated access attempts, port scans, or abnormal packet rates. It is ideal for **research**, **security learning**.

---

## 🚀 Key Features
- **🔍 Real-Time Packet Capture:** Uses `libpcap` for live traffic capture at the system level.  
- **🧠 Intelligent Analysis:** Extracts headers and metadata to identify protocol, IPs, and ports.  
- **🧩 Rule-Based Filtering:** Supports custom `ALLOW` and `BLOCK` rules via a configuration file (`rules.txt`).  
- **🚨 Intrusion Detection System (IDS):** Detects repetitive IP hits, port scans, or suspicious packet patterns.  
- **🖥️ System-Level Monitoring:** Provides packet statistics, traffic summaries, and active connections in real-time.  
- **📊 Logging & Alerting:** Logs all actions (allowed, blocked, suspicious) with timestamps for audit and debugging.  
- **💻 CLI Control Panel:** Command-based interface to manage capture sessions, load new rules, and monitor traffic interactively.  

---

## ⚙️ System Workflow
1. **Packet Capture Layer**  
   - Captures live packets using `libpcap` or Npcap (on Windows).  
   - Extracts IP, ports, protocol, and packet size.  
   - Passes metadata to the Analysis Engine.  

2. **Packet Analysis & Decision Engine**  
   - Parses packet headers and applies decision logic.  
   - Matches packets against `rules.txt`.  
   - Supports dynamic actions: `ALLOW`, `BLOCK`, or `SUSPICIOUS`.  
   - Includes a traffic frequency tracker for anomaly detection.  

3. **Intrusion Detection (IDS) Module**  
   - Detects repetitive packet patterns or sudden traffic spikes.  
   - Flags IPs performing multiple failed attempts or unusual port activity.  
   - Generates alerts and logs for suspicious traffic.  

4. **Monitoring & Logging System**  
   - Records all firewall actions and IDS alerts to `firewall_log.txt`.  
   - Displays real-time summary: total, allowed, blocked, and suspicious packets.  
   - Offers traffic statistics (packets/sec, bytes/sec).  

5. **CLI Controller**  
   - Menu-based control (start/stop capture, reload rules, view stats).  
   - Can display recent logs or live traffic feed.  

---

## 🛠️ Requirements
- **Programming Language:** C / C++  
- **Library:** `libpcap`  
- **Compiler:** GCC / G++  
- **Operating System:** Linux or Windows (with Npcap/WinPcap)


# User-Space Defensive Security Monitoring System


## Project Description
The core idea of this project is to develop a C++-based **user-space** network monitoring system that captures **live packets**, detects **layer-4 intrusions** (like DoS), and securely logs all events using a **block chain-based hashing** mechanism for integrity...

---

## Key Features
- **Packet capture and traffic analysis:** Captures live packets using `raw sockets` or `libpcap`. Extracts layer 3 and Layer 4 headers (IP, Port, Protocol) and classifies packets as inbound, outbound, or local.  
- **Firewall Engine:** Implements rule-based filtering to `allow`, `block`, or monitor packets based on IP, Ports, or Protocol. Every decision is logged in real time.  
- **Intrusion Detection:** Maintains a suspicious flow table to identify potential `Port scans` and `DoS patterns` using timestamp-based frequency counter.  
- **Block chain-Secured Logging:** Network event are securely stored as linked blocks, each containing a timestamp, event data, and the previous block’s hash. Implement  `SHA-256` hashing for block validation, ensuring tamper-proof and immutable logs chains.    
- **Real-Time Terminal Dashboard:** Displays live packets `ststistics` (total, allowed, blocked, suspicious). Shows IDS `alerts` and block-chain update dynamically.  
- **Modular Architecture:** 6.Designed with independent modules (Capture, Firewall, IDS, Logger, Block chain), enabling re-usability, maintainability and future extensibility.    

---

## System Workflow
1. **Packet Capture Layer**  
   - Captures live packets using `libpcap` or raw sockets.  
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

## Requirements
- **Programming Language:** C++  
- **Library:** `stdio`, `stdlib`, `ctime`, `string`, `fstream`, `thread`, `libcap` etc.  
- **Compiler:** GCC / G++  
- **Operating System:** Linux 


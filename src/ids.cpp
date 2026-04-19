// src/ids.cpp er update
#include "../include/ids.h"
#include <iostream>
#include <map>
#include <deque>
#include <mutex>
#include "../include/color.h"

using namespace std;

namespace IDS {

    const int DOS_THRESHOLD = 1000;      // 1 second e 1000 packet
    const int PORT_SCAN_THRESHOLD = 20;  // 1 second e 20+ unique port
    const int TIME_WINDOW_MS = 1000;     // Time window 1 second

    // Packet er timestamp abong port eksathe rakhar jonno struct
    struct PacketData {
        long long timestamp;
        int port;
    };

    struct Flow {
        deque<PacketData> history;
        map<int, int> port_counts; // Kon port e koyta request asche tar hishab
    };

    map<string, Flow> flowTable;
    mutex idsLock;

    void init() {
        cout << "[IDS] " << GREEN << "Intrusion Detection System Initialized" << RESET << endl;
    }

    void shutdown() {
        cout << "[IDS] " << YELLOW << "Shutting down Intrusion Detection System" << RESET << endl;
    }

    bool analyze(const Packet &p) {
        lock_guard<mutex> guard(idsLock);
        Flow &f = flowTable[p.srcIP];

        // 1. Notun packet add kora hocche
        f.history.push_back({p.timestamp_ms, p.dstPort});
        f.port_counts[p.dstPort]++; 

        // 2. 1 second (1000ms) er purono packet gulo window theke remove kora hocche
        long long cutoff = p.timestamp_ms - TIME_WINDOW_MS;
        while (!f.history.empty() && f.history.front().timestamp < cutoff) {
            int old_port = f.history.front().port;
            
            // Purono port er count komano hocche
            f.port_counts[old_port]--;
            
            // Jodi kono port er count 0 hoye jay, map theke kete deya hocche
            if (f.port_counts[old_port] == 0) {
                f.port_counts.erase(old_port);
            }
            f.history.pop_front();
        } 
    
        // 3. DoS Detection (1 second er moddhe total packet count)
        if (f.history.size() > DOS_THRESHOLD) {
            cout << "\033[2K\r" << RED << BOLD << "[IDS ALERT] DoS Attack detected from " << p.srcIP << RESET << endl;
            return true; 
        }

        // 4. Port Scan Detection (1 second er moddhe unique port er count)
        if (f.port_counts.size() > PORT_SCAN_THRESHOLD) {
            cout << "\033[2K\r" << YELLOW << BOLD << "[IDS ALERT] Port Scan detected from " << p.srcIP << RESET << endl;
            
            // Alert deyar por data clear kore deya holo jate bar bar same alert na ase
            f.port_counts.clear(); 
            f.history.clear(); 
            return true;
        }

        return false;
    }
}
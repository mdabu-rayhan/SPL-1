#include "../include/stats.h"
#include "../include/color.h"
#include <iostream>
using namespace std;


static long total = 0, allowed = 0, blocked = 0, suspicious = 0;

void initUI() {
    total = allowed = blocked = suspicious = 0;
}

void printPacketLog(const Packet &p, const Decision &d) {
    total++;

    if (d.rule == "NO MATCH") {
        suspicious++;
        cout << YELLOW << "[SUSPICIOUS] " << RESET;
    }
    else if (d.allowed) {
        allowed++;
        cout << GREEN << "[ALLOW] " << RESET;
    }
    else {
        blocked++;
        cout << RED << "[BLOCK] " << RESET;
    }

    cout << p.protocol << " "
              << p.srcIP << ":" << p.srcPort
              << " -> "
              << p.dstIP << ":" << p.dstPort
              << "                      \n";

    printLiveStats();
}

void printLiveStats() {
    cout << CYAN
              << "                    Total: " << total
              << " | " << GREEN << "Allow: " << allowed << CYAN
              << " | " << RED << "Block: " << blocked << CYAN
              << " | " << YELLOW << "Suspicious: " << suspicious << CYAN
              << "\r" << RESET << std::flush;
}

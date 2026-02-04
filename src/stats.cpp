#include "../include/stats.h"
#include "../include/color.h"
#include <iostream>


using namespace std;

// Clear entire line
#define CLEAR_LINE "\033[2K"

static long total = 0;
static long allowed = 0;
static long blocked = 0;
static long suspicious = 0;

void initUI() {
    total = allowed = blocked = suspicious = 0;
}

/* Print one packet log */
void printPacketLog(const Packet &p, const Decision &d) {
    total++;

    // Move to new line
    cout << CLEAR_LINE << "\r";


    if (d.rule == "DoS DETECTED") {
        blocked++;
        cout << RED << "[ALERT] " << BOLD << "DoS ATTACK " << RESET;
    }
    else if (d.rule == "NO MATCH") {
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
         << endl;

    printLiveStats();
}


void printLiveStats() {
    cout << CLEAR_LINE << "\r"
         << CYAN
         << "                    Total: " << total
         << " | " << GREEN << "Allow: " << allowed << CYAN
         << " | " << RED << "Block: " << blocked << CYAN
         << " | " << YELLOW << "Suspicious: " << suspicious
         << RESET << flush;
}

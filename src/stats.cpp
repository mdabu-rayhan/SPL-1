// src/stats.cpp er update
#include "../include/stats.h"
#include "../include/color.h"
#include "../include/blockchain.h" // Blockchain e data pathanor jonno include kora holo
#include <iostream>
#include <fstream>
#include <ctime>
#include <string>

using namespace std;

#define CLEAR_LINE "\033[2K"

static long total = 0;
static long allowed = 0;
static long blocked = 0;
static long suspicious = 0;
static long logIndex = 0; // Log ID er jonno counter

// src/stats.cpp er initUI() function er update
void initUI() {
    total = allowed = blocked = suspicious = logIndex = 0;

    // Program start holei firewall_log.txt clear kore dibe
    ofstream logFile("logs/firewall_log.txt", ios::trunc);
    if (logFile.is_open()) {
        logFile.close();
    }
}

// Timestamp function
string getTimestamp() {
    time_t now = time(0);
    char* dt = ctime(&now);
    string t(dt);
    t.pop_back();
    return t;
}

void printPacketLog(const Packet &p, const Decision &d) {
    total++;

    // Tag ta match korar jonno update kora holo
    if (d.rule == "DYNAMIC BLOCK (IDS ALERT)") {
        blocked++;
        printLiveStats();
        return;
    }

    // ... function er nicher baki ongsho ager motoni thakbe ...
    ofstream logFile("logs/firewall_log.txt", ios::app);
    string actionText;

    cout << CLEAR_LINE << "\r";

    if (d.rule == "NO MATCH") {
        suspicious++;
        actionText = "[SUSPICIOUS]";
        cout << YELLOW << "[SUSPICIOUS] " << RESET;
    }
    else if (d.allowed) {
        allowed++;
        actionText = "[ALLOW]";
        cout << GREEN << "[ALLOW] " << RESET;
    }
    else {
        blocked++;
        actionText = "[BLOCK]";
        cout << RED << "[BLOCK] " << RESET;
    }

    logIndex++; // ID increment kora holo (1, 2, 3...)

    // Log entry te ID add kora holo (Example: [ID: 1])
    string logEntry =getTimestamp() + " | " + actionText + " | " + p.protocol + " " + p.srcIP + ":" + to_string(p.srcPort) + " -> " + p.dstIP + ":" + to_string(p.dstPort);
    
    cout << p.protocol << " "
         << p.srcIP << ":" << p.srcPort
         << " -> "
         << p.dstIP << ":" << p.dstPort
         << endl;

    if (logFile.is_open()) {
        logFile << logEntry << "\n";
        logFile.close();
    }

    // !! IMPORTENT: Ekhane log er data ta blockchain e block hishebe add kora hocche !!
    Blockchain::addBlock(logEntry);

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
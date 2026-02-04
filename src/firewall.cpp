// rule_engine.cpp
#include "../include/firewall.h"
#include "../include/color.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <mutex> //
#include <vector>
#include <string>

using namespace std;

// Global variables 
vector<Rule> rules;         
mutex ruleLock;             // Protect rules vector

// Load rules from file
bool loadRules(const string &path) {
    lock_guard<mutex> guard(ruleLock);

    ifstream file(path);
    if (!file) {
        cerr << "[Firewall] Cannot open rules file: " << path << "\n";
        return false;
    }

    rules.clear();
    string line;
    while (getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        stringstream ss(line);
        string action, proto, ip;
        int port;
        ss >> action >> proto >> ip >> port;

        Rule r;
        r.allow = (action == "ALLOW");
        r.proto = proto;
        r.ip = ip;
        r.port = port;
        r.raw = line;

        rules.push_back(r);
    }

    cout << "[Firewall]" << GREEN << " Rules loaded " << RED << rules.size() << GREEN << " rules\n" << RESET;
    return true;
}

// Helper functions
static bool matchIP(const string &ruleIP, const Packet &p) {
    // Match IP
    return (ruleIP == "*" || ruleIP == p.srcIP || ruleIP == p.dstIP);
}

static bool matchProto(const string &ruleProto, const string &pktProto) {
    return (ruleProto == "ANY" || ruleProto == pktProto);
}

static bool matchPort(int rulePort, int pktPort) {
    return (rulePort == 0 || rulePort == pktPort);
}

// Evaluate packet
Decision evaluatePacket(const Packet &p) {
    lock_guard<mutex> guard(ruleLock);

    for (auto &r : rules) {
        if (matchProto(r.proto, p.protocol) &&
            matchIP(r.ip, p) &&
            (matchPort(r.port, p.srcPort) || matchPort(r.port, p.dstPort)))
        {
            return { r.allow, r.raw };
        }
    }

    // No rule matched = suspicious
    return { false, "NO MATCH" };
}


void blockIP(const string &ip) {
    lock_guard<mutex> guard(ruleLock);

    
    for (const auto &r : rules) {
        if (!r.allow && r.ip == ip && r.proto == "ANY") {
            return; 
        }
    }

    
    Rule r;
    r.allow = false;      
    r.proto = "ANY";      
    r.ip = ip;            
    r.port = 0;           
    r.raw = "DYNAMIC BLOCK (DoS DETECTED)";

    rules.insert(rules.begin(), r);

    cout << "\033[2K\r";

    cout << BOLD << "[Firewall] " << RED << "BLOCKED IP: " << ip << " due to DoS Attack!" << RESET << endl;
}

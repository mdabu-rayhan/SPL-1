#pragma once
#include <string>
#include <vector>
#include "packet.h"
using namespace std;

struct Rule {
    bool allow;         // ALLOW = true, BLOCK = false
    string proto;  // TCP, UDP, ICMP, ANY
    string ip;     // exact or "*"
    int port;           // 0 = ANY
    string raw;    // original rule text
};

struct Decision {
    bool allowed;
    string rule;
};

bool loadRules(const string &path);
Decision evaluatePacket(const Packet &p);

void blockIP(const string &ip);


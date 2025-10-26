#pragma once
#include "utils.h"
#include <string>
#include <vector>
using namespace std;

struct Rule
{
    string action; // "ALLOW" or "BLOCK"
    string proto;  // "TCP","UDP","ICMP","ANY"
    string ip;     // ip or "*"
    int port;      // 0 means any
};

namespace RuleEngine
{
    bool loadRules(const string &path);
    string decide(const Packet &p, int &matchedIndex); // returns "ALLOW" or "BLOCK"
    void reloadRules();
    vector<Rule> getRules();
}

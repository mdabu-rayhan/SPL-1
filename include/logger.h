#pragma once
#include "packet.h"
#include <string>
using namespace std;

namespace Logger
{
    bool init(const string &path);
    void shutdown();
    void logDecision(const Packet &p, const string &decision, int ruleIndex);
    void logIDS(const Packet &p, const string &msg);
}

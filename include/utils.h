#pragma once
#include <string>
using namespace std;

struct Packet
{
    string srcIP;
    string dstIP;
    string protocol; // "TCP", "UDP", "ICMP", "OTHER"
    int srcPort;
    int dstPort;
    int size; // bytes
    long long timestamp_ms;
};

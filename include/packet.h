#pragma once
#include <string>
using namespace std;

struct Packet
{
    string srcIP;
    string dstIP;
    string protocol;
    int srcPort;
    int dstPort;
    int size; 
    long long timestamp_ms;
};

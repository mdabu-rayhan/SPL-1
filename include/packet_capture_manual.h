#pragma once
#include "packet.h"
#include <string>
#include <pcap.h>
#include <iostream>
#include <chrono>
#include <arpa/inet.h>
#include <cstring>
using namespace std;

namespace PacketCapture
{

    // reads 2 bytes in big-endian
    uint16_t read_u16(const u_char* data);
    // reads 4 bytes in big-endian
    uint32_t read_u32(const u_char* data);
    // Manual parser
    Packet parseRaw(const u_char* packet, int len);
    // Callback
    void packetHandler(u_char*, const pcap_pkthdr* header, const u_char* packet);
    // start simulated capture in a blocking call; returns when stopped
    void startCapture(const char* device);
    // stop capture by setting global flag (main uses running flag)
    void stopCapture();
}

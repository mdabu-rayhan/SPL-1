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

    uint16_t read_u16(const u_char* data); // reads 2 bytes
    
    uint32_t read_u32(const u_char* data); // reads 4 bytes
    
    Packet parseRaw(const u_char* packet, int len); // Manual parser

    void packetHandler(u_char*, const pcap_pkthdr* header, const u_char* packet); // Callback
    
    void startCapture(const char* device);

    void stopCapture();
}

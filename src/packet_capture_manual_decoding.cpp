#include <pcap.h>
#include <iostream>
#include <chrono>
#include <arpa/inet.h>
#include <cstring>


#include "../include/packet.h"
#include "../include/packet_capture_manual.h"
#include "../include/firewall.h"
#include "../include/ids.h"
#include "../include/stats.h"
#include "../include/color.h"

using namespace std;

// Global handle for stopping
pcap_t* global_handle = nullptr;

uint16_t read_u16(const u_char* data) {
    return (data[0] << 8) | data[1];
}

uint32_t read_u32(const u_char* data) {
    return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
}

// Manual parser
Packet parseRaw(const u_char* packet, int len) {
    Packet pkt;
    pkt.size = len;
    pkt.srcPort = pkt.dstPort = 0;

    pkt.timestamp_ms =
        chrono::duration_cast<chrono::milliseconds>(
            chrono::system_clock::now().time_since_epoch()
        ).count();

    // Ethernet 
    uint16_t ethertype = read_u16(packet + 12);
    if (ethertype != 0x0800) {
        pkt.protocol = "OTHER";
        return pkt;
    }

    const u_char* ip = packet + 14;

    uint8_t version = ip[0] >> 4;
    uint8_t ihl = ip[0] & 0x0F;
    int ip_header_len = ihl * 4;

    uint8_t protocol = ip[9];

    // IP addresses
    char src_ip[16], dst_ip[16];

    snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u",
        ip[12], ip[13], ip[14], ip[15]);

    snprintf(dst_ip, sizeof(dst_ip), "%u.%u.%u.%u",
        ip[16], ip[17], ip[18], ip[19]);

    pkt.srcIP = src_ip;
    pkt.dstIP = dst_ip;

    const u_char* transport = ip + ip_header_len;

    // TCP
    if (protocol == 6) {
        pkt.protocol = "TCP";
        pkt.srcPort = read_u16(transport);
        pkt.dstPort = read_u16(transport + 2);

        if (transport[13] & 0x04) {
            pkt.protocol = "IGNORE"; // Ignore outgoing reset packets
        }

    // UDP 
    } else if (protocol == 17) {
        pkt.protocol = "UDP";
        pkt.srcPort = read_u16(transport);
        pkt.dstPort = read_u16(transport + 2);

    // ICMP 
    } else if (protocol == 1) {
        pkt.protocol = "ICMP";
        pkt.srcPort = 0;
        pkt.dstPort = 0;

        uint8_t icmp_type = transport[0];

        if (icmp_type == 0 || icmp_type == 3) {
            pkt.protocol = "IGNORE"; // Ignore outgoing echo replies & dest unreachable
        }


    } else {
        pkt.protocol = "OTHER";
    }

    return pkt;
}

// Callback
void packetHandler(u_char*, const pcap_pkthdr* header, const u_char* packet) {
    Packet pkt = parseRaw(packet, header->len);

    if (pkt.protocol == "IGNORE") {
        return;
    }

    // 1. Run Firewall Checks
    Decision d = evaluatePacket(pkt);

    if (!d.allowed) {
        printPacketLog(pkt, d);
        return; 
    }


    // 2. Run IDS (DoS Detection)
    bool isDoS = IDS::analyze(pkt);


    // 3. Override Firewall decision if IDS detects an attack
    if (isDoS) {
        d.allowed = false;
        d.rule = "DoS DETECTED";

        blockIP(pkt.srcIP);
    }

    // 4. Log the packet
    printPacketLog(pkt, d);

}

void startCapture(const char* device) {

    // Initialize firewall & stats
    //loadRules("/home/kali/Desktop/SPL-1/data/rules.txt");
    if (!loadRules("/home/kali/Desktop/SPL-1/data/rules.txt")) { 
         cerr << RED << "Failed to load rules! Defaulting to deny all." << RESET << endl;
    }
    initUI(); // Initialize Stats UI
    IDS::init(); //Initialize IDS

    char errbuf[PCAP_ERRBUF_SIZE];
    global_handle = pcap_open_live(device, 65535, 1, 1000, errbuf);

    if (!global_handle) {
        cerr << "Error: " << errbuf << "\n";
        return;
    }

    cout << "Capturing on " << GREEN << device << RESET << "...\n\n";

    pcap_loop(global_handle, -1, packetHandler, nullptr);

    pcap_close(global_handle);
    global_handle = nullptr;
}

void stopCapture() {
    if (global_handle)
        pcap_breakloop(global_handle);
}

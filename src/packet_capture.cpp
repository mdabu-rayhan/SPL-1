#include <pcap.h>
#include <iostream>
#include <chrono>
#include <thread>
#include <arpa/inet.h>

#include "../include/packet.h"
#include "../include/packet_capture.h"

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

// Global handle to allow stopping capture
pcap_t* global_handle = nullptr;

// Convert raw packet to Packet object
Packet parsePacket(const u_char* packet, int packet_len) {
    Packet pkt;
    pkt.size = packet_len;

    pkt.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    const struct ether_header* eth = (struct ether_header*) packet;

    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        pkt.protocol = "OTHER";
        return pkt;
    }

    const struct iphdr* ip = (struct iphdr*) (packet + sizeof(ether_header));
    int ip_header_len = ip->ihl * 4;

    pkt.srcIP = inet_ntoa(*(in_addr*)&ip->saddr);
    pkt.dstIP = inet_ntoa(*(in_addr*)&ip->daddr);

    switch (ip->protocol) {
        case IPPROTO_TCP: {
            pkt.protocol = "TCP";
            const struct tcphdr* tcp = (struct tcphdr*) (packet + sizeof(ether_header) + ip_header_len);
            pkt.srcPort = ntohs(tcp->source);
            pkt.dstPort = ntohs(tcp->dest);
            break;
        }
        case IPPROTO_UDP: {
            pkt.protocol = "UDP";
            const struct udphdr* udp = (struct udphdr*) (packet + sizeof(ether_header) + ip_header_len);
            pkt.srcPort = ntohs(udp->source);
            pkt.dstPort = ntohs(udp->dest);
            break;
        }
        case IPPROTO_ICMP: {
            pkt.protocol = "ICMP";
            pkt.srcPort = 0;
            pkt.dstPort = 0;
            break;
        }
        default:
            pkt.protocol = "OTHER";
            pkt.srcPort = pkt.dstPort = 0;
            break;
    }

    return pkt;
}

// Callback from libpcap
void packetHandler(u_char* args, const pcap_pkthdr* header, const u_char* packet) {
    Packet pkt = parsePacket(packet, header->len);

    std::cout << pkt.protocol << " "
              << pkt.srcIP << ":" << pkt.srcPort << " -> "
              << pkt.dstIP << ":" << pkt.dstPort
              << "  size=" << pkt.size << "\n";
}

// Start capturing packets
void startCapture(const char* device) {
    char errbuf[PCAP_ERRBUF_SIZE];

    global_handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);

    if (!global_handle) {
        std::cerr << "Error opening device: " << errbuf << "\n";
        return;
    }

    std::cout << "Capturing on device: " << device << "\n";

    pcap_loop(global_handle, -1, packetHandler, nullptr);

    pcap_close(global_handle);
    global_handle = nullptr;

    std::cout << "Capture stopped.\n";
}

// Stop capturing safely
void stopCapture() {
    if (global_handle != nullptr)
        pcap_breakloop(global_handle);
}

// ...existing code...
#include "../include/packet_capture.h"
#include "../include/rule_engine.h"
#include "../include/ids.h"
#include "../include/logger.h"
#include "../include/stats.h"
#include <atomic> //(local_running) used to safely signal stopCapture() across threads

#include <iostream>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>    // inet_ntop, ntohs
#include <netinet/ip.h>   // struct ip
#include <pcap/pcap.h>    // libpcap

using namespace std;

static atomic<bool> local_running(true);
static pcap_t *g_pcap_handle = nullptr;

// stop capture: signals loop to break immediately
void PacketCapture::stopCapture() {
    local_running = false;
    if (g_pcap_handle) {
        pcap_breakloop(g_pcap_handle);
    }
}

// helper: convert timeval to ms
static long long ts_to_ms(const struct timeval &tv) {
    return (long long)tv.tv_sec * 1000LL + (tv.tv_usec / 1000);
}

// minimal ethernet/ipv4 parsing constants
static const size_t ETH_HDR_LEN = 14;
static const uint16_t ETHERTYPE_IP = 0x0800;

// packet callback called by pcap_loop
static void pcap_packet_cb(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    if (!local_running) {
        // pcap_breakloop already requested in stopCapture()
        return;
    }

    // sanity: need ethernet + ipv4 header
    if (!bytes || h->caplen < ETH_HDR_LEN + sizeof(struct ip)) return;

    // check ether type at offset 12..13
    uint16_t eth_type = ntohs(*(const uint16_t *)(bytes + 12));
    if (eth_type != ETHERTYPE_IP) return; // skip non-IPv4

    const u_char *ip_ptr = bytes + ETH_HDR_LEN;
    const struct ip *ip_hdr = (const struct ip *)ip_ptr;
    int ip_hdr_len = (ip_hdr->ip_hl & 0x0f) * 4;
    if (ip_hdr_len < 20) return;
    size_t trans_offset = ETH_HDR_LEN + ip_hdr_len;
    if (h->caplen < trans_offset) return;

    char src_buf[INET_ADDRSTRLEN] = {0}, dst_buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &ip_hdr->ip_src, src_buf, sizeof(src_buf));
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_buf, sizeof(dst_buf));

    Packet p;
    p.srcIP = src_buf;
    p.dstIP = dst_buf;
    p.size = (int)h->len;
    p.timestamp_ms = ts_to_ms(h->ts);
    p.srcPort = 0;
    p.dstPort = 0;
    p.protocol = "OTHER";

    // transport parsing (extract first 4 bytes -> src/dst ports for TCP/UDP)
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        p.protocol = "TCP";
        if (h->caplen >= trans_offset + 4) {
            const uint16_t srcp = ntohs(*(const uint16_t *)(bytes + trans_offset));
            const uint16_t dstp = ntohs(*(const uint16_t *)(bytes + trans_offset + 2));
            p.srcPort = (int)srcp;
            p.dstPort = (int)dstp;
        }
    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        p.protocol = "UDP";
        if (h->caplen >= trans_offset + 4) {
            const uint16_t srcp = ntohs(*(const uint16_t *)(bytes + trans_offset));
            const uint16_t dstp = ntohs(*(const uint16_t *)(bytes + trans_offset + 2));
            p.srcPort = (int)srcp;
            p.dstPort = (int)dstp;
        }
    } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        p.protocol = "ICMP";
        p.srcPort = 0;
        p.dstPort = 0;
    }

    // processing pipeline
    Stats::total++;

    int matchedIndex = -1;
    string decision = RuleEngine::decide(p, matchedIndex);

    bool is_susp = IDS::analyze(p);
    if (is_susp) {
        cout << "[IDS] Suspicious activity: " << p.srcIP << "\n";
    }

    if (decision == "ALLOW") {
        cout << "[ALLOW] " << p.protocol << " " << p.srcIP << ":" << p.srcPort
             << " -> " << p.dstIP << ":" << p.dstPort << "\n";
        Stats::allowed++;
    } else {
        cout << "[BLOCK] " << p.protocol << " " << p.srcIP
             << " -> " << p.dstIP << " (Rule idx " << matchedIndex << ")\n";
        Stats::blocked++;
    }

    Logger::logDecision(p, decision, matchedIndex);
}

void PacketCapture::startCapture(const string &iface) {
    cout << "[CAPTURE] Live capture starting on: " << iface << "\n";

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    // snaplen 65535, promisc 1, timeout 1000ms (so pcap_loop remains responsive)
    pcap_t *handle = pcap_open_live(iface.c_str(), 65535, 1, 1000, errbuf);
    if (!handle) {
        cerr << "[CAPTURE] pcap_open_live failed: " << errbuf << "\n";
        return;
    }

    // apply filter for tcp/udp/icmp to reduce noise
    const char *filter_exp = "tcp or udp or icmp";
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);
    }

    // make handle visible to stopCapture()
    g_pcap_handle = handle;
    local_running = true;

    // blocking call - will run callback for each packet until stopCapture() calls pcap_breakloop
    pcap_loop(handle, -1, pcap_packet_cb, nullptr);

    // cleanup
    g_pcap_handle = nullptr;
    pcap_close(handle);
    cout << "[CAPTURE] Capture stopped\n";
}
// ...existing code...
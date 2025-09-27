// Sniffer.cpp
// Responsable: <Nombre> (Módulo Sniffing)

#include "Sniffer.h"
#include <pcap.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <chrono>
#include <thread>

Sniffer::Sniffer(const std::string &target_ip, const std::vector<int> &ports, int header_bytes)
    : ip(target_ip), ports(ports), nbytes(header_bytes), running(false) {}

Sniffer::~Sniffer() {
    stop_capture();
}

void Sniffer::set_header(const std::string &key, const std::string &hex) {
    std::lock_guard<std::mutex> lock(map_mtx);
    if (headers.find(key) == headers.end()) headers[key] = hex;
}

bool Sniffer::get_header(const std::string &key, std::string &hex) {
    std::lock_guard<std::mutex> lock(map_mtx);
    auto it = headers.find(key);
    if (it != headers.end()) { hex = it->second; return true; }
    return false;
}

std::string Sniffer::make_bpf_filter() {
    // Filter: host IP and (tcp or udp) and (port p1 or port p2 ...)
    std::ostringstream oss;
    oss << "host " << ip << " and (tcp or udp)";
    // optionally restrict ports:
    if (!ports.empty()) {
        oss << " and (";
        for (size_t i = 0; i < ports.size(); ++i) {
            if (i) oss << " or ";
            oss << "port " << ports[i];
        }
        oss << ")";
    }
    return oss.str();
}

void Sniffer::pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    // user pointer will be 'this'
    Sniffer *self = reinterpret_cast<Sniffer*>(user);
    if (!self) return;

    // Parse Ethernet header offset (assuming DLT_EN10MB). We'll try to detect IPv4 after 14 bytes.
    const u_char *ip_packet = bytes;
    int offset = 0;
    // If datalink is Ethernet, skip 14 bytes. We can't get dlt here, assume ethernet.
    offset = 14;
    if (h->caplen <= (size_t)offset) return;

    const struct ip *ip_hdr = (struct ip*)(ip_packet + offset);
    if (ip_hdr->ip_v != 4) return;

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    int proto = ip_hdr->ip_p;
    const u_char *transport = ip_packet + offset + ip_hdr_len;

    // dest port and src port extraction
    uint16_t sport = 0, dport = 0;
    std::ostringstream keyoss;
    std::ostringstream hexoss;

    if (proto == IPPROTO_TCP) {
        if ((size_t)(offset + ip_hdr_len + sizeof(struct tcphdr)) > h->caplen) return;
        struct tcphdr *tcp = (struct tcphdr*)transport;
        sport = ntohs(tcp->th_sport);
        dport = ntohs(tcp->th_dport);
        keyoss << inet_ntoa(ip_hdr->ip_src) << ":" << sport << ":TCP"; // packet from src->dst
    } else if (proto == IPPROTO_UDP) {
        if ((size_t)(offset + ip_hdr_len + sizeof(struct udphdr)) > h->caplen) return;
        struct udphdr *udp = (struct udphdr*)transport;
        sport = ntohs(udp->uh_sport);
        dport = ntohs(udp->uh_dport);
        keyoss << inet_ntoa(ip_hdr->ip_src) << ":" << sport << ":UDP";
    } else {
        // other protocols - ignore
        return;
    }

    // We want packets that are responses *from target ip* (ip_src == target ip)
    if (std::string(inet_ntoa(ip_hdr->ip_src)) != self->ip) {
        // Not from target
        return;
    }

    // Build hex for first nbytes of IP + transport header (but ensure we don't go past caplen)
    size_t want = self->nbytes;
    size_t available = h->caplen - offset;
    size_t to_take = std::min(want, available);
    for (size_t i = 0; i < to_take; ++i) {
        hexoss << std::setw(2) << std::setfill('0') << std::uppercase << std::hex << (int) (bytes[offset + i]);
        if (i+1 < to_take) hexoss << " ";
    }

    std::string key = keyoss.str();
    std::string hex = hexoss.str();
    // store only first seen
    {
        std::lock_guard<std::mutex> lock(self->map_mtx);
        if (self->headers.find(key) == self->headers.end()) {
            self->headers[key] = hex;
        }
    }
}

void Sniffer::capture_loop() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = pcap_lookupdev(errbuf);
    if (!dev) {
        std::cerr << "[Sniffer] pcap_lookupdev error: " << errbuf << ". Trying 'any'." << std::endl;
        dev = "any";
    }

    pcap_t *handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "[Sniffer] pcap_open_live failed: " << errbuf << std::endl;
        return;
    }

    std::string filter = make_bpf_filter();
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[Sniffer] pcap_compile failed for filter: " << filter << std::endl;
        pcap_close(handle);
        return;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "[Sniffer] pcap_setfilter failed." << std::endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        return;
    }
    pcap_freecode(&fp);

    // Loop until stopped
    running = true;
    while (running) {
        int ret = pcap_dispatch(handle, 10, (pcap_handler)Sniffer::pcap_callback, (u_char*)this);
        if (ret == -1) {
            std::cerr << "[Sniffer] pcap_dispatch error: " << pcap_geterr(handle) << std::endl;
            break;
        }
        // small sleep to avoid busy loop if no packets
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    pcap_close(handle);
}

bool Sniffer::start_capture() {
    if (running) return true;
    cap_thread = std::thread([this]() { capture_loop(); });
    return true;
}

void Sniffer::stop_capture() {
    if (!running) return;
    running = false;
    if (cap_thread.joinable()) cap_thread.join();
}

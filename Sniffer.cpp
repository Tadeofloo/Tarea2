// Sniffer.cpp
// Responsable: <Tu Nombre y Apellido> (Módulo Sniffing)

#include "Sniffer.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <algorithm> // Para std::min

Sniffer::Sniffer(const std::string &target_ip, const std::vector<int> &ports, int header_bytes)
    : ip(target_ip), ports(ports), nbytes(header_bytes) {}

Sniffer::~Sniffer() {
    stop_capture();
}

void Sniffer::set_header(const std::string &key, const std::string &hex) {
    std::lock_guard<std::mutex> lock(map_mtx);
    if (headers.find(key) == headers.end()) {
        headers[key] = hex;
    }
}

bool Sniffer::get_header(const std::string &key, std::string &hex) {
    std::lock_guard<std::mutex> lock(map_mtx);
    auto it = headers.find(key);
    if (it != headers.end()) {
        hex = it->second;
        return true;
    }
    return false;
}

void Sniffer::add_icmp_unreachable(int port) {
    std::lock_guard<std::mutex> lock(map_mtx);
    icmp_unreachable[port] = true;
}

bool Sniffer::icmp_port_unreachable_received(int port) {
    std::lock_guard<std::mutex> lock(map_mtx);
    return icmp_unreachable.count(port) > 0;
}

std::string Sniffer::make_bpf_filter() {
    std::ostringstream oss;
    oss << "host " << ip << " and (tcp or udp or icmp)";
    return oss.str();
}

void Sniffer::pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    Sniffer *self = reinterpret_cast<Sniffer*>(user);
    if (!self || !self->pcap_handle) return;

    int offset = 0;
    int link_type = pcap_datalink(self->pcap_handle);
    if (link_type == DLT_EN10MB) { offset = 14; }
    else if (link_type == DLT_LINUX_SLL) { offset = 16; }
    else if (link_type == DLT_NULL) { offset = 4; }

    if (h->caplen <= (u_int)offset) return;

    const struct ip *ip_hdr = (struct ip*)(bytes + offset);
    if (ip_hdr->ip_v != 4 || std::string(inet_ntoa(ip_hdr->ip_src)) != self->ip) {
        return;
    }

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    const u_char *transport = bytes + offset + ip_hdr_len;

    if (ip_hdr->ip_p == IPPROTO_TCP || ip_hdr->ip_p == IPPROTO_UDP) {
        uint16_t sport = 0;
        std::ostringstream keyoss, hexoss;

        if (ip_hdr->ip_p == IPPROTO_TCP) {
            if ((size_t)(offset + ip_hdr_len + sizeof(struct tcphdr)) > h->caplen) return;
            sport = ntohs(((struct tcphdr*)transport)->th_sport);
            keyoss << inet_ntoa(ip_hdr->ip_src) << ":" << sport << ":TCP";
        } else { // UDP
            if ((size_t)(offset + ip_hdr_len + sizeof(struct udphdr)) > h->caplen) return;
            sport = ntohs(((struct udphdr*)transport)->uh_sport);
            keyoss << inet_ntoa(ip_hdr->ip_src) << ":" << sport << ":UDP";
        }

        size_t to_take = std::min((size_t)self->nbytes, (size_t)(h->caplen - offset));
        for (size_t i = 0; i < to_take; ++i) {
            hexoss << std::setw(2) << std::setfill('0') << std::uppercase << std::hex << (int)(bytes[offset + i]);
            if (i + 1 < to_take) hexoss << " ";
        }
        self->set_header(keyoss.str(), hexoss.str());
    } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        const struct icmp* icmp_hdr = (const struct icmp*)transport;
        
        if (icmp_hdr->icmp_type == 3 && icmp_hdr->icmp_code == 3) {
            const struct ip* orig_ip_hdr = (const struct ip*)(transport + 8);
            const u_char* orig_transport_hdr = ((const u_char*)orig_ip_hdr) + (orig_ip_hdr->ip_hl * 4);
            
            // **AQUÍ ESTABA EL ERROR CORREGIDO:**
            // Leemos el puerto DESTINO (offset de 2 bytes) del paquete original, no el fuente.
            uint16_t orig_dport = ntohs(*(uint16_t*)(orig_transport_hdr + 2)); 
            
            self->add_icmp_unreachable(orig_dport);
        }
    }
}

void Sniffer::capture_loop() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = "any";
    
    pcap_handle = pcap_open_live(dev, 65536, 1, 500, errbuf);
    
    if (!pcap_handle) {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) != 0 || !alldevs) {
            std::cerr << "[Sniffer] Error: No se encontraron dispositivos de captura." << std::endl;
            return;
        }
        dev = alldevs->name;
        pcap_handle = pcap_open_live(dev, 65536, 1, 500, errbuf);
        pcap_freealldevs(alldevs);
    }
    
    if (!pcap_handle) {
        std::cerr << "[Sniffer] Error: No se pudo abrir un dispositivo de captura." << std::endl;
        return;
    }
    
    std::cout << "[Sniffer] Escuchando en el dispositivo: " << dev << std::endl;

    std::string filter = make_bpf_filter();
    struct bpf_program fp;
    if (pcap_compile(pcap_handle, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[Sniffer] pcap_compile failed: " << pcap_geterr(pcap_handle) << std::endl;
        pcap_close(pcap_handle);
        return;
    }
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        std::cerr << "[Sniffer] pcap_setfilter failed: " << pcap_geterr(pcap_handle) << std::endl;
        pcap_freecode(&fp);
        pcap_close(pcap_handle);
        return;
    }
    pcap_freecode(&fp);

    running = true;
    pcap_loop(pcap_handle, -1, Sniffer::pcap_callback, (u_char*)this);

    pcap_close(pcap_handle);
    pcap_handle = nullptr;
}

bool Sniffer::start_capture() {
    if (running) return true;
    cap_thread = std::thread([this]() { capture_loop(); });
    return true;
}

void Sniffer::stop_capture() {
    if (running) {
        running = false;
        if (pcap_handle) {
            pcap_breakloop(pcap_handle);
        }
    }
    if (cap_thread.joinable()) {
        cap_thread.join();
    }
}
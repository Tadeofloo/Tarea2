// Sniffer.h
// Responsable: <Tu Nombre y Apellido> (Módulo Sniffing)

#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <pcap.h>

class Sniffer {
public:
    Sniffer(const std::string &target_ip, const std::vector<int> &ports, int header_bytes = 16);
    ~Sniffer();
    bool start_capture();
    void stop_capture();
    bool get_header(const std::string &key, std::string &hex);
    bool icmp_port_unreachable_received(int port); // Nueva función para ICMP

private:
    std::string ip;
    std::vector<int> ports;
    int nbytes;
    bool running = false;
    pcap_t* pcap_handle = nullptr;
    std::thread cap_thread;
    std::mutex map_mtx;
    std::unordered_map<std::string, std::string> headers;
    std::unordered_map<int, bool> icmp_unreachable; // Para rastrear respuestas ICMP

    void capture_loop();
    std::string make_bpf_filter();
    void set_header(const std::string &key, const std::string &hex);
    void add_icmp_unreachable(int port);
    static void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
};

#endif // SNIFFER_H
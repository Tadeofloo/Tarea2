// Sniffer.h
// Responsable: <Nombre> (Módulo Sniffing)

#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <thread>

class Sniffer {
public:
    Sniffer(const std::string &target_ip, const std::vector<int> &ports, int header_bytes = 16);
    ~Sniffer();
    bool start_capture(); // lanza captura en hilo
    void stop_capture();
    // Consulta y seteo thread-safe de header bytes: key = ip:port:proto
    void set_header(const std::string &key, const std::string &hex);
    bool get_header(const std::string &key, std::string &hex);

private:
    std::string ip;
    std::vector<int> ports;
    int nbytes;
    bool running;
    std::thread cap_thread;
    std::mutex map_mtx;
    std::unordered_map<std::string, std::string> headers;

    void capture_loop();
    std::string make_bpf_filter();
    static void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
};

#endif // SNIFFER_H

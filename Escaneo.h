// Escaneo.h
// Responsable: <Nombre> (Módulo Escaneo)

#ifndef ESCANEO_H
#define ESCANEO_H

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

struct ScanResult {
    std::string ip;
    int port;
    std::string protocol; // "TCP" o "UDP"
    std::string state;    // "Abierto", "Cerrado", "Filtrado"
    std::string service;  // estimado (puede ser vacío)
    std::string header_bytes; // rellenado por Sniffer si hay captura
};

class Escaneo {
public:
    Escaneo(const std::string &target_ip, const std::vector<int> &ports, int timeout_ms);
    void run(); // Ejecuta el escaneo TCP y UDP
    std::vector<ScanResult> get_results();

private:
    std::string ip;
    std::vector<int> ports;
    int timeout;
    std::vector<ScanResult> results;
    std::mutex results_mtx;

    void scan_tcp(int port);
    void scan_udp(int port);
    void add_result(const ScanResult &r);
    std::string guess_service(int port, const std::string &proto);
};

#endif // ESCANEO_H

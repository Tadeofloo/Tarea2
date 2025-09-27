// main.cpp
// Responsable: <Nombre> (Orquestación)

#include "Escaneo.h"
#include "Sniffer.h"
#include "JSONGen.h"

#include <iostream>
#include <sstream>
#include <thread>
#include <chrono>
#include <algorithm>
#include <set>
#include <limits>

// helper parse ports: range "20-1024" or comma list "22,80,443"
std::vector<int> parse_ports(const std::string &s) {
    std::set<int> ports;
    if (s.find('-') != std::string::npos) {
        int a, b;
        char dash;
        std::istringstream iss(s);
        if (iss >> a >> dash >> b && dash == '-') {
            if (a > b) std::swap(a,b);
            for (int p = a; p <= b; ++p) ports.insert(p);
        }
    } else {
        std::istringstream iss(s);
        std::string token;
        while (std::getline(iss, token, ',')) {
            try {
                int p = std::stoi(token);
                ports.insert(p);
            } catch (...) {}
        }
    }
    return std::vector<int>(ports.begin(), ports.end());
}

int main() {
    std::string ip;
    std::string ports_input;
    int timeout_ms;
    std::string outfile;

    std::cout << "IP objetivo: ";
    std::getline(std::cin, ip);
    std::cout << "Puertos (rango p.e. 20-1024 o lista 22,80,443): ";
    std::getline(std::cin, ports_input);
    std::cout << "Timeout en ms (ej. 500): ";
    std::cin >> timeout_ms;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cout << "Archivo JSON de salida (ej. resultado.json): ";
    std::getline(std::cin, outfile);

    auto ports = parse_ports(ports_input);
    if (ports.empty()) {
        std::cerr << "No se detectaron puertos válidos." << std::endl;
        return 1;
    }

    // Crear Sniffer y arrancar captura
    Sniffer sniffer(ip, ports, 16);
    if (!sniffer.start_capture()) {
        std::cerr << "No se pudo iniciar sniffer." << std::endl;
    } else {
        std::cout << "[main] Sniffer iniciado." << std::endl;
    }

    // Ejecutar escaneo (bloqueante, spawnea hilos internos)
    Escaneo esc(ip, ports, timeout_ms);
    std::cout << "[main] Iniciando escaneo..." << std::endl;
    esc.run();
    std::cout << "[main] Escaneo finalizado." << std::endl;

    // Recoger resultados y complementar con capturas (si existen)
    auto results = esc.get_results();
    for (auto &r : results) {
        // intentar encontrar header bytes en sniffer:
        std::ostringstream key;
        // buscar paquete *from target ip* con source port = puerto -> la sniffer guarda como src:port:PROTO
        key.str(""); key.clear();
        key << ip << ":" << r.port << ":" << r.protocol;
        std::string hex;
        if (sniffer.get_header(key.str(), hex)) {
            r.header_bytes = hex;
            // marcar abierto si no se detectó antes
            if (r.state == "Filtrado" || r.state == "Filtrado/Cerrado") {
                r.state = "Abierto (captura)";
            }
        }
    }

    // detener sniffer
    sniffer.stop_capture();
    std::cout << "[main] Sniffer detenido." << std::endl;

    // Generar JSON
    JSONGen jgen(outfile);
    if (jgen.write(results)) {
        std::cout << "Archivo JSON generado en: " << outfile << std::endl;
    } else {
        std::cout << "Error al generar JSON." << std::endl;
    }

    // Mostrar resumen en consola
    for (const auto &r : results) {
        std::cout << r.protocol << " " << r.port << " -> " << r.state;
        if (!r.service.empty()) std::cout << " (" << r.service << ")";
        if (!r.header_bytes.empty()) std::cout << " | header: " << r.header_bytes;
        std::cout << std::endl;
    }

    return 0;
}

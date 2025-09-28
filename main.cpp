// main.cpp
// Responsable: <Tu Nombre y Apellido> (Orquestación)

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

    Sniffer sniffer(ip, ports, 16);
    if (!sniffer.start_capture()) {
        std::cerr << "No se pudo iniciar sniffer." << std::endl;
    } else {
        std::cout << "[main] Sniffer iniciado." << std::endl;
    }

    // Pequeña pausa para asegurar que el sniffer esté listo
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    Escaneo esc(ip, ports, timeout_ms);
    std::cout << "[main] Iniciando escaneo..." << std::endl;
    esc.run();
    std::cout << "[main] Escaneo finalizado." << std::endl;

    // Pequeña pausa para capturar paquetes de respuesta tardíos
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    sniffer.stop_capture();
    std::cout << "[main] Sniffer detenido." << std::endl;
    
    auto results = esc.get_results();
    for (auto &r : results) {
        std::ostringstream key;
        key << ip << ":" << r.port << ":" << r.protocol;
        std::string hex;
        if (sniffer.get_header(key.str(), hex)) {
            r.header_bytes = hex;
            if (r.state != "Abierto") {
                r.state = "Abierto (captura)";
            }
        } 
        // MODIFICADO: Lógica para UDP usando ICMP
        else if (r.protocol == "UDP" && sniffer.icmp_port_unreachable_received(r.port)) {
            r.state = "Cerrado";
        }
    }

    JSONGen jgen(outfile);
    if (jgen.write(results)) {
        std::cout << "Archivo JSON generado en: " << outfile << std::endl;
    } else {
        std::cout << "Error al generar JSON." << std::endl;
    }

    for (const auto &r : results) {
        std::cout << r.protocol << " " << r.port << " -> " << r.state;
        if (!r.service.empty()) std::cout << " (" << r.service << ")";
        if (!r.header_bytes.empty()) std::cout << " | header: " << r.header_bytes;
        std::cout << std::endl;
    }

    return 0;
}
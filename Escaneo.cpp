// Escaneo.cpp
// Responsable: <Nombre> (Módulo Escaneo)

#include "Escaneo.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <thread>

Escaneo::Escaneo(const std::string &target_ip, const std::vector<int> &ports, int timeout_ms)
    : ip(target_ip), ports(ports), timeout(timeout_ms) {}

void Escaneo::add_result(const ScanResult &r) {
    std::lock_guard<std::mutex> lock(results_mtx);
    results.push_back(r);
}

std::vector<ScanResult> Escaneo::get_results() {
    std::lock_guard<std::mutex> lock(results_mtx);
    return results;
}

std::string Escaneo::guess_service(int port, const std::string &proto) {
    // lista simple de puertos comunes (puedes ampliar)
    if (proto == "TCP") {
        if (port == 22) return "ssh";
        if (port == 80) return "http";
        if (port == 443) return "https";
        if (port == 21) return "ftp";
        if (port == 25) return "smtp";
    } else {
        if (port == 53) return "dns";
        if (port == 161) return "snmp";
    }
    return "";
}

void Escaneo::scan_tcp(int port) {
    ScanResult r;
    r.ip = ip;
    r.port = port;
    r.protocol = "TCP";
    r.service = guess_service(port, "TCP");
    r.header_bytes = "";

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        r.state = "Error socket";
        add_result(r);
        return;
    }

    // non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    int conn = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (conn == 0) {
        // Conexión inmediata (raro)
        r.state = "Abierto";
        close(sock);
        add_result(r);
        return;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);

    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    int sel = select(sock + 1, NULL, &wfds, NULL, &tv);
    if (sel > 0 && FD_ISSET(sock, &wfds)) {
        // comprobar errores en socket
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            r.state = "Abierto";
        } else {
            if (so_error == ECONNREFUSED) r.state = "Cerrado";
            else r.state = "Cerrado";
        }
    } else if (sel == 0) {
        r.state = "Filtrado";
    } else {
        r.state = "Error select";
    }

    close(sock);
    add_result(r);
}

void Escaneo::scan_udp(int port) {
    ScanResult r;
    r.ip = ip;
    r.port = port;
    r.protocol = "UDP";
    r.service = guess_service(port, "UDP");
    r.header_bytes = "";

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        r.state = "Error socket";
        add_result(r);
        return;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    // enviar datagrama vacío
    ssize_t sent = sendto(sock, nullptr, 0, 0, (struct sockaddr*)&addr, sizeof(addr));
    if (sent < 0) {
        r.state = "Error sendto";
        close(sock);
        add_result(r);
        return;
    }

    // No esperamos respuesta por este socket (puede llegar por sniffer).
    // Para simplificar: esperamos el timeout localmente para marcar como "Filtrado/Cerrado" si no hay captura.
    // Sniffer debe llenar header_bytes si llega respuesta.
    std::this_thread::sleep_for(std::chrono::milliseconds(timeout));

    // Por ahora, dejamos como "Filtrado/Cerrado" — el Sniffer puede sobrescribir header_bytes después.
    r.state = "Filtrado/Cerrado";
    close(sock);
    add_result(r);
}

void Escaneo::run() {
    // Para optimizar, correr threads por puerto (limitado si son muchos puertos).
    std::vector<std::thread> threads;
    for (int p : ports) {
        // Crea una tarea que haga TCP y UDP
        threads.emplace_back([this, p]() {
            this->scan_tcp(p);
        });
        threads.emplace_back([this, p]() {
            this->scan_udp(p);
        });
    }

    for (auto &t : threads) if (t.joinable()) t.join();
}

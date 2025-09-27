// JSONGen.cpp
// Responsable: <Nombre> (Módulo JSONGen)

#include "JSONGen.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>

using json = nlohmann::json;

JSONGen::JSONGen(const std::string &filename) : fname(filename) {}

bool JSONGen::write(const std::vector<ScanResult> &results) {
    json arr = json::array();

    for (const auto &r : results) {
        json obj;
        obj["ip"] = r.ip;
        obj["port"] = r.port;
        obj["protocol"] = r.protocol;
        obj["service"] = r.service;
        obj["state"] = r.state;
        if (!r.header_bytes.empty()) obj["header_bytes"] = r.header_bytes;
        else obj["header_bytes"] = json::value_t::null;
        arr.push_back(obj);
    }

    std::ofstream ofs(fname);
    if (!ofs.is_open()) {
        std::cerr << "[JSONGen] No se pudo abrir " << fname << " para escribir." << std::endl;
        return false;
    }
    ofs << std::setw(2) << arr << std::endl;
    ofs.close();
    return true;
}

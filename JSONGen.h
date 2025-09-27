// JSONGen.h
// Responsable: <Nombre> (Módulo JSONGen)

#ifndef JSONGEN_H
#define JSONGEN_H

#include "Escaneo.h"
#include <string>
#include <vector>

class JSONGen {
public:
    JSONGen(const std::string &filename);
    bool write(const std::vector<ScanResult> &results);
private:
    std::string fname;
};

#endif // JSONGEN_H

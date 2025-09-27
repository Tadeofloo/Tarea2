# Proyecto: Escáner híbrido de puertos y sniffing en C++

## Descripción
Herramienta en C++ (Linux) que realiza escaneo real de puertos TCP y UDP, captura la primera trama de respuesta mediante libpcap y genera un informe JSON con servicios detectados y primeros bytes de cabecera.

## Estructura
- `main.cpp` — Orquestación.
- `Escaneo.cpp/h` — Lógica de escaneo TCP/UDP.
- `Sniffer.cpp/h` — Captura con libpcap y filtrado BPF.
- `JSONGen.cpp/h` — Serialización JSON (nlohmann/json).
- `resultado.json` — Ejemplo de salida.

## Requisitos
- Sistema: Linux (Ubuntu/Debian recomendado).
- Compilador: g++ (soporte C++17).
- Dependencias:
  - libpcap (instalar: `sudo apt-get install libpcap-dev`)
  - nlohmann/json (header-only). Puedes instalarlo o descargar `json.hpp`:
    - Opción apt: `sudo apt-get install nlohmann-json3-dev`
    - Opción manual: descargar `json.hpp` y ponerlo en include path.

## Compilación
```bash
g++ -std=c++17 main.cpp Escaneo.cpp Sniffer.cpp JSONGen.cpp -o escaner_hibrido -lpcap -pthread
```

## Ejecución (ejemplo)
```bash
sudo ./escaner_hibrido
# Se pedirán:
# IP objetivo: 192.168.1.100
# Puertos: 20-1024
# Timeout en ms: 500
# Archivo JSON: resultado.json
```

> Nota: se recomienda ejecutar con `sudo` para que libpcap pueda abrir interfaces en modo promiscuo.

## Notas técnicas y limitaciones
- El módulo TCP usa sockets no bloqueantes + `select()` para manejar timeout.
- El módulo UDP envía datagramas vacíos; la detección de respuestas UDP depende de la captura por sniffer (si el servicio responde). Si no hay respuesta, el programa marca `Filtrado/Cerrado`. Detectar ICMP "port unreachable" es posible pero requiere parseo adicional del payload; la implementación actual utiliza la captura de libpcap para detectar respuestas que permitan marcar el puerto como abierto.
- El Sniffer abre la primera interfaz que `pcap_lookupdev` retorna (o `any`) y aplica un filtro BPF: `host <IP> and (tcp or udp) and (port p1 or port p2 ...)`.
- El Sniffer almacena los **primeros 16 bytes** de la trama IP/transport para la primera respuesta por puerto/protocolo.
- Para pruebas locales en máquina propia, evita escanear hosts remotos sin permiso.

## Entregables
- Código fuente (los .cpp/.h).
- `resultado.json` (salida de ejemplo).
- README.md
- Indicar en el repo los integrantes y el módulo responsable (en comentarios de cada archivo hay placeholders).

## Mejoras futuras (sugeridas)
- Parseo de ICMP para distinguir cerrados vs filtrados en UDP.
- Límite de concurrencia (pool de hilos).
- Mejor reconocimiento de servicios vía banner grabado (lectura más profunda de payload).

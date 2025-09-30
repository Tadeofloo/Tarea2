# Proyecto: Escáner Híbrido de Puertos y Sniffing en C++

## Descripción General

Herramienta de línea de comandos para Linux, desarrollada en C++ (C++17), que realiza un escaneo de puertos TCP y UDP sobre un host objetivo. El programa integra un sniffer de red pasivo utilizando **libpcap** para capturar y analizar las respuestas de los puertos. Al finalizar, genera un informe detallado en formato **JSON** que incluye el estado de cada puerto, el servicio estimado y los primeros 16 bytes de la cabecera de la primera trama de respuesta capturada para los puertos abiertos.

---

## Integrantes del Equipo

- Andres Tadeo Flores Pinal - Módulo Sniffing
- Tadeo Floo - Módulo Escaneo
- Tadeo Floo - Módulo JSONGen


---

## Requisitos

- **Sistema Operativo:** Linux (probado en Ubuntu/Debian).
- **Compilador:** `g++` con soporte para C++17.

### Dependencias

- `libpcap-dev` — Biblioteca para la captura de paquetes.
- `nlohmann/json` — Biblioteca header-only para la manipulación de JSON (archivo `json.hpp` incluido en el proyecto).

Instalación de dependencias:

```bash
sudo apt-get update && sudo apt-get install g++ libpcap-dev
```

Si vas a usar `nlohmann/json` vía paquete del sistema (opcional):

```bash
sudo apt-get install nlohmann-json3-dev
```

---

## Estructura de Archivos Sugerida

```
escaner_hibrido/
├── include/
│   └── json.hpp                 # nlohmann::json (header-only) opcional
├── src/
│   ├── main.cpp
│   ├── Escaneo.cpp
│   ├── Escaneo.h
│   ├── Sniffer.cpp
│   ├── Sniffer.h
│   ├── JSONGen.cpp
│   └── JSONGen.h
├── Makefile                     # Opcional
├── resultado_ejemplo.json       # Ejemplo de salida
└── README.md
```

---

## Compilación

Navega a la carpeta `src` (o al root si usas rutas relativas) y compila con:

```bash
g++ -std=c++17 main.cpp Escaneo.cpp Sniffer.cpp JSONGen.cpp -o escaner_hibrido -lpcap -pthread
```

Si usas headers en `include/`, ajusta `-I../include` o usa un `Makefile`.

---

## Ejecución

> **Requisito:** Se requiere privilegios de superusuario para que libpcap ponga la interfaz en modo promiscuo.

```bash
sudo ./escaner_hibrido
```

El programa pedirá interactivamente:

- **IP objetivo:** (ej. `127.0.1.1`)
- **Puertos:** Rango (`20-1024`) o lista separada por comas (`22,80,443`)
- **Timeout en ms:** (ej. `500`)
- **Archivo JSON de salida:** Nombre de archivo (ej. `resultado.json`)

---

## Lógica y Enfoque Técnico (Resumen)

### Módulo de Escaneo (`Escaneo.cpp`)

- **TCP:** Sockets no bloqueantes y `select()` para timeouts.
  - **Abierto:** Conexión establecida.
  - **Cerrado:** Respuesta RST.
  - **Filtrado:** Timeout sin respuesta.

- **UDP:** Envía datagrama vacío y marca estado provisional como `Filtrado/Cerrado`. El sniffer confirmará estado posteriormente.

- Para rendimiento, se usan hilos: por cada puerto se lanzan dos tareas (TCP y UDP) o un grupo de workers con una cola.

### Módulo de Sniffing (`Sniffer.cpp`)

- Usa `libpcap` y escucha en la interfaz `any` por defecto para capturar tráfico local y externo.
- Aplica un filtro BPF: `host <IP> and (tcp or udp or icmp)`.
- Reglas de interpretación UDP/ICMP:
  - Si se captura un paquete UDP proveniente del puerto objetivo → Puerto **Abierto**.
  - Si se captura ICMP "Port Unreachable" → Puerto **Cerrado**.
  - Si no se captura nada → **Filtrado/Cerrado**.
- Para cada puerto que responda, se guardan los primeros **16 bytes** de la cabecera en hexadecimal.

### Concurrencia

- El sniffer corre en su propio hilo y va informando al orquestador (cola o estructura compartida protegida por mutex) sobre respuestas observadas.
- El escaneo lanza hilos para las sondas (o usa un thread pool) y consulta el estado final en la estructura compartida.

---

## Formato JSON de Salida

El archivo contiene un array de objetos — cada objeto representa el resultado de un puerto.

Ejemplo (`resultado.json`):

```json
[
  {
    "header_bytes": "45 00 00 3C 00 00 40 00 40 06 3B BA 7F 00 01 01",
    "ip": "127.0.1.1",
    "port": 8080,
    "protocol": "TCP",
    "service": "",
    "state": "Abierto"
  },
  {
    "header_bytes": null,
    "ip": "127.0.1.1",
    "port": 80,
    "protocol": "UDP",
    "service": "",
    "state": "Cerrado"
  }
]
```

---


## Seguridad y Consideraciones Legales

- **Solo escanea hosts sobre los que tengas permiso explícito.** El escaneo de puertos y la captura de tráfico pueden considerarse intrusivos y, en muchos lugares, ilegales sin autorización.
- Evita ejecutar esta herramienta en redes corporativas o de terceros sin consentimiento.

---

## Posibles Mejoras

- Añadir un thread pool para limitar la concurrencia.
- Implementar reintentos y backoff.
- Detección y mapeo de servicios (`service fingerprinting`) usando banners y/o nmap-like probes.
- Guardar también timestamps y metadatos de la interfaz en el JSON.
- Soporte para IPv6.


---

## Contacto

Para dudas o mejoras, abre un issue en el repositorio o contacta al equipo del proyecto.


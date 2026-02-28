# DNS Expert Monitor

![Version](https://img.shields.io/badge/version-0.2.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Security](https://img.shields.io/badge/security-detection-red)

**DNS Expert Monitor** es una herramienta avanzada de monitoreo y análisis de tráfico DNS con detección proactiva de amenazas de seguridad. Diseñada para profesionales de seguridad, administradores de sistemas y analistas forenses.

---

## 📋 Tabla de Contenidos
- [Características Principales](#-características-principales)
- [Instalación](#-instalación)
- [Uso Rápido](#-uso-rápido)
- [Comandos Detallados](#-comandos-detallados)
- [Sistema de Reportes](#-sistema-de-reportes-profesionales)
- [Exportación Multiformato](#-exportación-multiformato)
- [Detectores de Seguridad](#detectores-de-seguridad)
- [Utilidades y Mantenimiento](#-utilidades-y-mantenimiento)
- [Flujos de Trabajo](#-flujos-de-trabajo-recomendados)
- [Solución de Problemas](#-solución-de-problemas-comunes)
- [Arquitectura](#arquitectura)
- [Contribuir](#-contribuir)

---

## 🎯 Características Principales

### 🔍 Monitoreo en Tiempo Real
| Característica | Descripción |
|----------------|-------------|
| 📡 Captura DNS | Captura de tráfico DNS en interfaces de red |
| 📊 Estadísticas | QPS, top dominios, clientes únicos en tiempo real |
| 🌍 Multiplataforma | Linux, Windows, macOS (con Npcap/libpcap) |
| 🎨 CLI Moderna | Interfaz interactiva con Rich |

### 🛡️ Detección de Amenazas DNS

<details>
<summary><b>📌 DNS Tunneling</b> - Exfiltración de datos vía DNS</summary>

- 🔴 Alta entropía en nombres de dominio (>4.5)
- 🔴 Patrones Base64/Hexadecimal
- 🔴 Subdominios anormalmente largos (>50 chars)
- 🔴 Tipos de registro sospechosos (TXT, NULL, KEY, OPT)
</details>

<details>
<summary><b>⚠️ DNS Poisoning</b> - Envenenamiento de caché</summary>

- 🟡 TTL anormalmente bajos (<30s)
- 🟡 Múltiples respuestas diferentes para misma consulta
- 🟡 Servidores DNS no autorizados
</details>

<details>
<summary><b>🚨 Amplificación DDoS</b> - Ataques de amplificación</summary>

- 🟠 Altos ratios respuesta/consulta (>10x)
- 🟠 Tasas de consulta anómalas (>100 QPS)
- 🟠 Consultas excesivas de tipo ANY
</details>

<details>
<summary><b>📌 Ataques NXDOMAIN</b> - Inundación de dominios inexistentes</summary>

- 🔵 Alto porcentaje de respuestas NXDOMAIN (>30%)
- 🔵 Tasas elevadas de NXDOMAIN por minuto (>100)
- 🔵 Subdominios aleatorios generados automáticamente
</details>

### 📊 Análisis y Reportes
- 📈 **Reportes ejecutivos** con hallazgos críticos
- 📋 **Exportación multiformato**: HTML, JSON, CSV, YAML, PCAP
- 🏷️ **Clasificación por severidad**: CRITICAL, HIGH, MEDIUM, LOW, INFO
- 🔍 **Evidencia detallada** de cada detección
- 💡 **Recomendaciones accionables** para mitigación

---

## 🚀 Instalación

### 📦 Desde fuente (recomendado)
```
git clone https://github.com/augustozarate/dns-expert-monitor.git
cd dns-expert-monitor
pip install -e .
```

# 🐧 Linux (Debian/Ubuntu)
## Dependencias del sistema
```
sudo apt-get install libpcap-dev
```

## Dependencias Python (mínimas)
```
pip install -r requirements.txt
```
### or
```
pip install scapy>=2.5.0 rich>=13.0.0 click>=8.1.0 netifaces>=0.11.0 pyyaml>=6.0
```

## Para análisis y visualización (opcional)
```
pip install pandas matplotlib numpy
```

## 🍎 macOS
```
brew install libpcap
pip install -e .
```

## 🪟 Windows
- 1. Instalar Npcap (NO WinPcap) en modo "WinPcap API-compatible Mode"
- 2. Instalar Python 3.8+
- 3. `pip install -e .`

---

# 🔧 Configuración de Permisos (Linux)
## Usar sudo (recomendado para pruebas)
```
sudo python run.py monitor
```
---

# ⚡ Uso Rápido
## Verificar instalación

## Mostrar interfaces disponibles
```
dns-expert interfaces
```
### or
```
python run.py interfaces
```

## Modo prueba (sin tráfico real)
```
sudo python run.py test --duration 10
```

# Primera captura
## Análisis rápido de 30 segundos
```
sudo python run.py quick --duration 30
```

## Monitoreo con detección de seguridad
```
sudo python run.py monitor --security
```

# Generar reporte
## Reporte en Markdown (legible)
```
python run.py report captura.json --output informe.md
```
## Reporte en JSON (procesable)
```
dns-expert report captura.json --format json --output informe.json
or
python run.py report captura.json --format json --output informe.json
```
---

# 📚 Comandos Detallados
## 🎯 Monitoreo y Captura
| Comando	| Descripción	| Ejemplo |
|---------|-------------|---------|
| monitor |	Captura continua hasta Ctrl+C |	`sudo python run.py monitor --security` |
| quick	| Captura por tiempo definido |	`sudo python run.py quick --duration 60` |
| test | Simula tráfico sin red |	`sudo python run.py test --duration 20` |

## Opciones disponibles:

| Opción | Descripción | Por Defecto |
|--------|-------------|-------------|
| `--duration` | Segundos de captura | 10 |
| `-i, --interface` |	Interfaz de red | auto-detectada |
| `-o, --output` | Guardar captura en JSON | None |
| `-s, --security` | Habilitar detectores | False |
| `-c, --config` | Archivo de configuración |	None |
| `-v, --verbose` | Mostrar actividad en tiempo real | False |

## Ejemplos completos
```
sudo python run.py monitor --security --verbose --output captura.json -i eth0
sudo python run.py quick --duration 120 --security --output analisis.json
sudo python run.py monitor --config config/detectors.yaml
```

### ⚡ Comando Quick (Análisis Rápido)

## Uso básico
```
sudo python run.py quick --duration 30
```
## Con detección de seguridad
```
sudo python run.py quick --duration 120 --security
```
## Guardar captura
```
sudo python run.py quick --duration 60 --security --output analisis.json
```
## Modo detallado
```
sudo python run.py quick --duration 30 --security --verbose
```
## Especificar interfaz
```
sudo python run.py quick -i eth0 --duration 30 --security
```

# 📊 Reportes y Análisis
| Comando |	Descripción |	Ejemplo |
|---------|-------------|---------|
| report |	Genera reporte de seguridad	| `dns-expert report captura.json` |
| export |	Exporta a múltiples formatos |	`dns-expert export captura.json --format all` |

## Opciones de reporte:

`-o, --output` - Archivo de salida

`-f, --format` - `md` (default) o `json`

## Formatos de reporte
```
dns-expert report captura.json --output informe.md     # Markdown
or
python run.py report captura.json --output informe.md   # Markdown

dns-expert report captura.json --format json           # JSON
or
python run.py report captura.json --format json        # JSON
```

## 🔧 Utilidades

| Comando |	Descripción |	Ejemplo |
|---------|-------------|---------|
| `interfaces` | Lista interfaces disponibles | `dns-expert interfaces` |
| `fix-json` | Repara archivos JSON corruptos |	`dns-expert fix-json captura.json` |
| `version` |	Muestra versión |	`python run.py version` |

## Opciones fix-json:

- `--diagnostic` - Solo diagnosticar

- `--force` - Métodos agresivos

- `--no-backup` - Sin backup automático

---

# 📋 Sistema de Reportes Profesionales
## 🏗️ Estructura del Reporte
```
📊 DNS Security Analysis Report
├── 📋 Executive Summary
│   └── Resumen ejecutivo de hallazgos críticos
├── 📈 Analysis Statistics
│   ├── Período analizado
│   ├── Volumen de tráfico
│   └── Métricas de rendimiento
├── 🚨 Security Findings
│   ├── 🔴 CRITICAL (0)
│   ├── 🟠 HIGH (32)
│   ├── 🟡 MEDIUM (51)
│   ├── 🔵 LOW (0)
│   └── ⚪ INFO (0)
└── 📋 Recommendations
    ├── Acciones inmediatas
    ├── Mejoras a corto plazo
    └── Estrategia a largo plazo
```
---

## 📄 Ejemplo de Reporte (Markdown)
```
# DNS Security Analysis Report
Generated: 2026-02-11 16:19:05

## Executive Summary
🚨 **CRITICAL FINDINGS DETECTED**: 32 high/critical security issues found.

## Key Statistics
- **Analysis Period**: 2m 4s
- **Total Packets**: 266
- **DNS Queries**: 142
- **DNS Responses**: 124
- **Unique Clients**: 3
- **Unique Domains**: 31
- **Average QPS**: 1.14

## Security Findings
### 🟠 HIGH Severity Findings (32)
#### Possible DNS Tunneling Detected
- **Domain**: y1apecughjwuye2qgbhxw9d0arnb2t.example.com
- **Entropy**: 4.52
- **Client**: 192.168.xxx.xxx
- **Recommendation**: Investigate source IP, block suspicious domains
```
---

# 📤 Exportación Multiformato
## 🎯 Formatos Soportados

| Formato |	Extensión |	Uso Principal |	Comando	Estado |
|---------|-----------|---------------|----------------|
| HTML | .html | Dashboard interactivo, informes visuales | --format html |	✅ |
| JSON | .json | Procesamiento programático, APIs |	--format json |	✅ |
| CSV	| .csv | Excel, Google Sheets, análisis estadístico	| --format csv |	✅ |
| YAML | .yaml | Configuraciones, documentación	| --format yaml	| ✅ |
| PCAP | .pcap | Wireshark, análisis forense | --format pcap	| ✅ |
| ALL | - |	Todos los formatos simultáneamente | --format all	| ✅ |

## 📊 Dashboard HTML
## El reporte HTML incluye:

<div align="center"> <table> <tr> <td>📊 Estadísticas en tiempo real</td> <td>🏆 Top dominios consultados</td> </tr> <tr> <td>🛡️ Alertas de seguridad destacadas</td> <td>📋 Actividad reciente</td> </tr> <tr> <td colspan="2">📈 Gráficos de tráfico y distribución</td> </tr> </table> </div>

## 💻 Ejemplos de Exportación
## Dashboard interactivo
```
dns-expert export captura.json --format html
```
## Genera: captura.html

## Análisis forense con Wireshark
```
dns-expert export captura.json --format pcap
```
## Genera: captura.pcap

## Análisis estadístico en Excel
```
dns-expert export captura.json --format csv
```
## Genera: captura.csv

## Exportación completa (todos los formatos)
```
dns-expert export captura.json --format all
```
## Genera: captura.json, .csv, .html, .yaml, .pcap

---

# Detectores de Seguridad

1. 🚨 DNS Tunneling Detector 
- **DNS Tunneling 🛡️**: Detección de exfiltración de datos
- Alta entropía en nombres de dominio
- Patrones Base64/Hexadecimal
- Subdominios anormalmente largos
- Tipos de registro sospechosos (TXT, NULL, KEY)

| Parámetro | Umbral | Descripción |
|-----------|--------|-------------|
| Entropía | > 4.5 | Dominios con alta aleatoriedad |
| Longitud | > 50 chars | Subdominios excesivamente largos |
| Patrones | Base64/Hex | Codificación de datos |
| Tipos | TXT, NULL, KEY | Registros inusuales |

Ejemplo detección:
```
🚨 ALERTA: Alta entropía (4.62) en dominio: 23pzgde427i3ln7qmkdr986h4snnkt.example.com
```

2. ⚠️ DNS Poisoning Detector
- **DNS Poisoning 🛡️**: Protección contra envenenamiento de cache
- TTL anormalmente bajos (<30s)
- Múltiples respuestas diferentes para la misma consulta
- Servidores DNS no autorizados

| Parámetro | Umbral | Descripción |
|-----------|--------|-------------|
| TTL |	< 30s |	Respuestas con TTL anormalmente bajo |
| Respuestas | > 2 | Múltiples respuestas diferentes |
| Servidores |	No autorizados | Respuestas de fuentes no confiables |

Ejemplo detección:
```
⚠️ ADVERTENCIA: TTL anormalmente bajo (5s) para main.vscode-cdn.net
```

3. 🟠 Amplification Detector
- **Amplificación DDoS 🛡️**: Detección de ataques de amplificación
- Altos ratios respuesta/consulta (>10x)
- Tasas de consulta anómalas (>100 QPS)
- Consultas excesivas de tipo ANY

| Parámetro | Umbral | Descripción |
|-----------|--------|-------------|
| Ratio | > 10x | Respuesta mucho mayor que consulta |
| QPS |	> 100 |	Alta tasa de consultas por segundo |
| ANY Queries |	> 50/min | Consultas excesivas de tipo ANY |

Ejemplo detección:
```
⚠️ ADVERTENCIA: Alta tasa de consultas (1183.4 QPS) desde 192.168.xxx.xxx
```

4. 🔵 NXDOMAIN Attack Detector
- **Ataques NXDOMAIN 🛡️**: Detección de inundación
- Alto porcentaje de respuestas NXDOMAIN (>30%)
- Tasas elevadas de NXDOMAIN por minuto
- Subdominios aleatorios generados automáticamente

| Parámetro | Umbral | Descripción |
|-----------|--------|-------------|
| % NXDOMAIN | > 30% | Alto porcentaje de dominios inexistentes |
| Tasa | > 100/min | Muchas respuestas NXDOMAIN por minuto |
| Subdominios |	Aleatorios | Patrones de generación automática |

Ejemplo detección:
```
📊 Análisis del cliente 192.168.xxx.xxx:
   • Nivel sospechoso: high
   • NXDOMAIN responses: 69/min
```

## 📊 Resultados de Detección
```
🔒 RESUMEN DE SEGURIDAD
   Alertas de Seguridad    
 Tipo             Cantidad 
 base64_pattern          8 
 high_query_rate         1 
 low_ttl                 2 
 high_entropy            4 

Detectores activos:
  • tunneling: 12 alertas, 1 cliente sospechoso
  • poisoning: 2 alertas, 1 dominio sospechoso
  • amplification: 1 alerta, tasa anormal detectada
  • nxdomain: 69 NXDOMAIN/min, nivel HIGH
```
---

# 🔧 Utilidades y Mantenimiento
## 🛠️ Reparación de Archivos JSON
Los archivos de captura pueden dañarse si se interrumpe la escritura. DNS Expert Monitor incluye herramientas avanzadas de reparación:
## 1. Diagnosticar problemas
```
dns-expert fix-json --diagnostic captura.json
```
## 2. Reparar automáticamente (recomendado)
```
dns-fix --diagnostic captura.json       # Diagnosticar problemas
```
## 3. Forzar reparación con métodos agresivos
```
dns-fix --force captura.json             # Forzar reparación
```
## 4. Reparar sin backup
```
dns-fix --no-backup captura.json         # Reparar sin backup
```
## 5. Guardar archivo
```
dns-fix captura.json --output nuevo.json # Guardar en otro archivo
```

### Estrategias de reparación:

- ✅ Corrección de comas finales - Elimina comas antes de `]` o `}`
- ✅ Extracción de objetos - Recupera objetos JSON individuales
- ✅ Parser robusto - Múltiples métodos de recuperación
- ✅ Backup automático - Siempre crea .bak antes de modificar

# 🧹 Mantenimiento
## Verificar integridad del JSON
```
python3 -c "import json; json.load(open('captura.json'))" && echo "✅ Válido"
```
## Limpiar backups antiguos
```
rm captura.json.bak.* 2>/dev/null
```
## Comprimir capturas antiguas
```
gzip captura_*.json
```
---

# 🔄 Flujos de Trabajo Recomendados

1. 🚨 Investigación de Incidentes
## Captura enfocada (60 segundos)
```
sudo python run.py quick --duration 60 --output incident.json
```
## Análisis inmediato
```
dns-expert report incident.json --output incident_report.md
```
### or
```
python run.py report incident.json --output incident_report.md
```
## Exportar evidencias para forense
```
dns-expert export incident.json --format pcap
dns-expert export incident.json --format html
or
python run.py export incident.json --format pcap
python run.py export incident.json --format html

```

2. 📊 Auditoría de Seguridad Programada
```
#!/bin/bash
# audit_dns.sh - Ejecutar diariamente via cron

DATE=$(date +%Y%m%d)
OUTPUT_DIR="/var/log/dns-audit"
mkdir -p $OUTPUT_DIR

echo "📡 Iniciando auditoría DNS $DATE..."

# Captura de 5 minutos
sudo dns-expert monitor --security \
  --output "$OUTPUT_DIR/capture_$DATE.json" \
  --duration 300

# Generar reporte
dns-expert report "$OUTPUT_DIR/capture_$DATE.json" \
  --output "$OUTPUT_DIR/report_$DATE.md"

# Exportar estadísticas
dns-expert export "$OUTPUT_DIR/capture_$DATE.json" \
  --format csv

echo "✅ Auditoría completada"
```

3. 🔄 Monitoreo Continuo
```
# monitor_continuo.sh
while true; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    sudo dns-expert monitor --security \
      --output "capture_$TIMESTAMP.json" \
      --duration 300
    sleep 60  # Pausa entre capturas
done
```

4. 📈 Análisis de Tendencias
```
# Recolectar datos por una hora
for i in {1..6}; do
    sudo dns-expert quick --duration 600 \
      --output "trend_$(date +%H%M).json"
    sleep 60
done

# Combinar y analizar
dns-expert export trend_*.json --format all
```

5. ⚡ Comandos Combinados
## Capturar + Reporte (una línea)
```
sudo python run.py monitor --security --output temp.json \
  && python run.py report temp.json --output reporte.md
```
## Captura rápida + Exportación completa
```
sudo python run.py quick --duration 60 --output quick.json \
  && python run.py export quick.json --format all
```
## Análisis completo con todos los formatos
```
sudo python run.py monitor --security --output analysis.json \
  && python run.py export analysis.json --format all \
  && python run.py report analysis.json --output security_report.md
```
---

# ❓ Solución de Problemas Comunes
| Error | Causa | Solución |
|-------|-------|----------|
| `JSON decode error` | Archivo JSON corrupto | `dns-expert fix-json captura.json` |
| `Interface not found` |	Interfaz incorrecta/no existe |	`dns-expert interfaces` para listar disponibles |
| `No traffic captured` |	Sin tráfico DNS en la red |	Verificar: `ping 8.8.8.8`, `nslookup google.com` |
| `Module not found` | Dependencias faltantes | `pip install -e .` o `pip install -r requirements.txt` |
| `[Errno 1]` | Permisos de captura |	Configurar Npcap (Windows) o capabilities (Linux) |
| `No module named 'core'` | Path incorrecto | Ejecutar desde directorio raíz del proyecto |

---

# Arquitectura
🏗️
```
dns_expert_monitor/
├── src/
│   └── dns_expert_monitor/          # Paquete principal
│       ├── __init__.py
│       ├── cli.py                   # Interfaz de línea de comandos
│       │
│       ├── core/                    # Componentes principales
│       │   ├── packet_engine.py     # Motor de captura con Scapy
│       │   ├── interface_manager.py # Gestión multiplataforma
│       │   └── packet_queue.py      # Colas thread-safe
│       │
│       ├── detectors/              # Detectores de seguridad
│       │   ├── dns_tunneling.py    # Detección de tunneling
│       │   ├── poisoning_detector.py # Detección de poisoning
│       │   ├── amplification_detector.py # Detección DDoS
│       │   ├── nxdomain_attack.py  # Detección NXDOMAIN
│       │   └── security_manager.py # Orquestador
│       │
│       ├── analyzers/              # Análisis de datos
│       │   ├── statistics_engine.py # Métricas en tiempo real
|       |   ├── security_analyzer   # Escaneo de paquetes DNS maliciosos
│       │   ├── dns_parser.py       # Parseo avanzado
│       │   └── cache_analyzer.py   # Análisis de caché
│       │
│       └── visualizers/           # Visualización y reportes
│           ├── data_export.py     # Exportación multiformato
│           ├── report_generator.py # Reportes profesionales
│           └── realtime_dashboard.py # Dashboard interactivo
│
├── tests/                          # Tests unitarios
|   ├── generate_test_trafic.py     # Genera trafico DNS para testeo
|   └── test_security.py            # Script para detectores de seguridad DNS
├── config/                         # Configuraciones
│   └── detectors.yaml             # Firmas de ataques
|   └── detectors_simple.yaml
|   └── signatures.yaml
├── docs/                          # Documentación
├── examples/                      # Ejemplos de uso
├── run.py                         # Script de ejecución
├── fix_json.py                    # Reparador JSON
├── dns-fix.py                     # Reparador DNS
├── requirements.txt               # Dependencias
├── requirements-dev.txt           # Dependencias-dev
├── README.es.md                   # Español
└── README.md                      # Ingles (Por defecto)
```
---

# 🤝 Contribuir
¡Las contribuciones son bienvenidas y apreciadas!

## 🎯 Áreas de contribución
- 🐛 Reportar bugs - Abre un issue con detalles del problema
- 💡 Sugerir características - Nueva funcionalidad o mejora
- 📚 Documentación - Mejora guías y ejemplos
- 🌍 Traducciones - Internacionalización
- 🔧 Plugins - Nuevos detectores de seguridad

## 🙏 Reconocimientos

### 📚 Librerías
- **[Scapy](https://scapy.net/)** - Manipulación de paquetes
- **[Rich](https://rich.readthedocs.io/)** - Terminal formateada
- **[Click](https://click.palletsprojects.com/)** - Framework CLI profesional
- **[Netifaces](https://github.com/al45tair/netifaces)** - Detección multiplataforma
- **[PyYAML](https://pyyaml.org/)** - Configuración estructurada
- **[Pandas](https://pandas.pydata.org/)** - Análisis de datos (opcional)
- **[Matplotlib](https://matplotlib.org/)** - Visualización (opcional)

### 👥 Comunidad
- A todos los contribuidores que han ayudado a mejorar esta herramienta
- A la comunidad de seguridad que comparte conocimiento sobre amenazas DNS
- A los usuarios que reportan bugs y sugieren mejoras

# ⚠️ ADVERTENCIA LEGAL
DNS Expert Monitor es una herramienta diseñada para:

✅ USO AUTORIZADO:

- Administración de redes propias

- Auditorías de seguridad con consentimiento

- Investigación y educación

- Respuesta a incidentes

❌ USO NO AUTORIZADO:

- Monitoreo de redes sin consentimiento

- Actividades maliciosas o ilegales

- Vulneración de privacidad

- Ataques a infraestructura ajena

**El uso no autorizado de esta herramienta para monitorear redes sin permiso explícito puede violar leyes locales e internacionales. El autor no se responsabiliza por el mal uso de esta herramienta.**

# 👨‍💻 Información del Proyecto

| Desarrollador | Augusto Zarate |
|---------------|----------------|
| Versión	0.2.0 | (Estable) |
| Última actualización | Febrero 2026 |
| Licencia | MIT |
| Repositorio |	github.com/augustozarate/dns-expert-monitor |
| Reportar issues |	GitHub Issues |
| Documentación | docs/ |

<div align="center"> <h3>⭐ ¿Te gusta el proyecto? ¡Dale una estrella en GitHub! ⭐</h3> <p> <a href="https://github.com/augustozarate/dns-expert-monitor/stargazers"> <img src="https://img.shields.io/github/stars/augustozarate/dns-expert-monitor?style=social" alt="GitHub stars"> </a> <a href="https://github.com/augustozarate/dns-expert-monitor/network/members"> <img src="https://img.shields.io/github/forks/augustozarate/dns-expert-monitor?style=social" alt="GitHub forks"> </a> <a href="https://github.com/augustozarate/dns-expert-monitor/watchers"> <img src="https://img.shields.io/github/watchers/augustozarate/dns-expert-monitor?style=social" alt="GitHub watchers"> </a> </p> <p> <sub>Hecho con ❤️ para la comunidad de seguridad</sub> </p> </div> ```
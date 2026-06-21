# FW-AUDIT-MV

## Descripción

FW-AUDIT-MV es una herramienta CLI en Python 3 orientada a Kali Linux para auditorías autorizadas de firewalls empresariales multi-vendor. Automatiza validaciones controladas de caja negra y caja blanca para FortiGate, Palo Alto, Check Point, Cisco ASA/FTD/FMC, Sophos, SonicWall, WatchGuard, Juniper SRX, AWS Network Firewall y Azure Firewall.

Su foco es la validación de controles, hardening, exposición, segmentación, revisión de reglas, evidencias y generación de reportes técnicos. No incorpora explotación, fuerza bruta, DoS, evasión ni técnicas destructivas.

## Advertencia de uso autorizado

Esta herramienta debe utilizarse exclusivamente con autorización formal y dentro del alcance definido por el cliente u organización. El operador debe contar con cambio aprobado, ventanas de ejecución y responsables designados. `safe_mode` está pensado para reforzar un uso conservador y no intrusivo.

## Instalación en Kali Linux

```bash
git clone https://github.com/USUARIO/fw-audit-mv.git
cd fw-audit-mv
chmod +x install.sh run.sh
./install.sh
cp config.example.yaml config.yaml
nano config.yaml
source .venv/bin/activate
python3 fw_audit.py --config config.yaml --mode full
```

## Configuración

El archivo base es `config.example.yaml`. Debe copiarse a `config.yaml` y adaptarse al alcance, IPs, puertos, targets internos, dispositivos y preferencias de reporte.

`config.yaml` no se sube al repositorio porque puede contener datos sensibles del entorno, como IPs de gestión, alcance interno, nombres de activos o referencias operativas.

Secciones relevantes:

- `project`: metadatos de la auditoría.
- `scope`: modo, `safe_mode`, timeout y paralelismo máximo.
- `blackbox`: objetivos públicos, puertos TCP/UDP/TLS y expectativas de exposición.
- `internal_tests`: validación de segmentación desde red interna controlada.
- `egress`: comprobación de salida hacia un endpoint externo controlado.
- `vendors`: conectores de caja blanca por fabricante.
- `reporting`: formatos de salida.

## Uso de variables de entorno

Las credenciales y tokens no se hardcodean. Deben definirse por variables de entorno o mediante un archivo `.env` local no versionado.

Archivo de ejemplo:

```env
FORTIGATE_TOKEN=
PALOALTO_TOKEN=
CHECKPOINT_USER=
CHECKPOINT_PASS=
CISCO_FMC_USER=
CISCO_FMC_PASS=
SOPHOS_TOKEN=
SONICWALL_USER=
SONICWALL_PASS=
WATCHGUARD_USER=
WATCHGUARD_PASS=
```

## Ejemplos de ejecución

```bash
python3 fw_audit.py --config config.yaml --mode full
python3 fw_audit.py --config config.yaml --mode blackbox
python3 fw_audit.py --config config.yaml --mode whitebox
python3 fw_audit.py --config config.yaml --mode external
python3 fw_audit.py --config config.yaml --mode internal
python3 fw_audit.py --config config.yaml --mode tls
python3 fw_audit.py --config config.yaml --mode egress
python3 fw_audit.py --config config.yaml --mode report
```

## Modos disponibles

- `full`: ejecuta caja negra, caja blanca y reportes.
- `blackbox`: lanza pruebas externas e internas controladas.
- `whitebox`: ejecuta conectores autorizados y análisis de reglas.
- `external`: orientado a validaciones públicas.
- `internal`: orientado a segmentación interna.
- `tls`: enfocado en enumeración TLS segura.
- `egress`: valida salida controlada hacia puertos definidos.
- `report`: genera reportes desde resultados disponibles de la ejecución actual.

## Fabricantes soportados

- FortiGate
- Palo Alto
- Check Point
- Cisco ASA/FTD/FMC
- Sophos
- SonicWall
- WatchGuard
- Juniper SRX
- AWS Network Firewall
- Azure Firewall

El conector FortiGate queda con base funcional para API token. El resto se entrega como estructura extensible lista para crecer sin romper el diseño del proyecto.

## Estructura de carpetas

```text
fw-audit-mv/
├── fw_audit.py
├── config.example.yaml
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── .env.example
├── install.sh
├── run.sh
├── modules/
├── templates/
├── evidence/
├── reports/
└── logs/
```

## Evidencias generadas

Cada ejecución crea automáticamente una subcarpeta con timestamp dentro de `evidence/`. Allí se guardan:

- Evidencia JSON de scans TCP, UDP, TLS, segmentación y egress.
- Evidencia XML de `nmap` cuando aplica.
- Normalización JSON por firewall en caja blanca.
- Resúmenes `blackbox_summary.json` y `whitebox_summary.json`.

## Reportes generados

La herramienta genera, según configuración:

- Reporte Markdown.
- Reporte HTML con Jinja2.
- Export técnico JSON.
- Resumen por severidad.
- Tabla de hallazgos.
- Recomendaciones.
- Anexo técnico.

## Limitaciones

- La calidad del análisis de caja negra depende de la visibilidad de red y del permiso operacional.
- El análisis TLS se basa en la salida de `nmap ssl-enum-ciphers`.
- El conector FortiGate queda preparado con base funcional y evidencia estructurada; para producción suele requerirse adaptación al firmware y endpoints exactos.
- Los demás conectores están preparados como scaffolding extensible y no hacen extracción completa del fabricante por defecto.
- El modo `report` reconstruye reportes desde evidencia de la ejecución actual; si se requiere histórico, conviene añadir selector de timestamp en una evolución posterior.

## Roadmap

- Ampliar parsing de XML de `nmap` para hallazgos más precisos.
- Integrar conectores completos para Palo Alto, Check Point y Cisco FMC.
- Añadir soporte opcional para AWS y Azure mediante SDKs oficiales.
- Incorporar comparación contra baseline de hardening.
- Exportar anexos CSV y evidencias indexadas.

## Buenas prácticas operativas

- Validar autorización, alcance y ventana antes de cada ejecución.
- Mantener `safe_mode: true` salvo justificación formal.
- Limitar `max_parallel_scans` en entornos sensibles.
- Usar un host de salto controlado para pruebas internas.
- Proteger `config.yaml`, `.env` y los reportes generados.
- Revisar manualmente los hallazgos antes de emitir el informe final al cliente.

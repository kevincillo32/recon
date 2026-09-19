# Changelog

## v1.0.0

Primera versión estable del framework modular.

### Añadido
- Estructura modular completa (`modules/`): nmap, web, servicios, hostnames, reporting, correlación de vulnerabilidades, misconfiguraciones.
- CLI con `argparse`: `--deep`, `--vhost-domain`, `-y`, `--version`.
- Extracción real de puertos UDP (antes se ignoraban).
- Correlación de CVEs contra NVD + búsqueda de PoC en GitHub, con niveles de confianza (HIGH/MEDIUM/LOW) y verificación opcional con `nuclei` en modo `--deep`.
- Retry/backoff automático ante rate-limit (429) de la API de NVD.
- Detección de misconfiguraciones y archivos interesantes expuestos por HTTP (`.git`, `.env`, backups, etc.).
- `README.md` y `attack-surface.md` autogenerados por máquina.
- `findings.md` / `findings.json` con el detalle de cada CVE correlacionado.
- `config/tools.conf` centraliza rutas de wordlists y parámetros, ya conectado al código.
- Logging a `recon.log` dentro del workspace de cada máquina.

### Corregido
- Bug de precedencia de operadores en el filtro de hostnames (`not x or y` → filtraba casi nada).
- Módulos LDAP, SMTP y bases de datos, ausentes en la v0.

### Conocido / pendiente para v1.1
- Enumeración de shares SMB con acceso anónimo no descarga contenido automáticamente (por diseño).
- Sin soporte todavía para AD avanzado (kerbrute, BloodHound).
- El módulo de correlación de CVEs no ha sido probado contra la API real de NVD en este entorno de desarrollo (sin acceso a red); validar en el primer uso real.

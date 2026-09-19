# recon

Framework de reconocimiento modular para HTB/eJPT (uso autorizado únicamente).

## Instalación

```bash
pip install -r requirements.txt --break-system-packages
```

Herramientas externas opcionales (el script detecta cuáles faltan y las
salta sin romper la ejecución): `nmap`, `whatweb`, `gobuster`, `ffuf`,
`sslscan`, `smbclient`, `enum4linux-ng`, `smbmap`, `dig`, `snmpwalk`,
`ldapsearch`, `nuclei`.

## Uso

```bash
# Recon normal
python3 recon.py 10.129.121.28 -n ghostlink

# Recon agresivo: UDP top1000, NSE vuln, verificación con nuclei
python3 recon.py 10.129.121.28 -n ghostlink --deep

# Con fuzzing de vhosts sobre un dominio conocido
python3 recon.py 10.129.121.28 -n ghostlink --vhost-domain ghostlink.htb

# Auto-confirmar cambios en /etc/hosts
python3 recon.py 10.129.121.28 -n ghostlink -y
```

## Estructura de salida

```
ghostlink/
├── 01_target/
├── 02_discovery/
├── 03_nmap/
├── 04_web/
├── 05_services/
├── 06_vulnerabilities/
│   ├── nmap-vuln.txt      (solo con --deep)
│   ├── nuclei.txt         (solo con --deep)
│   ├── findings.md
│   └── findings.json
├── 07_credentials/
├── exploits/
├── loot/
├── scripts/
├── README.md              (autogenerado)
└── attack-surface.md      (autogenerado)
```

## Correlación de CVEs

El módulo `vuln_correlation.py`:

1. Lee `03_nmap/targeted.xml` (salida de `nmap -sCV`) y extrae producto/versión de cada servicio.
2. Consulta la API pública de **NVD** por CVEs relacionados (sin API key; hay un delay de 6s entre requests para respetar el rate limit).
3. Busca PoCs públicos en **GitHub** por nombre de CVE (solo guarda el link, nunca clona repos automáticamente).
4. Asigna un nivel de **confianza** (`HIGH` / `MEDIUM` / `LOW`) según qué tan específica es la versión detectada.
5. Si se corre con `--deep` y hay `nuclei` instalado, cruza resultados: si nuclei confirma el CVE, el finding pasa de `POTENTIAL` a `VERIFIED`.
6. Nunca marca algo como "vulnerable" sin más — todo queda como `POTENTIALLY VULNERABLE` salvo verificación explícita.

## Notas

- Sin conexión a internet, el módulo de correlación de CVEs avisa y se desactiva solo; el resto del recon sigue funcionando con normalidad.
- Pensado exclusivamente para laboratorios autorizados (HTB, eJPT, entornos propios).

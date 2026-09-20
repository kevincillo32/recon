#!/usr/bin/env python3
"""
Modo --resume: si un recon se interrumpió a mitad de camino, permite
continuar sin repetir las fases que ya escribieron su archivo de salida.

No es un sistema de estado transaccional complejo -- se apoya en algo
simple y verificable: si el archivo de salida de una fase ya existe y
no está vacío, se asume completa y se salta. Es heurístico a propósito,
para no añadir una dependencia de base de datos de estado separada.
"""

from pathlib import Path

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored


# Mapea el nombre de cada fase a la ruta relativa (dentro del workspace)
# que indica que esa fase ya se completó.
CHECKPOINTS = {
    "host_discovery": "02_discovery/hostDiscovery.txt",
    "tcp_full": "03_nmap/allPortsTCP.xml",
    "tcp_targeted": "03_nmap/targeted.xml",
    "udp": "03_nmap/udpTop100",  # o udpTop1000 con --deep, se chequea con fase_completa()
    "os_detection": "03_nmap/osDetection",
    "web_recon": "04_web",
    "vuln_correlation": "06_vulnerabilities/findings.json",
    "reporting": "attack-surface.md",
}


def fase_completa(folder, nombre_fase, deep=False):
    ruta_relativa = CHECKPOINTS.get(nombre_fase)
    if not ruta_relativa:
        return False

    if nombre_fase == "udp" and deep:
        ruta_relativa = "03_nmap/udpTop1000"

    ruta = Path(folder) / ruta_relativa

    if not ruta.exists():
        return False

    if ruta.is_dir():
        return any(ruta.iterdir())

    return ruta.stat().st_size > 0


def resumen_estado(folder, deep=False):
    """Imprime qué fases ya están completas, para que el usuario sepa
    desde dónde continuará --resume antes de que corra nada."""
    print(colored("\n[+] Estado de checkpoints existentes:", "cyan"))
    for fase in CHECKPOINTS:
        estado = "✓ completa" if fase_completa(folder, fase, deep) else "✗ pendiente"
        print(f"    [{estado}] {fase}")

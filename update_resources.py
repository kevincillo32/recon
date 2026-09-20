#!/usr/bin/env python3
"""
update_resources.py - Actualiza templates de nuclei y verifica que las
wordlists de config/tools.conf existan en el sistema.

Uso:
    python3 update_resources.py
"""

from pathlib import Path
from modules.utils import run_command, tool_exists
from modules.config_loader import CONFIG


def actualizar_nuclei_templates():
    if not tool_exists("nuclei"):
        print("[!] nuclei no está instalado, se omite actualización de templates.")
        return

    print("[+] Actualizando templates de nuclei...")
    run_command(["nuclei", "-update-templates"])


def verificar_wordlists():
    print("\n[+] Verificando wordlists configuradas en config/tools.conf:")
    for clave in ("dir_common", "dir_medium", "subdomains"):
        ruta = CONFIG.get("wordlists", clave)
        existe = Path(ruta).exists()
        estado = "OK" if existe else "FALTA"
        print(f"    [{estado}] {clave}: {ruta}")


def main():
    actualizar_nuclei_templates()
    verificar_wordlists()


if __name__ == "__main__":
    main()

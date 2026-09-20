#!/usr/bin/env python3
"""
recon-note.py - Bitácora rápida sin abrir el editor.

Uso:
    python3 recon-note.py ghostlink "Encontré RCE en /upload.php via extensión .phtml"
    python3 recon-note.py ghostlink "user www-data, buscando privesc" --section Notes

Si la sección no existe en el README.md de esa máquina, la crea al final.
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime


def agregar_nota(workspace, nota, seccion="Notes"):
    readme_path = Path(workspace) / "README.md"

    if not readme_path.exists():
        print(f"[!] No existe {readme_path}. ¿El nombre del workspace es correcto?")
        sys.exit(1)

    contenido = readme_path.read_text(encoding="utf-8")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    linea_nota = f"- [{timestamp}] {nota}"

    marcador = f"## {seccion}"

    if marcador in contenido:
        # Insertar justo después del encabezado de la sección
        partes = contenido.split(marcador, 1)
        contenido = f"{partes[0]}{marcador}\n{linea_nota}{partes[1]}"
    else:
        contenido += f"\n\n{marcador}\n\n{linea_nota}\n"

    readme_path.write_text(contenido, encoding="utf-8")
    print(f"[+] Nota agregada a {readme_path} (sección '{seccion}')")


def main():
    parser = argparse.ArgumentParser(description="Bitácora rápida para workspaces de recon.py")
    parser.add_argument("workspace", help="Nombre de la carpeta del workspace (ej. ghostlink)")
    parser.add_argument("nota", help="Texto de la nota")
    parser.add_argument("--section", default="Notes", help="Sección del README donde insertar (default: Notes)")
    args = parser.parse_args()

    agregar_nota(args.workspace, args.nota, args.section)


if __name__ == "__main__":
    main()

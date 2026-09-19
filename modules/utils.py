#!/usr/bin/env python3
"""Utilidades compartidas por todos los módulos de recon."""

import shutil
import subprocess
import ipaddress
from pathlib import Path

from termcolor import colored


def banner():
    print(colored(r"""
╔══════════════════════════════════════════════════════════╗
║                  RECON TOOL v2                            ║
║   TCP / UDP / WEB / SMB / DNS / TLS / VULN CORRELATION     ║
╚══════════════════════════════════════════════════════════╝
""", "cyan"))


def run_command(command, output_file=None, timeout=None):
    """
    Ejecuta un comando y opcionalmente guarda stdout/stderr.
    Devuelve el stdout como string ("" si la herramienta no existe o falla).
    """
    print(colored(f"\n[>] {' '.join(str(c) for c in command)}", "cyan"))

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout,
        )

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)

        return result.stdout

    except FileNotFoundError:
        print(colored(f"[!] Herramienta no encontrada: {command[0]}", "red"))
        return ""
    except subprocess.TimeoutExpired:
        print(colored(f"[!] Timeout ejecutando: {command[0]}", "yellow"))
        return ""


def tool_exists(tool):
    return shutil.which(tool) is not None


def validar_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        print(colored("[!] Dirección IP no válida.", "red"))
        return False


class Carpeta:
    """Gestiona el workspace de la máquina objetivo."""

    def __init__(self, nombre):
        self.nombre = Path(nombre)
        self.nombre.mkdir(parents=True, exist_ok=True)

    def crear_carpeta(self, carpetas):
        for carpeta in carpetas:
            ruta = self.nombre / carpeta
            if ruta.exists():
                print(colored(f"[=] Ya existe: {ruta}", "yellow"))
            else:
                ruta.mkdir(parents=True, exist_ok=True)
                print(colored(f"[+] Creada: {ruta}", "green"))

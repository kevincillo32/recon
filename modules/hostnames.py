#!/usr/bin/env python3
"""Extracción de hostnames a partir de los outputs de recon y gestión de /etc/hosts."""

import re
try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

PATRONES = [
    r"(?i)(?:hostname|host|server|domain|fqdn)"
    r"[\s:=]+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",

    r"(?i)\b([a-zA-Z0-9][a-zA-Z0-9-]*"
    r"\.(?:htb|local|internal|lan|corp|test))\b",
]

# Dominios genéricos que casi siempre son ruido (falsos positivos de webs públicas,
# ejemplos en banners, etc.) y no aportan como hostname de la máquina objetivo.
DOMINIOS_RUIDO = (".com", ".org", ".net", ".gov", ".edu")


def extraer_de_texto(contenido):
    """Aplica los patrones de hostname sobre un string suelto (no archivo).
    Reutilizado tanto por extraer_hostnames() como por la sonda rápida
    de web.py antes del recon pesado."""
    encontrados = set()

    for patron in PATRONES:
        for hostname in re.findall(patron, contenido):
            hostname = hostname.strip(".,:;()[]{}<>\"'").lower()

            if not hostname:
                continue
            if hostname.endswith(".htb"):
                encontrados.add(hostname)
            elif not hostname.endswith(DOMINIOS_RUIDO):
                encontrados.add(hostname)

    return encontrados


def extraer_hostnames(folder):
    encontrados = set()

    archivos = list(folder.rglob("*"))

    for archivo in archivos:
        if not archivo.is_file():
            continue

        try:
            contenido = archivo.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        encontrados |= extraer_de_texto(contenido)

    return sorted(encontrados)


def agregar_hosts(ip, hostnames, auto_confirm=False):
    """Devuelve la lista de hostnames que quedaron efectivamente
    resueltos en /etc/hosts (ya existían o se acaban de agregar), para
    que el llamador sepa cuáles puede usar de forma confiable como URL."""
    if not hostnames:
        return []

    print(colored("\n[+] Hostnames encontrados:", "green"))
    for hostname in hostnames:
        print(f"    {hostname}")

    try:
        with open("/etc/hosts", "r", encoding="utf-8") as f:
            lines = f.readlines()
    except PermissionError:
        print(colored("[!] Se necesitan permisos para leer /etc/hosts.", "red"))
        return []

    ya_resueltos = []
    nuevas = []
    for hostname in hostnames:
        existe = any(
            len(line.split()) >= 2 and hostname in line.split()[1:]
            for line in lines
        )
        if existe:
            print(colored(f"[=] Ya existe: {hostname}", "yellow"))
            ya_resueltos.append(hostname)
        else:
            nuevas.append(hostname)

    if not nuevas:
        return ya_resueltos

    print(colored("\n[+] Hostnames que serán agregados:", "cyan"))
    for hostname in nuevas:
        print(f"    {ip} -> {hostname}")

    if not auto_confirm:
        respuesta = input("\n¿Agregar a /etc/hosts? [Y/n]: ").strip().lower()
        if respuesta not in ("", "y", "yes", "s", "si"):
            print(colored("[!] No se modificó /etc/hosts.", "yellow"))
            return ya_resueltos

    try:
        with open("/etc/hosts", "a", encoding="utf-8") as f:
            f.write(f"\n# Recon Tool - {ip}\n")
            for hostname in nuevas:
                f.write(f"{ip}\t{hostname}\n")
        print(colored("[+] /etc/hosts actualizado.", "green"))
        return ya_resueltos + nuevas
    except PermissionError:
        print(colored("[!] No tienes permisos de escritura.", "red"))
        print(colored("[!] Ejecuta el script con sudo o agrega las entradas manualmente.", "yellow"))
        return ya_resueltos

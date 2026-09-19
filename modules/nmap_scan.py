#!/usr/bin/env python3
"""Módulo de escaneo con Nmap: discovery, TCP full, targeted, UDP, OS, NSE."""

import re
import pyperclip
from termcolor import colored

from modules.utils import run_command


def host_discovery(ip, folder):
    output = folder / "02_discovery" / "hostDiscovery.txt"
    run_command([
        "nmap", "-sn", "-PE", "-PP", "-PS22,80,443", "-PA80,443",
        "--reason", "-n", ip, "-oN", str(output)
    ])
    print(colored(f"[+] Host discovery guardado en {output}", "green"))


def escanear_puertos_tcp(ip, folder):
    output = folder / "03_nmap" / "allPortsTCP"
    xml = folder / "03_nmap" / "allPortsTCP.xml"

    run_command([
        "nmap", "-p-", "--open", "-sS", "--min-rate", "5000",
        "-vvv", "-n", "-Pn", ip, "-oG", str(output), "-oX", str(xml)
    ])

    print(colored(f"[+] TCP completo guardado en {output}", "green"))
    return extraer_puertos(output)


def extraer_puertos(nmap_file):
    if not nmap_file.exists():
        return []

    contenido = nmap_file.read_text(encoding="utf-8", errors="ignore")
    puertos = sorted(set(int(p) for p in re.findall(r"(\d+)/open", contenido)))

    if puertos:
        port_string = ",".join(str(p) for p in puertos)
        try:
            pyperclip.copy(port_string)
            print(colored("[+] Puertos copiados al clipboard.", "green"))
        except Exception:
            pass
        print(colored(f"[+] Puertos TCP: {port_string}", "green"))
    else:
        print(colored("[!] No se encontraron puertos TCP abiertos.", "yellow"))

    return puertos


def escanear_puertos_personalizados(ip, folder, puertos):
    if not puertos:
        return

    ports = ",".join(str(p) for p in puertos)
    output = folder / "03_nmap" / "targeted"
    xml = folder / "03_nmap" / "targeted.xml"

    run_command([
        "nmap", "-sCV", "-p", ports, ip, "-oN", str(output), "-oX", str(xml)
    ])
    print(colored(f"[+] Enumeración TCP guardada en {output}", "green"))


def escanear_udp(ip, folder, deep=False):
    top = "1000" if deep else "100"
    output = folder / "03_nmap" / f"udpTop{top}"
    grepable = folder / "03_nmap" / f"udpTop{top}.gnmap"

    run_command([
        "nmap", "-sU", "--top-ports", top, "-Pn", "-n", ip,
        "-oN", str(output), "-oG", str(grepable)
    ])
    print(colored(f"[+] UDP Top {top} guardado en {output}", "green"))

    return extraer_puertos_udp(grepable)


def extraer_puertos_udp(nmap_grepable_file):
    """
    UDP suele reportar 'open|filtered' en vez de 'open' a secas cuando no
    hay -sV, así que se necesita una regex distinta a la de TCP.
    """
    if not nmap_grepable_file.exists():
        return []

    contenido = nmap_grepable_file.read_text(encoding="utf-8", errors="ignore")
    puertos = sorted(set(
        int(p) for p in re.findall(r"(\d+)/open(?:\|filtered)?/udp", contenido)
    ))

    if puertos:
        print(colored(f"[+] Puertos UDP (open/open|filtered): {puertos}", "green"))
    else:
        print(colored("[!] No se encontraron puertos UDP abiertos/filtrados.", "yellow"))

    return puertos


def detectar_os(ip, folder):
    output = folder / "03_nmap" / "osDetection"
    run_command([
        "nmap", "-O", "--osscan-guess", "-Pn", "-n", ip, "-oN", str(output)
    ])
    print(colored(f"[+] OS detection guardado en {output}", "green"))


def nse_discovery(ip, folder, puertos):
    if not puertos:
        return

    ports = ",".join(str(p) for p in puertos)
    output = folder / "03_nmap" / "discovery"

    run_command([
        "nmap", "-sV", "--script", "discovery", "-p", ports, ip, "-oN", str(output)
    ])
    print(colored(f"[+] NSE discovery guardado en {output}", "green"))


def nse_vuln(ip, folder, puertos):
    """Escaneo NSE orientado a vulnerabilidades (solo potential findings)."""
    if not puertos:
        return

    ports = ",".join(str(p) for p in puertos)
    output = folder / "06_vulnerabilities" / "nmap-vuln.txt"

    run_command([
        "nmap", "--script", "vuln", "-p", ports, ip, "-oN", str(output)
    ])
    print(colored(f"[+] NSE vuln guardado en {output} (revisar manualmente)", "green"))

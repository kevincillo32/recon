#!/usr/bin/env python3
"""
recon.py - Framework de reconocimiento modular para HTB/eJPT.

Uso:
    recon.py <ip> -n <nombre_carpeta> [--deep] [--vhost-domain target.htb] [-y]
"""

import argparse
import os

from modules.utils import banner, validar_ip, Carpeta
from modules import nmap_scan, web, services, hostnames as hn, reporting, vuln_correlation


SUBFOLDERS = [
    "01_target", "02_discovery", "03_nmap", "04_web",
    "05_services", "06_vulnerabilities", "07_credentials",
    "exploits", "loot", "scripts",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Framework de reconocimiento modular (HTB/eJPT)."
    )
    parser.add_argument("ip", help="Dirección IP del objetivo")
    parser.add_argument("-n", "--nombre", help="Nombre de la carpeta del workspace", required=False)
    parser.add_argument("--deep", action="store_true",
                         help="Escaneo más agresivo: UDP top1000, más wordlists, etc.")
    parser.add_argument("--vhost-domain", help="Dominio base para fuzzing de vhosts (ej. target.htb)")
    parser.add_argument("-y", "--yes", action="store_true",
                         help="Auto-confirmar cambios en /etc/hosts sin preguntar")
    return parser.parse_args()


def main():
    os.system("cls" if os.name == "nt" else "clear")
    banner()

    args = parse_args()

    if not validar_ip(args.ip):
        return

    nombre_carpeta = args.nombre or args.ip
    carpeta = Carpeta(nombre_carpeta)
    carpeta.crear_carpeta(SUBFOLDERS)

    ip = args.ip

    # 1. Host discovery
    nmap_scan.host_discovery(ip, carpeta.nombre)

    # 2. TCP full
    puertos = nmap_scan.escanear_puertos_tcp(ip, carpeta.nombre)
    if not puertos:
        print("[!] No hay puertos TCP abiertos. Fin del recon.")
        return

    # 3. TCP service enumeration
    nmap_scan.escanear_puertos_personalizados(ip, carpeta.nombre, puertos)

    # 4. UDP
    nmap_scan.escanear_udp(ip, carpeta.nombre, deep=args.deep)
    puertos_udp = []  # placeholder: extraer de output si se necesita más adelante

    # 5. OS detection
    nmap_scan.detectar_os(ip, carpeta.nombre)

    # 6. NSE discovery
    nmap_scan.nse_discovery(ip, carpeta.nombre, puertos)

    # 7. Web
    urls = web.http_recon(ip, carpeta.nombre, puertos)
    web.ssl_recon(ip, carpeta.nombre, puertos)

    if args.vhost_domain:
        web.vhost_fuzz(ip, carpeta.nombre, args.vhost_domain)

    # 8. Servicios
    services.smb_recon(ip, carpeta.nombre, puertos)
    services.ftp_recon(ip, carpeta.nombre, puertos)
    services.dns_recon(ip, carpeta.nombre, puertos)
    services.snmp_recon(ip, carpeta.nombre, puertos)
    services.ldap_recon(ip, carpeta.nombre, puertos)
    services.smtp_recon(ip, carpeta.nombre, puertos)
    services.database_recon(ip, carpeta.nombre, puertos)

    # 9. Vulnerabilidades: NSE vuln + correlación CVE (NVD + GitHub PoC)
    if args.deep:
        nmap_scan.nse_vuln(ip, carpeta.nombre, puertos)

    vuln_correlation.correlacionar_vulnerabilidades(carpeta.nombre, urls=urls, deep=args.deep)

    # 10. Hostnames
    hostnames_encontrados = hn.extraer_hostnames(carpeta.nombre)
    hostname_file = carpeta.nombre / "content_hostnames.txt"
    hostname_file.write_text("\n".join(hostnames_encontrados), encoding="utf-8")
    hn.agregar_hosts(ip, hostnames_encontrados, auto_confirm=args.yes)

    # 11. Reporting
    reporting.generar_attack_surface(ip, carpeta.nombre, puertos, puertos_udp, hostnames_encontrados)
    reporting.generar_readme(ip, carpeta, puertos, hostnames_encontrados)

    print("\n[+] Recon completado.")
    print(f"[+] Workspace: {carpeta.nombre}")
    print(f"[+] TCP: {','.join(map(str, puertos))}")
    if hostnames_encontrados:
        print(f"[+] Hostnames: {', '.join(hostnames_encontrados)}")


if __name__ == "__main__":
    main()

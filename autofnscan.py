#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
import ipaddress
from pathlib import Path

import pyperclip
from termcolor import colored


# ============================================================
# CONFIG
# ============================================================

WORDLIST = "/usr/share/wordlists/dirb/common.txt"

WEB_PORTS = {
    80, 81, 443, 591, 593, 800, 801, 8080,
    8081, 8088, 8443, 8888, 9000, 9090, 9443
}

SMB_PORTS = {139, 445}
FTP_PORTS = {21}
SSH_PORTS = {22}
DNS_PORTS = {53}
SNMP_PORTS = {161}
TLS_PORTS = {443, 465, 636, 853, 989, 990, 992, 993, 995, 8443}


# ============================================================
# UTILIDADES
# ============================================================

def banner():
    print(colored(r"""
╔══════════════════════════════════════════════════════════╗
║                  RECON TOOL                             ║
║          TCP / UDP / WEB / SMB / DNS / TLS              ║
╚══════════════════════════════════════════════════════════╝
""", "cyan"))


def run_command(command, output_file=None):
    """
    Ejecuta un comando y opcionalmente guarda stdout/stderr.
    """

    print(colored(f"\n[>] {' '.join(command)}", "cyan"))

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace"
        )

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)

        return result.stdout

    except FileNotFoundError:
        print(colored(
            f"[!] Herramienta no encontrada: {command[0]}",
            "red"
        ))
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


# ============================================================
# WORKSPACE
# ============================================================

class Carpeta:

    def __init__(self, nombre):
        self.nombre = Path(nombre)

        self.nombre.mkdir(
            parents=True,
            exist_ok=True
        )

    def crear_carpeta(self, carpetas):

        for carpeta in carpetas:

            ruta = self.nombre / carpeta

            if ruta.exists():
                print(colored(
                    f"[=] Ya existe: {ruta}",
                    "yellow"
                ))
            else:
                ruta.mkdir(
                    parents=True,
                    exist_ok=True
                )

                print(colored(
                    f"[+] Creada: {ruta}",
                    "green"
                ))


# ============================================================
# HOST DISCOVERY
# ============================================================

def host_discovery(ip, folder):

    output = folder / "nmap" / "hostDiscovery"

    run_command([
        "nmap",
        "-sn",
        "-PE",
        "-PP",
        "-PS22,80,443",
        "-PA80,443",
        "--reason",
        "-n",
        ip,
        "-oN",
        str(output)
    ])

    print(colored(
        f"[+] Host discovery guardado en {output}",
        "green"
    ))


# ============================================================
# TCP FULL
# ============================================================

def escanear_puertos(ip, folder):

    output = folder / "nmap" / "allPortsTCP"
    xml = folder / "nmap" / "allPortsTCP.xml"

    run_command([
        "nmap",
        "-p-",
        "--open",
        "-sS",
        "--min-rate",
        "5000",
        "-vvv",
        "-n",
        "-Pn",
        ip,
        "-oG",
        str(output),
        "-oX",
        str(xml)
    ])

    print(colored(
        f"[+] TCP completo guardado en {output}",
        "green"
    ))

    return extraer_puertos(output)


def extraer_puertos(nmap_file):

    if not nmap_file.exists():
        return []

    contenido = nmap_file.read_text(
        encoding="utf-8",
        errors="ignore"
    )

    puertos = re.findall(
        r"(\d+)/open",
        contenido
    )

    puertos = sorted(
        set(int(p) for p in puertos)
    )

    if puertos:

        port_string = ",".join(
            str(p) for p in puertos
        )

        pyperclip.copy(port_string)

        print(colored(
            f"[+] Puertos TCP: {port_string}",
            "green"
        ))

        print(colored(
            "[+] Puertos copiados al clipboard.",
            "green"
        ))

    else:
        print(colored(
            "[!] No se encontraron puertos TCP abiertos.",
            "yellow"
        ))

    return puertos


# ============================================================
# TCP TARGETED
# ============================================================

def escanear_puertos_personalizados(ip, folder, puertos):

    if not puertos:
        return

    ports = ",".join(
        str(p) for p in puertos
    )

    output = folder / "nmap" / "targeted"
    xml = folder / "nmap" / "targeted.xml"

    run_command([
        "nmap",
        "-sCV",
        "-p",
        ports,
        ip,
        "-oN",
        str(output),
        "-oX",
        str(xml)
    ])

    print(colored(
        f"[+] Enumeración TCP guardada en {output}",
        "green"
    ))


# ============================================================
# UDP
# ============================================================

def escanear_udp(ip, folder):

    output = folder / "nmap" / "udpTop100"

    run_command([
        "nmap",
        "-sU",
        "--top-ports",
        "100",
        "-Pn",
        "-n",
        ip,
        "-oN",
        str(output)
    ])

    print(colored(
        f"[+] UDP Top 100 guardado en {output}",
        "green"
    ))


# ============================================================
# OS DETECTION
# ============================================================

def detectar_os(ip, folder):

    output = folder / "nmap" / "osDetection"

    run_command([
        "nmap",
        "-O",
        "--osscan-guess",
        "-Pn",
        "-n",
        ip,
        "-oN",
        str(output)
    ])

    print(colored(
        f"[+] OS detection guardado en {output}",
        "green"
    ))


# ============================================================
# NSE DISCOVERY
# ============================================================

def nse_discovery(ip, folder, puertos):

    if not puertos:
        return

    ports = ",".join(
        str(p) for p in puertos
    )

    output = folder / "nmap" / "discovery"

    run_command([
        "nmap",
        "-sV",
        "--script",
        "discovery",
        "-p",
        ports,
        ip,
        "-oN",
        str(output)
    ])

    print(colored(
        f"[+] NSE discovery guardado en {output}",
        "green"
    ))


# ============================================================
# HTTP
# ============================================================

def http_recon(ip, folder, puertos):

    web_ports = sorted(
        set(puertos) & WEB_PORTS
    )

    if not web_ports:
        return []

    http_folder = folder / "content" / "http"
    http_folder.mkdir(parents=True, exist_ok=True)

    urls = []

    for port in web_ports:

        if port in {443, 8443}:
            scheme = "https"
        else:
            scheme = "http"

        url = f"{scheme}://{ip}:{port}"

        urls.append(url)

        safe_port = str(port)

        # Headers
        headers_file = (
            http_folder /
            f"headers-{safe_port}.txt"
        )

        run_command([
            "curl",
            "-k",
            "-sS",
            "-I",
            "--max-time",
            "10",
            url
        ], headers_file)

        # WhatWeb
        if tool_exists("whatweb"):

            whatweb_file = (
                http_folder /
                f"whatweb-{safe_port}.txt"
            )

            run_command([
                "whatweb",
                "-a",
                "3",
                url
            ], whatweb_file)

    return urls


# ============================================================
# WHATWEB
# ============================================================

def whatweb_recon(urls, folder):

    if not urls:
        return

    if not tool_exists("whatweb"):
        print(colored(
            "[!] whatweb no está instalado.",
            "yellow"
        ))
        return

    output = folder / "content" / "http" / "whatweb.txt"

    with open(output, "w", encoding="utf-8") as f:

        for url in urls:

            result = subprocess.run(
                ["whatweb", "-a", "3", url],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            f.write(
                f"\n===== {url} =====\n"
            )

            f.write(result.stdout)

    print(colored(
        f"[+] WhatWeb guardado en {output}",
        "green"
    ))


# ============================================================
# SSL
# ============================================================

def ssl_recon(ip, folder, puertos):

    tls_ports = sorted(
        set(puertos) & TLS_PORTS
    )

    if not tls_ports:
        return

    ssl_folder = folder / "content" / "http"
    ssl_folder.mkdir(parents=True, exist_ok=True)

    for port in tls_ports:

        output = (
            ssl_folder /
            f"ssl-{port}.txt"
        )

        run_command([
            "openssl",
            "s_client",
            "-connect",
            f"{ip}:{port}",
            "-servername",
            ip,
            "-showcerts"
        ], output)


# ============================================================
# SMB
# ============================================================

def smb_recon(ip, folder, puertos):

    if not (set(puertos) & SMB_PORTS):
        return

    smb_folder = folder / "content" / "smb"
    smb_folder.mkdir(parents=True, exist_ok=True)

    # Nmap SMB
    run_command([
        "nmap",
        "-p",
        "139,445",
        "--script",
        "smb-os-discovery,smb-protocols,smb-security-mode",
        ip,
        "-oN",
        str(smb_folder / "nmap-smb.txt")
    ])

    # smbclient
    if tool_exists("smbclient"):

        run_command([
            "smbclient",
            "-L",
            f"//{ip}/",
            "-N"
        ], smb_folder / "smbclient.txt")

    # enum4linux-ng
    if tool_exists("enum4linux-ng"):

        run_command([
            "enum4linux-ng",
            "-A",
            ip
        ], smb_folder / "enum4linux-ng.txt")

    # smbmap
    if tool_exists("smbmap"):

        run_command([
            "smbmap",
            "-H",
            ip
        ], smb_folder / "smbmap.txt")


# ============================================================
# FTP
# ============================================================

def ftp_recon(ip, folder, puertos):

    if FTP_PORTS.isdisjoint(puertos):
        return

    output = folder / "content" / "ftp.txt"

    run_command([
        "nmap",
        "-p21",
        "--script",
        "ftp-anon,ftp-syst",
        ip,
        "-oN",
        str(output)
    ])


# ============================================================
# DNS
# ============================================================

def dns_recon(ip, folder, puertos):

    if DNS_PORTS.isdisjoint(puertos):
        return

    dns_folder = folder / "content" / "dns"
    dns_folder.mkdir(parents=True, exist_ok=True)

    if tool_exists("dig"):

        for record in ["A", "NS", "MX", "TXT"]:

            output = (
                dns_folder /
                f"dig-{record}.txt"
            )

            run_command([
                "dig",
                f"@{ip}",
                record,
                "localhost"
            ], output)

    run_command([
        "nmap",
        "-p53",
        "--script",
        "dns-recursion,dns-service-discovery",
        ip,
        "-oN",
        str(dns_folder / "nmap-dns.txt")
    ])


# ============================================================
# SNMP
# ============================================================

def snmp_recon(ip, folder):

    snmp_folder = folder / "content" / "snmp"
    snmp_folder.mkdir(parents=True, exist_ok=True)

    if tool_exists("snmpwalk"):

        run_command([
            "snmpwalk",
            "-v2c",
            "-c",
            "public",
            ip
        ], snmp_folder / "snmpwalk-public.txt")

    run_command([
        "nmap",
        "-sU",
        "-p161",
        "--script",
        "snmp-info",
        ip,
        "-oN",
        str(snmp_folder / "nmap-snmp.txt")
    ])


# ============================================================
# HOSTNAME EXTRACTION
# ============================================================

def extraer_hostnames(folder):

    encontrados = set()

    archivos = list(
        (folder / "nmap").glob("*")
    ) + list(
        (folder / "content").rglob("*")
    )

    patrones = [
        r"(?i)(?:hostname|host|server|domain|fqdn)"
        r"[\s:=]+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",

        r"(?i)\b([a-zA-Z0-9][a-zA-Z0-9-]*"
        r"\.(?:htb|local|internal|lan|corp|test|com|net|org))\b",

        r"(?i)\b([a-zA-Z0-9][a-zA-Z0-9-]*"
        r"\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b"
    ]

    for archivo in archivos:

        if not archivo.is_file():
            continue

        try:
            contenido = archivo.read_text(
                encoding="utf-8",
                errors="ignore"
            )
        except Exception:
            continue

        for patron in patrones:

            matches = re.findall(
                patron,
                contenido
            )

            for hostname in matches:

                hostname = hostname.strip(
                    ".,:;()[]{}<>\"'"
                ).lower()

                if (
                    hostname
                    and not hostname.endswith(".com")
                    or hostname.endswith(".htb")
                ):
                    encontrados.add(hostname)

    return sorted(encontrados)


# ============================================================
# /etc/hosts
# ============================================================

def agregar_hosts(ip, hostnames):

    if not hostnames:
        return

    print(colored(
        "\n[+] Hostnames encontrados:",
        "green"
    ))

    for hostname in hostnames:
        print(f"    {hostname}")

    try:
        with open(
            "/etc/hosts",
            "r",
            encoding="utf-8"
        ) as f:
            lines = f.readlines()

    except PermissionError:
        print(colored(
            "[!] Se necesitan permisos para leer /etc/hosts.",
            "red"
        ))
        return

    nuevas = []

    for hostname in hostnames:

        existe = False

        for line in lines:

            partes = line.split()

            if (
                len(partes) >= 2
                and hostname in partes[1:]
            ):
                existe = True

                print(colored(
                    f"[=] Ya existe: {hostname}",
                    "yellow"
                ))

                break

        if not existe:
            nuevas.append(hostname)

    if not nuevas:
        return

    print(colored(
        "\n[+] Hostnames que serán agregados:",
        "cyan"
    ))

    for hostname in nuevas:
        print(f"    {ip} -> {hostname}")

    respuesta = input(
        "\n¿Agregar a /etc/hosts? [Y/n]: "
    ).strip().lower()

    if respuesta not in ("", "y", "yes", "s", "si"):
        print(colored(
            "[!] No se modificó /etc/hosts.",
            "yellow"
        ))
        return

    try:

        with open(
            "/etc/hosts",
            "a",
            encoding="utf-8"
        ) as f:

            f.write(
                f"\n# Recon Tool - {ip}\n"
            )

            for hostname in nuevas:

                f.write(
                    f"{ip}\t{hostname}\n"
                )

        print(colored(
            "[+] /etc/hosts actualizado.",
            "green"
        ))

    except PermissionError:

        print(colored(
            "[!] No tienes permisos de escritura.",
            "red"
        ))

        print(colored(
            "[!] Ejecuta el script con sudo o agrega las entradas manualmente.",
            "yellow"
        ))


# ============================================================
# MAIN
# ============================================================

def main():

    os.system(
        "cls" if os.name == "nt" else "clear"
    )

    banner()

    nombre_carpeta = input(
        "Introduzca el nombre de la carpeta a crear: "
    ).strip()

    if not nombre_carpeta:
        print(colored(
            "[!] Nombre inválido.",
            "red"
        ))
        return

    carpeta = Carpeta(nombre_carpeta)

    carpeta.crear_carpeta([
        "nmap",
        "content",
        "exploits",
        "scripts"
    ])

    ip = input(
        "\nIntroduzca la dirección IP a escanear: "
    ).strip()

    if not validar_ip(ip):
        return

    # --------------------------------------------------------
    # 1. HOST DISCOVERY
    # --------------------------------------------------------

    host_discovery(
        ip,
        carpeta.nombre
    )

    # --------------------------------------------------------
    # 2. TCP FULL
    # --------------------------------------------------------

    puertos = escanear_puertos(
        ip,
        carpeta.nombre
    )

    if not puertos:
        print(colored(
            "[!] No hay puertos TCP abiertos.",
            "yellow"
        ))
        return

    # --------------------------------------------------------
    # 3. TCP SERVICE ENUMERATION
    # --------------------------------------------------------

    escanear_puertos_personalizados(
        ip,
        carpeta.nombre,
        puertos
    )

    # --------------------------------------------------------
    # 4. UDP
    # --------------------------------------------------------

    escanear_udp(
        ip,
        carpeta.nombre
    )

    # --------------------------------------------------------
    # 5. OS
    # --------------------------------------------------------

    detectar_os(
        ip,
        carpeta.nombre
    )

    # --------------------------------------------------------
    # 6. NSE DISCOVERY
    # --------------------------------------------------------

    nse_discovery(
        ip,
        carpeta.nombre,
        puertos
    )

    # --------------------------------------------------------
    # 7. WEB
    # --------------------------------------------------------

    urls = http_recon(
        ip,
        carpeta.nombre,
        puertos
    )

    whatweb_recon(
        urls,
        carpeta.nombre
    )

    # --------------------------------------------------------
    # 8. SSL
    # --------------------------------------------------------

    ssl_recon(
        ip,
        carpeta.nombre,
        puertos
    )

    # --------------------------------------------------------
    # 9. SMB
    # --------------------------------------------------------

    smb_recon(
        ip,
        carpeta.nombre,
        puertos
    )

    # --------------------------------------------------------
    # 10. FTP
    # --------------------------------------------------------

    ftp_recon(
        ip,
        carpeta.nombre,
        puertos
    )

    # --------------------------------------------------------
    # 11. DNS
    # --------------------------------------------------------

    dns_recon(
        ip,
        carpeta.nombre,
        puertos
    )

    # --------------------------------------------------------
    # 12. SNMP
    # --------------------------------------------------------

    if 161 in puertos:
        snmp_recon(
            ip,
            carpeta.nombre
        )

    # --------------------------------------------------------
    # 13. HOSTNAMES
    # --------------------------------------------------------

    hostnames = extraer_hostnames(
        carpeta.nombre
    )

    # Guardar descubrimientos
    hostname_file = (
        carpeta.nombre /
        "content" /
        "hostnames.txt"
    )

    with open(
        hostname_file,
        "w",
        encoding="utf-8"
    ) as f:

        for hostname in hostnames:
            f.write(
                hostname + "\n"
            )

    # Agregar /etc/hosts
    agregar_hosts(
        ip,
        hostnames
    )

    # --------------------------------------------------------
    # FIN
    # --------------------------------------------------------

    print(colored(
        "\n╔════════════════════════════════════════════════════╗",
        "green"
    ))

    print(colored(
        "║              RECON COMPLETADO                    ║",
        "green"
    ))

    print(colored(
        "╚════════════════════════════════════════════════════╝",
        "green"
    ))

    print(
        f"\n[+] Workspace: {carpeta.nombre}"
    )

    print(
        f"[+] TCP: {','.join(map(str, puertos))}"
    )

    if hostnames:
        print(
            f"[+] Hostnames: {', '.join(hostnames)}"
        )


if __name__ == "__main__":
    main()

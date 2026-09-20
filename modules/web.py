#!/usr/bin/env python3
"""Módulo de reconocimiento web: headers, fingerprinting, SSL, vhosts."""

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

from modules.utils import run_command, tool_exists
from modules.config_loader import CONFIG

WEB_PORTS = {80, 81, 443, 591, 593, 800, 801, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443}
TLS_PORTS = {443, 465, 636, 853, 989, 990, 992, 993, 995, 8443}


def sondar_hostname_temprano(ip, puertos):
    """
    Sonda liviana (solo headers HTTP + certificado TLS) ANTES del recon
    web pesado, para descubrir el hostname real de la máquina (ej.
    'ghostlink.htb') antes de gastar tiempo enumerando directorios
    contra la IP -- que en HTB casi siempre da un resultado distinto
    (o vacío) al que da el vhost real.

    Devuelve un set de hostnames candidatos extraídos de:
    - Headers HTTP (Location de un redirect, Host reflejado, etc.)
    - El Common Name / SAN del certificado TLS, si hay puerto TLS abierto

    No escribe nada a disco -- es una sonda de un solo tiro por puerto,
    pensada para ser rápida y no duplicar el trabajo de http_recon/ssl_recon
    que sí guardan todo a archivo más adelante.
    """
    from modules.hostnames import extraer_de_texto

    web_ports = sorted(set(puertos) & WEB_PORTS)
    if not web_ports:
        return set()

    candidatos = set()

    for port in web_ports:
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{ip}:{port}"

        headers_texto = run_command(["curl", "-k", "-sS", "-I", "--max-time", "6", url])
        candidatos |= extraer_de_texto(headers_texto or "")

        if port in TLS_PORTS and tool_exists("openssl"):
            cert_texto = run_command([
                "openssl", "s_client", "-connect", f"{ip}:{port}",
                "-servername", ip
            ], timeout=8) or ""
            # El CN/SAN del certificado suele venir en líneas tipo
            # "subject=CN = ghostlink.htb" -- ya cubierto por los patrones
            # genéricos de hostnames.py (busca *.htb, *.local, etc.)
            candidatos |= extraer_de_texto(cert_texto)

    return candidatos


def http_recon(ip, folder, puertos):
    web_ports = sorted(set(puertos) & WEB_PORTS)
    if not web_ports:
        return []

    urls = []

    for port in web_ports:
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{ip}:{port}"
        urls.append(url)

        port_folder = folder / "04_web" / str(port)
        port_folder.mkdir(parents=True, exist_ok=True)

        run_command([
            "curl", "-k", "-sS", "-I", "--max-time", "10", url
        ], port_folder / "headers.txt")

        if tool_exists("whatweb"):
            run_command([
                "whatweb", "-a", "3", url
            ], port_folder / "whatweb.txt")

        # Directory enumeration básico (wordlist común primero)
        if tool_exists("gobuster"):
            wordlist = CONFIG.get("wordlists", "dir_common")
            threads = CONFIG.get("web", "gobuster_threads")
            dir_output = port_folder / "directories.txt"

            run_command([
                "gobuster", "dir", "-u", url,
                "-w", wordlist,
                "-q", "-t", threads
            ], dir_output)

    return urls


def vhost_fuzz(ip, folder, hostname_base, wordlist=None):
    """Fuzzing de vhosts si se conoce un dominio base (ej. target.htb)."""
    if not hostname_base or not tool_exists("ffuf"):
        return

    wordlist = wordlist or CONFIG.get("wordlists", "subdomains")

    output = folder / "04_web" / "vhosts.txt"
    output.parent.mkdir(parents=True, exist_ok=True)

    run_command([
        "ffuf", "-u", f"http://{ip}/",
        "-H", f"Host: FUZZ.{hostname_base}",
        "-w", wordlist,
        "-of", "csv", "-o", str(output)
    ])
    print(colored(f"[+] VHost fuzzing guardado en {output}", "green"))


def ssl_recon(ip, folder, puertos):
    tls_ports = sorted(set(puertos) & TLS_PORTS)
    if not tls_ports:
        return

    ssl_folder = folder / "04_web" / "ssl"
    ssl_folder.mkdir(parents=True, exist_ok=True)

    for port in tls_ports:
        output = ssl_folder / f"ssl-{port}.txt"
        run_command([
            "openssl", "s_client", "-connect", f"{ip}:{port}",
            "-servername", ip, "-showcerts"
        ], output)

        if tool_exists("sslscan"):
            run_command([
                "sslscan", f"{ip}:{port}"
            ], ssl_folder / f"sslscan-{port}.txt")

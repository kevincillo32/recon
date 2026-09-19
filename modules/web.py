#!/usr/bin/env python3
"""Módulo de reconocimiento web: headers, fingerprinting, SSL, vhosts."""

from termcolor import colored

from modules.utils import run_command, tool_exists

WEB_PORTS = {80, 81, 443, 591, 593, 800, 801, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443}
TLS_PORTS = {443, 465, 636, 853, 989, 990, 992, 993, 995, 8443}


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
            run_command([
                "gobuster", "dir", "-u", url,
                "-w", "/usr/share/wordlists/dirb/common.txt",
                "-q", "-t", "50"
            ], port_folder / "directories.txt")

    return urls


def vhost_fuzz(ip, folder, hostname_base, wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"):
    """Fuzzing de vhosts si se conoce un dominio base (ej. target.htb)."""
    if not hostname_base or not tool_exists("ffuf"):
        return

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

#!/usr/bin/env python3
"""
Detección de misconfiguraciones comunes y archivos interesantes expuestos
por HTTP. No descarga nada indiscriminadamente: solo hace HEAD/GET ligeros
a rutas conocidas y reporta el status code.
"""

import requests
import urllib3
try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RUTAS_INTERESANTES = [
    ".git/HEAD", ".git/config", ".env", "config.php", "database.php",
    "web.config", "settings.py", "backup.zip", "backup.tar.gz",
    "id_rsa", ".svn/entries", "wp-config.php.bak", "admin/",
    "phpinfo.php", ".DS_Store",
]


def buscar_archivos_interesantes(urls, folder):
    """
    Para cada URL web detectada, prueba rutas sensibles conocidas.
    Marca como HIGH INTEREST cualquier respuesta 200/301/302/403 (403 en
    .git o .env suele indicar que el archivo existe pero está bloqueado,
    lo cual también es información útil).
    """
    if not urls:
        return []

    hallazgos = []
    output = folder / "06_vulnerabilities" / "misconfigurations.md"
    output.parent.mkdir(parents=True, exist_ok=True)

    lines = ["# Misconfigurations / Archivos interesantes", ""]

    for base_url in urls:
        for ruta in RUTAS_INTERESANTES:
            url = f"{base_url.rstrip('/')}/{ruta}"

            try:
                resp = requests.get(url, timeout=6, verify=False, allow_redirects=False)
                status = resp.status_code
            except Exception:
                continue

            if status in (200, 301, 302, 403):
                marca = "⭐ HIGH INTEREST" if status in (200, 403) else "→ redirect"
                hallazgos.append({"url": url, "status": status})
                lines.append(f"- [{status}] {marca} — {url}")
                print(colored(f"[!] {marca} ({status}): {url}", "yellow"))

    if len(lines) == 2:
        lines.append("(nada encontrado en las rutas conocidas)")

    output.write_text("\n".join(lines), encoding="utf-8")
    return hallazgos

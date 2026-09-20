#!/usr/bin/env python3
"""
Escanea todos los archivos recolectados por el recon (web, smb, etc.)
buscando patrones de credenciales y hashes, y los centraliza en
07_credentials/.
"""

import re
try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

from modules.utils import run_command, tool_exists

PATRONES_CREDENCIALES = {
    "password_generic": re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{3,})"),
    "api_key": re.compile(r"(?i)\b(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{10,})"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "ntlm_hash": re.compile(r"\b[0-9a-f]{32}:[0-9a-f]{32}\b", re.IGNORECASE),
    "generic_hash_32": re.compile(r"\b[0-9a-f]{32}\b", re.IGNORECASE),
    "private_key_marker": re.compile(r"-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----"),
}


def escanear_credenciales(folder):
    """
    Recorre todos los archivos de texto del workspace (excepto lo ya
    generado en 07_credentials/) y extrae posibles credenciales/hashes.
    """
    hallazgos = []
    creds_folder = folder / "07_credentials"
    creds_folder.mkdir(parents=True, exist_ok=True)

    archivos = [
        f for f in folder.rglob("*")
        if f.is_file() and "07_credentials" not in f.parts and "screenshots" not in f.parts
    ]

    for archivo in archivos:
        try:
            contenido = archivo.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for nombre_patron, patron in PATRONES_CREDENCIALES.items():
            for match in patron.finditer(contenido):
                valor = match.group(0)
                hallazgos.append({
                    "archivo": str(archivo.relative_to(folder)),
                    "tipo": nombre_patron,
                    "valor": valor[:120],
                })

    _escribir_reporte(creds_folder, hallazgos)

    if hallazgos:
        print(colored(f"[!] {len(hallazgos)} posible(s) credencial(es)/hash(es) encontrados.", "yellow"))
    else:
        print(colored("[+] No se detectaron patrones de credenciales evidentes.", "green"))

    return hallazgos


def identificar_hash(valor):
    """Usa hashcat --identify si está disponible para sugerir el modo de hash."""
    if not tool_exists("hashcat"):
        return None

    salida = run_command(["hashcat", "--identify", valor])
    return salida.strip() if salida else None


def _escribir_reporte(creds_folder, hallazgos):
    output = creds_folder / "credentials-found.md"

    lines = ["# Posibles credenciales / hashes encontrados", "",
             "⚠️ Requiere verificación manual -- muchos de estos serán falsos positivos.", ""]

    if not hallazgos:
        lines.append("No se encontraron coincidencias.")
    else:
        for h in hallazgos:
            lines.append(f"- **[{h['tipo']}]** `{h['archivo']}` → `{h['valor']}`")

    output.write_text("\n".join(lines), encoding="utf-8")

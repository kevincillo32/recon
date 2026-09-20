#!/usr/bin/env python3
"""
Genera comandos SUGERIDOS de fuerza bruta para servicios de login
comunes (SSH, FTP, SMB) cuando se detecta un puerto de ese tipo. Nunca
se ejecutan automáticamente -- decisión del usuario, en su propio
entorno y siempre contra objetivos autorizados.
"""

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

SUGERENCIAS = {
    21: "hydra -L usuarios.txt -P /usr/share/wordlists/rockyou.txt ftp://{ip}",
    22: "hydra -L usuarios.txt -P /usr/share/wordlists/rockyou.txt ssh://{ip}",
    445: "hydra -L usuarios.txt -P /usr/share/wordlists/rockyou.txt smb://{ip}",
    3389: "hydra -L usuarios.txt -P /usr/share/wordlists/rockyou.txt rdp://{ip}",
}


def sugerir_bruteforce(ip, folder, puertos):
    sugerencias = []

    for puerto in puertos:
        if puerto in SUGERENCIAS:
            cmd = SUGERENCIAS[puerto].format(ip=ip)
            sugerencias.append((puerto, cmd))

    if not sugerencias:
        return

    output = folder / "07_credentials" / "bruteforce-suggestions.md"
    output.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Sugerencias de fuerza bruta (NO ejecutadas automáticamente)", "",
        "Ejecuta solo si es un objetivo autorizado y ya tienes una lista de usuarios razonable.", "",
    ]

    for puerto, cmd in sugerencias:
        lines.append(f"## Puerto {puerto}")
        lines.append(f"```\n{cmd}\n```")
        lines.append("")

    output.write_text("\n".join(lines), encoding="utf-8")
    print(colored(f"[i] Sugerencias de bruteforce guardadas en {output} (no ejecutadas)", "cyan"))

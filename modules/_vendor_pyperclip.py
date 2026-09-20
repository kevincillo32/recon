#!/usr/bin/env python3
"""
Reimplementación mínima local de pyperclip.copy(), usando las
herramientas de clipboard nativas del sistema (xclip/xsel/pbcopy/clip)
en vez de depender del paquete externo. Si ninguna está disponible,
falla en silencio (copiar al clipboard es una conveniencia, no algo
crítico para el funcionamiento del recon).
"""

import shutil
import subprocess


def copy(text):
    candidatos = [
        (["xclip", "-selection", "clipboard"], None),
        (["xsel", "--clipboard", "--input"], None),
        (["pbcopy"], None),          # macOS
        (["clip"], None),            # Windows
    ]

    for comando, _ in candidatos:
        if shutil.which(comando[0]):
            try:
                subprocess.run(comando, input=text.encode(), check=True, timeout=5)
                return
            except Exception:
                continue

    # Ninguna herramienta de clipboard disponible -- se omite en silencio.

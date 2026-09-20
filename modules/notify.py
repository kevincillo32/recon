#!/usr/bin/env python3
"""Aviso sonoro/visual al terminar un recon largo (útil con --deep)."""

from modules.utils import run_command, tool_exists


def notificar(mensaje="Recon completado"):
    # Beep de terminal (funciona casi siempre, no requiere nada instalado)
    print("\a", end="", flush=True)

    if tool_exists("notify-send"):
        run_command(["notify-send", "recon.py", mensaje])

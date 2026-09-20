#!/usr/bin/env python3
"""
Carga plugins de usuario desde modules/custom/*.py.

Un plugin de usuario mínimo:

    # modules/custom/mi_plugin.py
    PARALLEL_SAFE = True
    REQUIRES = ["puertos"]

    def run(ip, folder, context):
        puertos = context["puertos"]
        if 8080 not in puertos:
            return None
        # ... hacer algo ...
        return {"encontrado": True}

No requiere tocar recon.py: se auto-descubre y se ejecuta en la fase
de plugins de usuario (después de los módulos built-in).
"""

import importlib.util
import sys
from pathlib import Path
try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

CUSTOM_DIR = Path(__file__).resolve().parent / "custom"


def descubrir_plugins():
    """Devuelve una lista de módulos Python cargados desde modules/custom/."""
    if not CUSTOM_DIR.exists():
        return []

    plugins = []

    for archivo in sorted(CUSTOM_DIR.glob("*.py")):
        if archivo.name.startswith("_"):
            continue

        nombre_modulo = f"recon_custom_{archivo.stem}"

        try:
            spec = importlib.util.spec_from_file_location(nombre_modulo, archivo)
            modulo = importlib.util.module_from_spec(spec)
            sys.modules[nombre_modulo] = modulo
            spec.loader.exec_module(modulo)

            if not hasattr(modulo, "run"):
                print(colored(f"[!] Plugin {archivo.name} no tiene función run(), se omite.", "yellow"))
                continue

            plugins.append(modulo)
            print(colored(f"[+] Plugin cargado: {archivo.name}", "cyan"))

        except Exception as e:
            print(colored(f"[!] Error cargando plugin {archivo.name}: {e}", "red"))

    return plugins


def ejecutar_plugins(plugins, ip, folder, context):
    """
    Corre cada plugin, respetando REQUIRES (si el context no tiene esas
    claves, se omite silenciosamente) y guarda su resultado en context
    bajo el nombre del plugin.
    """
    for plugin in plugins:
        nombre = plugin.__name__.replace("recon_custom_", "")
        requires = getattr(plugin, "REQUIRES", [])

        if any(req not in context for req in requires):
            continue

        try:
            resultado = plugin.run(ip, folder, context)
            if resultado is not None:
                context[nombre] = resultado
        except Exception as e:
            print(colored(f"[!] Error ejecutando plugin {nombre}: {e}", "red"))

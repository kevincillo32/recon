#!/usr/bin/env python3
"""
Interfaz base de plugins.

Un plugin es cualquier archivo .py en modules/ (built-in) o
modules/custom/ (del usuario) que define una función:

    def run(ip: str, folder: Path, context: dict) -> dict | None:
        ...

`context` trae lo que otros módulos ya descubrieron (puertos, urls,
hostnames, etc.) para que el plugin decida si le toca correr o no.
El valor de retorno (si lo hay) se guarda en context bajo el nombre
del plugin, para que plugins posteriores puedan usarlo.

Cada plugin también puede declarar, como atributos de módulo:

    PARALLEL_SAFE = True   # puede correr en paralelo con otros plugins
    REQUIRES = ["puertos"] # claves de context que debe tener antes de correr
"""

from dataclasses import dataclass, field


@dataclass
class PluginResult:
    nombre: str
    ok: bool
    data: dict = field(default_factory=dict)
    error: str = ""

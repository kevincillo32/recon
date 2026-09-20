#!/usr/bin/env python3
"""
Reimplementación mínima y local de termcolor.colored(), para no
depender de la librería externa (que en algunos entornos con red
restringida no se puede instalar). Cubre el subconjunto que usa este
proyecto: texto + color de primer plano vía ANSI.

Si el paquete `termcolor` real está instalado, se usa ese en su lugar
(ver modules/utils.py) -- este archivo es el fallback.
"""

_COLORS = {
    "grey": 30, "red": 31, "green": 32, "yellow": 33,
    "blue": 34, "magenta": 35, "cyan": 36, "white": 37,
}

_RESET = "\033[0m"


def colored(text, color=None, on_color=None, attrs=None):
    if color is None or color not in _COLORS:
        return text

    codigo = _COLORS[color]
    return f"\033[{codigo}m{text}{_RESET}"

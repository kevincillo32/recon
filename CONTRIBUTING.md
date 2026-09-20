# Contribuir a recon-htb

Gracias por tu interés en aportar. Este proyecto es open source y
pensado para la comunidad de hacking ético (HTB, TryHackMe, eJPT, OSCP
labs, engagements autorizados) — no una sola plataforma.

## Antes de empezar

- Todo lo que "toca" un objetivo más allá de reconocimiento pasivo debe
  quedar detrás de un flag explícito (ver `--active-verify`,
  `--auto-exploit` como ejemplos). Nunca agregues algo que ejecute un
  exploit real sin confirmación humana explícita.
- Ningún módulo debe asumir que una herramienta externa está instalada
  sin verificarlo primero (`modules.utils.tool_exists`).
- Si tu cambio agrega una dependencia externa nueva, pregúntate primero
  si se puede vendorizar (ver `modules/_vendor_termcolor.py` y
  `modules/_vendor_pyperclip.py` como precedente) para no aumentar la
  fricción de instalación.

## Cómo agregar un módulo nuevo

Dos caminos, según qué tan integrado necesites que esté:

1. **Plugin de usuario** (recomendado para la mayoría de casos): deja un
   `.py` en `modules/custom/` con una función `run(ip, folder, context)`.
   Se auto-descubre, no requiere tocar `recon.py`. Ver
   `modules/custom/README.md` para el formato exacto.

2. **Módulo built-in**: si tu aporte debería ser parte del flujo
   principal (por ejemplo, un nuevo tipo de servicio que todos deberían
   tener por defecto), agrégalo a `modules/` siguiendo el patrón de los
   existentes (una función clara por responsabilidad, uso de
   `run_command`/`tool_exists` de `modules/utils.py`) e impórtalo en
   `recon.py`.

## Tests

Hay un set mínimo de tests en `tests/` que corre sin red ni herramientas
externas (nmap, etc.) — valida lógica pura: parseo de regex, cálculo de
confianza, construcción del grafo de ataque, etc.

```bash
pip install pytest --break-system-packages
pytest tests/
```

Si agregas un módulo con lógica no trivial (parseo, regex, cálculos),
agrega un test correspondiente en `tests/`. No hace falta mockear nmap
completo — la mayoría de la lógica interesante es pura (dado este XML,
devuelve esto; dado este finding, calcula esta confianza).

## Reportar bugs

Abre un issue con:
- Comando exacto que corriste
- Traceback completo (o el output relevante)
- Versión de la herramienta externa involucrada si aplica (`nmap --version`, etc.)

## Código de conducta implícito

Esta herramienta existe para la comunidad de hacking ético. Cualquier
PR que agregue funcionalidad orientada a atacar sistemas sin
autorización (fuerza bruta automática sin confirmación, exploits que se
ejecutan solos, exfiltración de datos no solicitada) será rechazado.

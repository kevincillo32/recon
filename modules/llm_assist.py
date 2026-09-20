#!/usr/bin/env python3
"""
Motor de sugerencias con LLM (--assist).

Diseñado para ser agnóstico del proveedor: por defecto usa la API de
Anthropic si hay ANTHROPIC_API_KEY en el entorno, pero la función
`_llamar_llm` es el único punto de integración -- cambiarlo a OpenAI,
Ollama local, etc. es una función, no un rediseño.

Nunca ejecuta nada por su cuenta: solo imprime/guarda una sugerencia en
texto para que el usuario decida.
"""

import os
import json
try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

try:
    import requests
except ImportError:
    requests = None

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-sonnet-4-6"


def _construir_prompt(context, findings):
    resumen = {
        "puertos_tcp": context.get("puertos"),
        "puertos_udp": context.get("puertos_udp"),
        "urls": context.get("urls"),
        "hostnames": context.get("hostnames"),
        "findings": [
            {"cve": f.get("cve"), "severity": f.get("severity"),
             "product": f.get("product"), "status": f.get("status")}
            for f in (findings or [])
        ],
    }

    return (
        "Eres un asistente de pentesting para un CTF/HTB autorizado. "
        "A partir de este reconocimiento, sugiere de forma concisa (máx 8 líneas) "
        "cuáles serían los 2-3 próximos pasos más razonables a investigar, "
        "explicando brevemente el porqué. No inventes CVEs ni datos que no estén "
        "en el contexto. No des instrucciones de explotación destructiva.\n\n"
        f"Contexto del recon:\n{json.dumps(resumen, indent=2, ensure_ascii=False)}"
    )


def _llamar_llm(prompt):
    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if not api_key:
        print(colored(
            "[!] --assist requiere ANTHROPIC_API_KEY en el entorno "
            "(o adapta modules/llm_assist.py a tu proveedor preferido).",
            "yellow"
        ))
        return None

    if requests is None:
        print(colored("[!] Falta 'requests' para usar --assist.", "red"))
        return None

    try:
        resp = requests.post(
            ANTHROPIC_API_URL,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": 500,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return "".join(block.get("text", "") for block in data.get("content", []))

    except Exception as e:
        print(colored(f"[!] Error consultando LLM: {e}", "yellow"))
        return None


def sugerir_siguientes_pasos(context, findings, folder):
    prompt = _construir_prompt(context, findings)
    sugerencia = _llamar_llm(prompt)

    if not sugerencia:
        return None

    output = folder / "06_vulnerabilities" / "llm-suggestions.md"
    output.write_text(
        "# Sugerencias del asistente (LLM)\n\n"
        "⚠️ Generado automáticamente. Verifica cada afirmación contra la evidencia real.\n\n"
        f"{sugerencia}\n",
        encoding="utf-8",
    )

    print(colored("\n[+] Sugerencias del asistente:\n", "cyan"))
    print(sugerencia)
    print(colored(f"\n[+] Guardado también en {output}", "green"))

    return sugerencia

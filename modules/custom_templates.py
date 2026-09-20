#!/usr/bin/env python3
"""
Motor de templates propio (--custom-templates), formato YAML simple,
inspirado en Nuclei pero sin la dependencia externa -- para que la
comunidad pueda contribuir checks de verificación sin tocar Python.

Formato de un template (templates/custom/CVE-2021-41773.yaml):

    id: CVE-2021-41773
    severity: high
    matchers:
      - type: word
        words:
          - "root:.*:0:0:"
        condition: regex
    request:
      path: "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
      method: GET

Solo soporta matchers de tipo "word"/"regex" sobre el body de la
respuesta -- es deliberadamente simple; para necesidades más complejas
seguimos recomendando nuclei real (--deep).
"""

import re
from pathlib import Path

import yaml

try:
    import requests
except ImportError:
    requests = None

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates" / "custom"


def cargar_templates():
    if not TEMPLATES_DIR.exists():
        return []

    templates = []
    for archivo in sorted(TEMPLATES_DIR.glob("*.yaml")) + sorted(TEMPLATES_DIR.glob("*.yml")):
        try:
            data = yaml.safe_load(archivo.read_text(encoding="utf-8"))
            if data and "id" in data and "request" in data:
                templates.append(data)
        except Exception as e:
            print(colored(f"[!] Error cargando template {archivo.name}: {e}", "yellow"))

    return templates


def _evaluar_matcher(matcher, respuesta_texto):
    if matcher.get("type") != "word":
        return False

    palabras = matcher.get("words", [])
    condicion = matcher.get("condition", "word")

    if condicion == "regex":
        return any(re.search(w, respuesta_texto) for w in palabras)

    return any(w in respuesta_texto for w in palabras)


def ejecutar_templates(urls, folder):
    if requests is None:
        print(colored("[!] Falta 'requests' para correr templates personalizados.", "red"))
        return []

    templates = cargar_templates()
    if not templates:
        return []

    print(colored(f"[+] {len(templates)} template(s) personalizado(s) cargado(s).", "cyan"))

    resultados = []

    for template in templates:
        path = template["request"].get("path", "/")
        method = template["request"].get("method", "GET")

        for base_url in urls or []:
            url = base_url.rstrip("/") + path

            try:
                resp = requests.request(method, url, timeout=8, verify=False)
            except Exception:
                continue

            for matcher in template.get("matchers", []):
                if _evaluar_matcher(matcher, resp.text):
                    resultados.append({
                        "template_id": template["id"],
                        "severity": template.get("severity", "unknown"),
                        "url": url,
                    })
                    print(colored(f"[!!!] Template '{template['id']}' hizo match en {url}", "red"))

    _escribir_reporte(resultados, folder)
    return resultados


def _escribir_reporte(resultados, folder):
    output = folder / "06_vulnerabilities" / "custom-templates.md"
    output.parent.mkdir(parents=True, exist_ok=True)

    lines = ["# Templates personalizados — resultados", ""]

    if not resultados:
        lines.append("Ningún template personalizado hizo match (o no había ninguno cargado).")
    else:
        for r in resultados:
            lines.append(f"- **{r['template_id']}** ({r['severity']}) — {r['url']}")

    output.write_text("\n".join(lines), encoding="utf-8")

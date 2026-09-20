#!/usr/bin/env python3
"""
Motor de detección propio (detection_engine.py), alternativa liviana a
nuclei basada en templates YAML que la comunidad puede contribuir sin
tocar Python.

Formato de un template (ver detection-templates/*.yaml para ejemplos):

    id: exposed-git-config
    info:
      name: Exposed .git/config
      severity: medium
    request:
      path: /.git/config
      method: GET
    matchers:
      - type: word
        words: ["[core]", "repositoryformatversion"]
      - type: status
        status: [200]

Un template "matchea" si TODOS sus matchers coinciden (AND simple, sin
la sofisticación completa de nuclei -- suficiente para detecciones
puntuales de la comunidad).
"""

import re
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

try:
    import requests
except ImportError:
    requests = None

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "detection-templates"


def cargar_templates():
    if yaml is None:
        print(colored("[!] PyYAML no instalado, se omite el motor de templates propio.", "yellow"))
        return []

    if not TEMPLATES_DIR.exists():
        return []

    templates = []
    for archivo in sorted(TEMPLATES_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(archivo.read_text(encoding="utf-8"))
            if data and "id" in data:
                templates.append(data)
        except Exception as e:
            print(colored(f"[!] Error cargando template {archivo.name}: {e}", "yellow"))

    return templates


def _evaluar_matcher(matcher, resp):
    tipo = matcher.get("type")

    if tipo == "status":
        return resp.status_code in matcher.get("status", [])

    if tipo == "word":
        palabras = matcher.get("words", [])
        condicion = matcher.get("condition", "or")  # or = al menos una; and = todas
        presencias = [w in resp.text for w in palabras]
        return all(presencias) if condicion == "and" else any(presencias)

    if tipo == "regex":
        patrones = matcher.get("regex", [])
        return any(re.search(p, resp.text) for p in patrones)

    return False


def _correr_template(template, url):
    if requests is None:
        return None

    info = template.get("info", {})
    peticion = template.get("request", {})
    matchers = template.get("matchers", [])

    path = peticion.get("path", "/")
    metodo = peticion.get("method", "GET").upper()

    target_url = url.rstrip("/") + path

    try:
        resp = requests.request(metodo, target_url, timeout=8, verify=False, allow_redirects=False)
    except Exception:
        return None

    if all(_evaluar_matcher(m, resp) for m in matchers):
        return {
            "template_id": template["id"],
            "nombre": info.get("name", template["id"]),
            "severity": info.get("severity", "info"),
            "url": target_url,
        }

    return None


def correr_templates(urls, folder):
    templates = cargar_templates()
    if not templates or not urls:
        return []

    print(colored(f"\n[+] Corriendo {len(templates)} template(s) de detección propios...", "cyan"))

    hallazgos = []
    for url in urls:
        for template in templates:
            resultado = _correr_template(template, url)
            if resultado:
                hallazgos.append(resultado)
                print(colored(f"[!] {resultado['nombre']} ({resultado['severity']}) en {resultado['url']}", "yellow"))

    _escribir_reporte(hallazgos, folder)
    return hallazgos


def _escribir_reporte(hallazgos, folder):
    output = folder / "06_vulnerabilities" / "custom-templates.md"
    output.parent.mkdir(parents=True, exist_ok=True)

    lines = ["# Detecciones de templates propios (detection-templates/)", ""]

    if not hallazgos:
        lines.append("Ningún template coincidió.")
    else:
        for h in hallazgos:
            lines.append(f"- **[{h['severity']}]** {h['nombre']} — {h['url']} (`{h['template_id']}`)")

    output.write_text("\n".join(lines), encoding="utf-8")

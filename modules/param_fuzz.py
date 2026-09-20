#!/usr/bin/env python3
"""
Fuzzing pasivo-agresivo de parámetros web comunes (--param-fuzz).

No es un scanner de SQLi/IDOR completo -- prueba una wordlist corta de
nombres de parámetros comunes (id, user, file, page, etc.) contra la
URL base, y solo señala una diferencia de longitud/status code notable
entre la respuesta base y la respuesta con el parámetro, como señal de
"esto merece que un humano lo mire", nunca como confirmación de
vulnerabilidad.
"""

try:
    import requests
except ImportError:
    requests = None

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored


PARAMETROS_COMUNES = [
    "id", "user", "username", "file", "page", "path", "redirect",
    "url", "next", "return", "q", "search", "category", "action",
    "debug", "test", "admin", "token",
]

VALORES_PRUEBA = ["1", "true", "admin"]


def _obtener_baseline(url):
    if requests is None:
        return None
    try:
        resp = requests.get(url, timeout=8, verify=False)
        return {"status": resp.status_code, "length": len(resp.text)}
    except Exception:
        return None


def fuzzear_parametros(urls, folder):
    if requests is None:
        print(colored("[!] Falta 'requests' para --param-fuzz.", "red"))
        return []

    hallazgos = []

    for base_url in urls or []:
        baseline = _obtener_baseline(base_url)
        if baseline is None:
            continue

        for parametro in PARAMETROS_COMUNES:
            for valor in VALORES_PRUEBA:
                url_prueba = f"{base_url.rstrip('/')}?{parametro}={valor}"

                try:
                    resp = requests.get(url_prueba, timeout=8, verify=False)
                except Exception:
                    continue

                diferencia_status = resp.status_code != baseline["status"]
                diferencia_longitud = abs(len(resp.text) - baseline["length"]) > 50

                if diferencia_status or diferencia_longitud:
                    hallazgos.append({
                        "url": url_prueba,
                        "parametro": parametro,
                        "valor": valor,
                        "status_baseline": baseline["status"],
                        "status_prueba": resp.status_code,
                        "diff_longitud": len(resp.text) - baseline["length"],
                    })

    _escribir_reporte(hallazgos, folder)
    return hallazgos


def _escribir_reporte(hallazgos, folder):
    output = folder / "06_vulnerabilities" / "param-fuzz.md"
    output.parent.mkdir(parents=True, exist_ok=True)

    lines = ["# Fuzzing de parámetros", "",
             "⚠️ Estas son diferencias de comportamiento, NO vulnerabilidades confirmadas. "
             "Requieren revisión manual.", ""]

    if not hallazgos:
        lines.append("No se detectaron diferencias de comportamiento notables.")
    else:
        for h in hallazgos:
            lines.append(
                f"- `{h['parametro']}={h['valor']}` en {h['url']}: "
                f"status {h['status_baseline']}→{h['status_prueba']}, "
                f"diff longitud {h['diff_longitud']:+d}"
            )

    output.write_text("\n".join(lines), encoding="utf-8")

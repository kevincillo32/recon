#!/usr/bin/env python3
"""
Comparación entre la corrida actual de findings.json y una anterior
(si existe un backup previo), para saber qué cambió entre dos ejecuciones
sobre la misma máquina.
"""

import json
import shutil
from datetime import datetime
try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored


def _cargar_findings(path):
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("findings", [])
    except Exception:
        return []


def comparar_y_archivar(folder):
    """
    Antes de sobreescribir findings.json, si ya existe uno de una corrida
    anterior lo compara y genera un diff.md. Luego archiva el anterior
    con timestamp para no perder histórico.
    """
    findings_path = folder / "06_vulnerabilities" / "findings.json"

    if not findings_path.exists():
        return  # primera corrida, nada que comparar

    anteriores = _cargar_findings(findings_path)
    if not anteriores:
        return

    # Archivar antes de que el nuevo run lo sobreescriba
    historial_folder = folder / "06_vulnerabilities" / "history"
    historial_folder.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = historial_folder / f"findings-{timestamp}.json"
    shutil.copy(findings_path, backup_path)

    print(colored(f"[i] findings.json anterior archivado en {backup_path}", "cyan"))

    return anteriores


def escribir_diff(folder, anteriores, actuales):
    if anteriores is None:
        return

    cves_antes = {f["cve"] for f in anteriores}
    cves_ahora = {f["cve"] for f in actuales}

    nuevos = cves_ahora - cves_antes
    resueltos = cves_antes - cves_ahora

    output = folder / "06_vulnerabilities" / "diff.md"
    lines = ["# Diff entre corridas", ""]

    if nuevos:
        lines.append("## Nuevos CVEs detectados")
        lines += [f"- {c}" for c in sorted(nuevos)]
    else:
        lines.append("## Sin CVEs nuevos")

    lines.append("")

    if resueltos:
        lines.append("## CVEs que ya no aparecen (posiblemente mitigados o falso positivo anterior)")
        lines += [f"- {c}" for c in sorted(resueltos)]
    else:
        lines.append("## Nada desapareció respecto a la corrida anterior")

    output.write_text("\n".join(lines), encoding="utf-8")

    if nuevos or resueltos:
        print(colored(f"[!] Cambios detectados respecto a la corrida anterior — ver {output}", "yellow"))

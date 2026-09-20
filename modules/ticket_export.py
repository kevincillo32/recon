#!/usr/bin/env python3
"""
Exporta cada finding como un "ticket" en CSV (formato de importación
genérico de Jira) y JSON (formato más flexible para Trello vía API
o scripts propios).
"""

import csv
import json
from pathlib import Path

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored


def _severidad_a_prioridad(severity):
    mapa = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
    return mapa.get((severity or "").upper(), "Medium")


def exportar_csv(findings, folder, ip):
    output = folder / "06_vulnerabilities" / "tickets.csv"
    output.parent.mkdir(parents=True, exist_ok=True)

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Summary", "Description", "Priority", "Labels", "Status"])

        for finding in findings or []:
            resumen = f"[{ip}] {finding.get('cve', 'Finding')} en {finding.get('product', '')}"
            descripcion = (
                f"CVE: {finding.get('cve')}\n"
                f"Producto: {finding.get('product')} {finding.get('version')}\n"
                f"Puerto: {finding.get('port')}\n"
                f"Confianza: {finding.get('confidence')}\n"
                f"Descripción: {finding.get('description', '')[:200]}"
            )
            writer.writerow([
                resumen, descripcion, _severidad_a_prioridad(finding.get("severity")),
                f"recon,{finding.get('status', '').lower()}", "To Do",
            ])

    print(colored(f"[+] Tickets CSV exportados a {output}", "green"))
    return output


def exportar_json(findings, folder, ip):
    output = folder / "06_vulnerabilities" / "tickets.json"
    output.parent.mkdir(parents=True, exist_ok=True)

    tickets = [
        {
            "title": f"[{ip}] {f.get('cve', 'Finding')} en {f.get('product', '')}",
            "description": f.get("description", ""),
            "priority": _severidad_a_prioridad(f.get("severity")),
            "labels": ["recon", (f.get("status") or "").lower()],
            "cve": f.get("cve"),
            "port": f.get("port"),
        }
        for f in (findings or [])
    ]

    output.write_text(json.dumps(tickets, indent=2, ensure_ascii=False), encoding="utf-8")
    print(colored(f"[+] Tickets JSON exportados a {output}", "green"))
    return output


def exportar_tickets(findings, folder, ip, formato="ambos"):
    if formato in ("csv", "ambos"):
        exportar_csv(findings, folder, ip)
    if formato in ("json", "ambos"):
        exportar_json(findings, folder, ip)

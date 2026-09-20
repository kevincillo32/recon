#!/usr/bin/env python3
"""
Soporte multi-idioma para los reportes generados (--lang en|es).
No traduce la interfaz de la CLI (eso seguiría en español, dado que es
el idioma en el que se escribió y mantiene el proyecto) -- traduce
específicamente el CONTENIDO de los reportes (README, findings.md,
PDF), que es lo que de verdad viaja fuera de tu propio uso personal
cuando compartes el resultado con alguien más.
"""

STRINGS = {
    "es": {
        "attack_surface_title": "Superficie de Ataque",
        "open_ports": "Puertos Abiertos",
        "hostnames": "Hostnames",
        "potential_entry_points": "Posibles Puntos de Entrada",
        "vulnerability_findings": "Hallazgos de Vulnerabilidades",
        "no_findings": "No se encontraron correlaciones de CVE.",
        "executive_summary": "Resumen Ejecutivo",
        "methodology": "Metodología",
        "target": "Objetivo",
        "machine": "Máquina",
        "analyst": "Analista",
        "date": "Fecha",
    },
    "en": {
        "attack_surface_title": "Attack Surface",
        "open_ports": "Open Ports",
        "hostnames": "Hostnames",
        "potential_entry_points": "Potential Entry Points",
        "vulnerability_findings": "Vulnerability Findings",
        "no_findings": "No CVE correlations were found.",
        "executive_summary": "Executive Summary",
        "methodology": "Methodology",
        "target": "Target",
        "machine": "Machine",
        "analyst": "Analyst",
        "date": "Date",
    },
}


def t(clave, idioma="es"):
    """Traduce una clave; si no existe o el idioma no está soportado, cae a español."""
    return STRINGS.get(idioma, STRINGS["es"]).get(clave, STRINGS["es"].get(clave, clave))

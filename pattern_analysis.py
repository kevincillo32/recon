#!/usr/bin/env python3
"""
pattern_analysis.py - Analiza el histórico acumulado en ~/.recon/history.db
para generar un reporte personal de patrones: qué vectores usaste más,
qué combinaciones de puertos suelen coincidir con qué tipo de hallazgo.

Uso independiente:
    python3 pattern_analysis.py
"""

import json
from collections import Counter
from modules.history_db import _conectar


def analizar_patrones():
    conn = _conectar()
    cur = conn.cursor()

    cur.execute("SELECT ip, tcp_ports, udp_ports FROM runs")
    runs = cur.fetchall()

    cur.execute("SELECT product, severity, port FROM findings WHERE product IS NOT NULL")
    findings = cur.fetchall()

    conn.close()

    total_runs = len(runs)

    puertos_contador = Counter()
    combinaciones_contador = Counter()

    for _, tcp_json, _ in runs:
        try:
            puertos = json.loads(tcp_json or "[]")
        except Exception:
            puertos = []

        for p in puertos:
            puertos_contador[p] += 1

        # Combinaciones de a pares, para detectar patrones tipo "445+8080"
        puertos_ordenados = sorted(puertos)
        for i in range(len(puertos_ordenados)):
            for j in range(i + 1, len(puertos_ordenados)):
                combinaciones_contador[(puertos_ordenados[i], puertos_ordenados[j])] += 1

    productos_contador = Counter(f[0] for f in findings)
    severidad_contador = Counter(f[1] for f in findings)

    return {
        "total_runs": total_runs,
        "puertos_mas_comunes": puertos_contador.most_common(10),
        "combinaciones_mas_comunes": combinaciones_contador.most_common(10),
        "productos_con_findings": productos_contador.most_common(10),
        "severidades": severidad_contador.most_common(),
    }


def generar_reporte_texto(analisis):
    lines = ["# Análisis de patrones personales", "",
             f"Basado en {analisis['total_runs']} corrida(s) registradas.", ""]

    lines.append("## Puertos más frecuentes en tus máquinas")
    for puerto, count in analisis["puertos_mas_comunes"]:
        lines.append(f"- Puerto {puerto}: visto en {count} corrida(s)")

    lines.append("")
    lines.append("## Combinaciones de puertos que más se repiten")
    for (p1, p2), count in analisis["combinaciones_mas_comunes"]:
        lines.append(f"- {p1} + {p2}: {count} vez/veces")

    lines.append("")
    lines.append("## Productos donde más encontraste vulnerabilidades")
    for producto, count in analisis["productos_con_findings"]:
        lines.append(f"- {producto}: {count} finding(s)")

    lines.append("")
    lines.append("## Distribución de severidad de tus findings históricos")
    for severidad, count in analisis["severidades"]:
        lines.append(f"- {severidad}: {count}")

    return "\n".join(lines)


if __name__ == "__main__":
    analisis = analizar_patrones()
    print(generar_reporte_texto(analisis))

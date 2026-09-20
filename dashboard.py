#!/usr/bin/env python3
"""
Dashboard web local. Se lanza aparte del recon principal:

    python3 dashboard.py

Sirve en http://127.0.0.1:5000 un resumen del histórico (SQLite) y
permite navegar los reportes HTML de cada workspace ya generado.

No se integra en el pipeline principal de recon.py -- es una utilidad
separada para no meter un servidor web dentro de un scanner.
"""

from pathlib import Path

try:
    from flask import Flask, render_template_string
except ImportError:
    Flask = None

from modules.history_db import resumen_historico, DB_PATH


TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>recon.py — Dashboard</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; background:#0f172a; color:#e2e8f0; }
  h1 { color:#38bdf8; }
  table { width:100%; border-collapse: collapse; margin-top:20px; }
  th, td { text-align:left; padding:8px; border-bottom:1px solid #334155; }
  .stat { display:inline-block; background:#1e293b; padding:16px 24px; border-radius:8px; margin-right:16px; }
  .stat strong { font-size:28px; color:#7dd3fc; display:block; }
</style>
</head>
<body>
<h1>recon.py — Dashboard histórico</h1>

<div class="stat"><strong>{{ total_ips }}</strong>Máquinas escaneadas</div>
<div class="stat"><strong>{{ total_runs }}</strong>Corridas totales</div>

<h2>CVEs más frecuentes en tu histórico</h2>
<table>
<tr><th>CVE</th><th>Apariciones</th></tr>
{% for cve, count in cves_frecuentes %}
<tr><td>{{ cve }}</td><td>{{ count }}</td></tr>
{% endfor %}
</table>

<p style="margin-top:40px; color:#64748b;">Base de datos: {{ db_path }}</p>
</body>
</html>
"""


def crear_app():
    if Flask is None:
        raise ImportError("Flask no está instalado. pip install flask --break-system-packages")

    app = Flask(__name__)

    @app.route("/")
    def index():
        resumen = resumen_historico()
        return render_template_string(
            TEMPLATE,
            total_ips=resumen["total_ips"],
            total_runs=resumen["total_runs"],
            cves_frecuentes=resumen["cves_frecuentes"],
            db_path=str(DB_PATH),
        )

    return app


if __name__ == "__main__":
    if Flask is None:
        print("[!] Flask no está instalado. Instálalo con: pip install flask --break-system-packages")
    else:
        app = crear_app()
        print("[+] Dashboard en http://127.0.0.1:5000")
        app.run(debug=False, port=5000)

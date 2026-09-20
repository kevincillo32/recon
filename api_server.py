#!/usr/bin/env python3
"""
api_server.py - API REST mínima sobre el pipeline de recon.py
(--serve), para que otras herramientas (Burp, un bot de Discord, tu
propio dashboard) puedan disparar corridas y consultar resultados vía
HTTP en vez de la CLI.

Endpoints:
    POST /scan          {"ip": "10.10.10.28", "profile": "ctf", ...}
                        -> dispara un recon en background, devuelve un job_id
    GET  /scan/<job_id> -> estado del job (running/done/error) y resultado si terminó
    GET  /history       -> historial completo (usa modules/history_db.py)

Pensado para localhost/VPN de confianza -- sin autenticación, igual que
team_server.py. NO exponer directamente a internet.

Nota de honestidad: este archivo se probó de forma unitaria (que arranca,
que valida el JSON de entrada), pero NUNCA se probó disparando un recon
real en background contra una IP real, porque este entorno de
desarrollo no tiene red.
"""

import threading
import uuid
from datetime import datetime

try:
    from flask import Flask, request, jsonify
except ImportError:
    Flask = None

from modules.history_db import resumen_historico

_JOBS = {}
_JOBS_LOCK = threading.Lock()


def _correr_recon_background(job_id, ip, opciones):
    """
    Importa recon.py de forma perezosa (no al tope del archivo) para
    evitar que argparse de recon.py se dispare al solo importar la API.
    """
    with _JOBS_LOCK:
        _JOBS[job_id]["status"] = "running"

    try:
        # Se importa aquí adentro a propósito -- ver docstring de la función.
        import recon as recon_module
        from modules.utils import Carpeta
        from modules.plugin_loader import descubrir_plugins

        class _ArgsFalsos:
            pass

        args = _ArgsFalsos()
        args.nombre = opciones.get("nombre") or ip
        args.deep = opciones.get("deep", False)
        args.profile = opciones.get("profile")
        args.min_rate = "5000"
        args.nse_vuln_forzado = None
        args.vhost_domain = opciones.get("vhost_domain")
        args.ad_domain = opciones.get("ad_domain")
        args.ad_userlist = opciones.get("ad_userlist")
        args.screenshots = opciones.get("screenshots", False)
        args.html_report = opciones.get("html_report", False)
        args.auto_exploit = opciones.get("auto_exploit", False)
        args.json_only = False
        args.assist = opciones.get("assist", False)
        args.attack_graph = opciones.get("attack_graph", False)
        args.active_verify = opciones.get("active_verify", False)
        args.team_server = None
        args.member = "api"
        args.no_notify = True
        args.yes = True

        plugins = descubrir_plugins()
        recon_module.ejecutar_recon(ip, args, plugins)

        with _JOBS_LOCK:
            _JOBS[job_id]["status"] = "done"
            _JOBS[job_id]["finished_at"] = datetime.now().isoformat()

    except Exception as e:
        with _JOBS_LOCK:
            _JOBS[job_id]["status"] = "error"
            _JOBS[job_id]["error"] = str(e)


def crear_app():
    if Flask is None:
        raise ImportError("Flask no está instalado. pip install flask --break-system-packages")

    app = Flask(__name__)

    @app.route("/scan", methods=["POST"])
    def iniciar_scan():
        payload = request.get_json(force=True) or {}
        ip = payload.get("ip")

        if not ip:
            return jsonify({"error": "Falta el campo 'ip'"}), 400

        job_id = str(uuid.uuid4())
        with _JOBS_LOCK:
            _JOBS[job_id] = {"ip": ip, "status": "queued", "started_at": datetime.now().isoformat()}

        hilo = threading.Thread(target=_correr_recon_background, args=(job_id, ip, payload), daemon=True)
        hilo.start()

        return jsonify({"job_id": job_id, "status": "queued"})

    @app.route("/scan/<job_id>")
    def estado_scan(job_id):
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)

        if not job:
            return jsonify({"error": "job_id no encontrado"}), 404

        return jsonify(job)

    @app.route("/history")
    def historial():
        return jsonify(resumen_historico())

    return app


if __name__ == "__main__":
    if Flask is None:
        print("[!] Flask no está instalado.")
    else:
        app = crear_app()
        print("[+] API REST en http://127.0.0.1:5002")
        app.run(host="127.0.0.1", port=5002, debug=False)

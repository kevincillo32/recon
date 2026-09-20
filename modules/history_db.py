#!/usr/bin/env python3
"""
Base de datos SQLite centralizada (fuera de cada workspace individual)
que acumula histórico de todas las corridas: qué máquinas escaneaste,
qué CVEs viste, en qué máquinas se repite un mismo CVE, etc.

Vive en ~/.recon/history.db por defecto (fuera del workspace de cada
máquina, para que sobreviva aunque borres una carpeta puntual).
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

DB_PATH = Path.home() / ".recon" / "history.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    workspace TEXT NOT NULL,
    started_at TEXT NOT NULL,
    tcp_ports TEXT,
    udp_ports TEXT,
    hostnames TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    cve TEXT,
    severity TEXT,
    cvss REAL,
    confidence TEXT,
    status TEXT,
    product TEXT,
    version TEXT,
    port TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve);
CREATE INDEX IF NOT EXISTS idx_runs_ip ON runs(ip);
"""


def _conectar():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    return conn


def registrar_corrida(ip, workspace_nombre, puertos_tcp, puertos_udp, hostnames, findings):
    """Inserta una nueva corrida y sus findings asociados."""
    conn = _conectar()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO runs (ip, workspace, started_at, tcp_ports, udp_ports, hostnames) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            ip, str(workspace_nombre), datetime.now().isoformat(),
            json.dumps(puertos_tcp), json.dumps(puertos_udp), json.dumps(hostnames),
        ),
    )
    run_id = cur.lastrowid

    for f in findings or []:
        cur.execute(
            "INSERT INTO findings (run_id, ip, cve, severity, cvss, confidence, status, product, version, port) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id, ip, f.get("cve"), f.get("severity"), f.get("cvss"),
                f.get("confidence"), f.get("status"), f.get("product"),
                f.get("version"), f.get("port"),
            ),
        )

    conn.commit()
    conn.close()

    print(colored(f"[+] Corrida registrada en histórico: {DB_PATH}", "green"))
    return run_id


def buscar_cve_en_historico(cve_id):
    """¿En qué otras máquinas/corridas ha aparecido este CVE?"""
    conn = _conectar()
    cur = conn.cursor()

    cur.execute(
        "SELECT runs.ip, runs.workspace, runs.started_at, findings.confidence, findings.status "
        "FROM findings JOIN runs ON findings.run_id = runs.id "
        "WHERE findings.cve = ? ORDER BY runs.started_at DESC",
        (cve_id,),
    )
    filas = cur.fetchall()
    conn.close()
    return filas


def resumen_historico():
    """Estadísticas generales: total de máquinas, CVEs más repetidos, etc."""
    conn = _conectar()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(DISTINCT ip) FROM runs")
    total_ips = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM runs")
    total_runs = cur.fetchone()[0]

    cur.execute(
        "SELECT cve, COUNT(*) as c FROM findings WHERE cve IS NOT NULL "
        "GROUP BY cve ORDER BY c DESC LIMIT 10"
    )
    cves_frecuentes = cur.fetchall()

    conn.close()
    return {
        "total_ips": total_ips,
        "total_runs": total_runs,
        "cves_frecuentes": cves_frecuentes,
    }

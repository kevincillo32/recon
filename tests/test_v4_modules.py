import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import checkpoints, i18n, ticket_export, team_webhooks


def test_checkpoint_detecta_archivo_no_vacio(tmp_path):
    (tmp_path / "06_vulnerabilities").mkdir()
    (tmp_path / "06_vulnerabilities" / "findings.json").write_text("{}")

    assert checkpoints.fase_completa(tmp_path, "vuln_correlation") is True


def test_checkpoint_falso_sin_archivo(tmp_path):
    assert checkpoints.fase_completa(tmp_path, "vuln_correlation") is False


def test_checkpoint_udp_respeta_deep(tmp_path):
    (tmp_path / "03_nmap").mkdir()
    (tmp_path / "03_nmap" / "udpTop1000").write_text("algo")

    assert checkpoints.fase_completa(tmp_path, "udp", deep=True) is True
    assert checkpoints.fase_completa(tmp_path, "udp", deep=False) is False


def test_i18n_traduce_correctamente():
    assert i18n.t("executive_summary", "en") == "Executive Summary"
    assert i18n.t("executive_summary", "es") == "Resumen Ejecutivo"


def test_i18n_cae_a_espanol_si_falta_clave():
    assert i18n.t("clave_inexistente", "en") == "clave_inexistente"


def test_ticket_export_csv_y_json(tmp_path):
    findings = [
        {"cve": "CVE-2021-41773", "severity": "HIGH", "product": "Apache",
         "version": "2.4.49", "port": "80", "confidence": "HIGH",
         "status": "VERIFIED", "description": "Path traversal"},
    ]
    ticket_export.exportar_tickets(findings, tmp_path, "10.10.10.28", formato="ambos")

    csv_path = tmp_path / "06_vulnerabilities" / "tickets.csv"
    json_path = tmp_path / "06_vulnerabilities" / "tickets.json"

    assert csv_path.exists()
    assert json_path.exists()

    tickets = json.loads(json_path.read_text())
    assert tickets[0]["priority"] == "High"
    assert tickets[0]["cve"] == "CVE-2021-41773"


def test_webhook_payload_discord_valido():
    findings = [{"cve": "CVE-2021-41773", "severity": "CRITICAL"}]
    payload = team_webhooks.validar_payload("discord", "alice", "10.10.10.28", findings)
    assert "embeds" in payload
    assert "10.10.10.28" in payload["embeds"][0]["title"]


def test_webhook_payload_slack_valido():
    findings = [{"cve": "CVE-2021-41773", "severity": "LOW"}]
    payload = team_webhooks.validar_payload("slack", "alice", "10.10.10.28", findings)
    assert "text" in payload
    assert "alice" in payload["text"]

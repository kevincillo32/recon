#!/usr/bin/env python3
"""
Notificaciones de equipo vía webhook (Discord o Slack), disparadas
cuando alguien envía una corrida al team_server.py (ver
team_server.enviar_corrida) o directamente desde recon.py con
--webhook-url.

Ambos formatos (Discord embeds, Slack blocks) se generan localmente --
un solo POST, sin SDK de terceros.

Nota de honestidad: nunca se probó contra un webhook real (requeriría
un servidor de Discord/Slack real y red), solo se validó que el payload
generado es JSON válido con la forma que cada plataforma documenta.
"""

import json

try:
    import requests
except ImportError:
    requests = None

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored


def _payload_discord(member, ip, findings):
    high_severity = [f for f in findings if (f.get("severity") or "").upper() in ("HIGH", "CRITICAL")]

    descripcion = f"**{member}** completó un recon de `{ip}`\n"
    descripcion += f"Findings totales: {len(findings)}"
    if high_severity:
        descripcion += f"\n⚠️ {len(high_severity)} de severidad alta/crítica:\n"
        descripcion += "\n".join(f"- {f.get('cve')}" for f in high_severity[:5])

    return {
        "embeds": [{
            "title": f"Recon completado: {ip}",
            "description": descripcion,
            "color": 15158332 if high_severity else 3066993,
        }]
    }


def _payload_slack(member, ip, findings):
    high_severity = [f for f in findings if (f.get("severity") or "").upper() in ("HIGH", "CRITICAL")]

    texto = f"*{member}* completó un recon de `{ip}` — {len(findings)} finding(s)"
    if high_severity:
        texto += f"\n⚠️ {len(high_severity)} de severidad alta/crítica: " + ", ".join(
            f.get("cve", "?") for f in high_severity[:5]
        )

    return {"text": texto}


def notificar_equipo(webhook_url, plataforma, member, ip, findings):
    """
    `plataforma` es "discord" o "slack" -- determina el formato del
    payload. Falla en silencio (con print) si no hay red, para no
    interrumpir el recon principal por un webhook caído.
    """
    if requests is None:
        print(colored("[!] Falta 'requests' para notificar al equipo.", "yellow"))
        return False

    if plataforma == "discord":
        payload = _payload_discord(member, ip, findings)
    elif plataforma == "slack":
        payload = _payload_slack(member, ip, findings)
    else:
        print(colored(f"[!] Plataforma de webhook desconocida: {plataforma}", "yellow"))
        return False

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        print(colored(f"[+] Notificación enviada a {plataforma}.", "green"))
        return True
    except Exception as e:
        print(colored(f"[!] No se pudo notificar al equipo ({plataforma}): {e}", "yellow"))
        return False


def validar_payload(plataforma, member, ip, findings):
    """Construye el payload y valida que sea JSON serializable, sin enviar nada."""
    if plataforma == "discord":
        payload = _payload_discord(member, ip, findings)
    else:
        payload = _payload_slack(member, ip, findings)

    json.dumps(payload)  # lanza si no es serializable
    return payload

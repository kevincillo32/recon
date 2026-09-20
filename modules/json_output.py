#!/usr/bin/env python3
"""
Modo --json-only: al final del recon, imprime un único JSON a stdout
(sin colores, sin logs intermedios en stdout -- esos van a recon.log)
para que otro script pueda hacer:

    resultado = json.loads(subprocess.check_output(["python3", "recon.py", ip, "--json-only"]))
"""

import json
import sys

_STDOUT_ORIGINAL = sys.stdout


def emitir_resultado_json(ip, workspace, puertos_tcp, puertos_udp, hostnames, findings):
    payload = {
        "ip": ip,
        "workspace": str(workspace),
        "tcp_ports": puertos_tcp,
        "udp_ports": puertos_udp,
        "hostnames": hostnames,
        "findings_count": len(findings or []),
        "findings": findings or [],
    }
    # Se usa el stdout original (guardado antes de silenciar) para que el
    # JSON final salga limpio incluso si silenciar_stdout_normal() ya
    # redirigió sys.stdout a stderr.
    print(json.dumps(payload, indent=2), file=_STDOUT_ORIGINAL)


def silenciar_stdout_normal():
    """
    Redirige los prints "cosméticos" (colored/banner) a stderr para que
    stdout quede limpio solo para el JSON final. Se activa solo si
    --json-only está presente.
    """
    sys.stdout = sys.stderr

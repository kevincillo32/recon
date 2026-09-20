import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import attack_graph


def test_construir_grafo_relaciona_credencial_smb_con_otros_puertos():
    context = {"puertos": [22, 445, 5985], "hostnames": []}
    findings = []
    credenciales = [{"archivo": "05_services/smb/smbclient.txt", "tipo": "password_generic", "valor": "x"}]

    grafo = attack_graph.construir_grafo(context, findings, credenciales)

    relaciones = {(a["origen"], a["destino"], a["relacion"]) for a in grafo["aristas"]}

    assert ("port:445", "cred:0", "expuso") in relaciones
    assert ("cred:0", "port:22", "podría_probarse_en") in relaciones
    assert ("cred:0", "port:5985", "podría_probarse_en") in relaciones
    # No debe sugerirse probar la credencial contra el mismo puerto de donde salió
    assert ("cred:0", "port:445", "podría_probarse_en") not in relaciones


def test_grafo_vacio_sin_datos():
    grafo = attack_graph.construir_grafo({"puertos": [], "hostnames": []}, [], [])
    assert grafo["nodos"] == []
    assert grafo["aristas"] == []


def test_sugerir_caminos_encuentra_reuso_de_credenciales():
    grafo = {
        "nodos": [],
        "aristas": [{"origen": "cred:0", "destino": "port:22", "relacion": "podría_probarse_en"}],
    }
    sugerencias = attack_graph.sugerir_caminos(grafo)
    assert any("cred:0" in s and "port:22" in s for s in sugerencias)

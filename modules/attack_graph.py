#!/usr/bin/env python3
"""
Grafo de ataque: en vez de una lista plana de findings, modela
relaciones entre nodos (puertos, servicios, credenciales, CVEs,
hostnames) para sugerir caminos de ataque conectados.

Ejemplo de relación que este módulo detecta:
    SMB anónimo (445) -- expuso credencial -- podría servir en WinRM (5985)

No requiere librerías pesadas de grafos para casos simples: usa
networkx si está disponible (mejor detección de rutas), y si no,
cae a un modelo de adyacencia simple en diccionarios puro-Python.
"""

import json
try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

try:
    import networkx as nx
except ImportError:
    nx = None


# Puertos que casi siempre implican una superficie de autenticación,
# para poder sugerir "esta credencial podría sondearse aquí".
PUERTOS_AUTH = {
    22: "SSH", 445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM (HTTPS)",
    21: "FTP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 389: "LDAP",
}


def construir_grafo(context, findings, credenciales):
    """
    Nodos: puertos abiertos, CVEs, credenciales encontradas, hostnames.
    Aristas: relaciones conocidas (mismo host, credencial reusable, etc.)
    """
    puertos = context.get("puertos", []) or []
    hostnames = context.get("hostnames", []) or []

    nodos = []
    aristas = []

    for p in puertos:
        nodos.append({"id": f"port:{p}", "tipo": "puerto", "label": f"{p}/{PUERTOS_AUTH.get(p, 'tcp')}"})

    for f in findings or []:
        cve_id = f.get("cve")
        if not cve_id:
            continue
        nodos.append({"id": f"cve:{cve_id}", "tipo": "cve", "label": cve_id,
                       "severity": f.get("severity")})
        if f.get("port"):
            aristas.append({"origen": f"port:{f['port']}", "destino": f"cve:{cve_id}",
                             "relacion": "vulnerable_a"})

    for i, cred in enumerate(credenciales or []):
        cred_id = f"cred:{i}"
        nodos.append({"id": cred_id, "tipo": "credencial", "label": cred.get("valor", "")[:40]})

        # Si la credencial vino de un archivo bajo 05_services/smb, la
        # conectamos con el puerto 445, y sugerimos probarla contra
        # cualquier otro puerto de autenticación detectado.
        origen_archivo = cred.get("archivo", "")
        if "smb" in origen_archivo:
            aristas.append({"origen": "port:445", "destino": cred_id, "relacion": "expuso"})

        for p in puertos:
            if p in PUERTOS_AUTH and f"port:{p}" != "port:445":
                aristas.append({"origen": cred_id, "destino": f"port:{p}",
                                 "relacion": "podría_probarse_en"})

    for h in hostnames:
        nodos.append({"id": f"host:{h}", "tipo": "hostname", "label": h})

    return {"nodos": nodos, "aristas": aristas}


def guardar_grafo(grafo, folder):
    output = folder / "06_vulnerabilities" / "attack-graph.json"
    output.write_text(json.dumps(grafo, indent=2, ensure_ascii=False), encoding="utf-8")
    print(colored(f"[+] Grafo de ataque guardado en {output}", "green"))
    return output


def sugerir_caminos(grafo):
    """
    Camino simple: credencial -> puerto donde probarla. Si hay networkx,
    también calcula el nodo con más conexiones (posible pivote central).
    """
    sugerencias = []

    for arista in grafo["aristas"]:
        if arista["relacion"] == "podría_probarse_en":
            sugerencias.append(
                f"{arista['origen']} → probar reuso de credencial en {arista['destino']}"
            )

    if nx is not None and grafo["nodos"]:
        g = nx.DiGraph()
        for n in grafo["nodos"]:
            g.add_node(n["id"], **n)
        for a in grafo["aristas"]:
            g.add_edge(a["origen"], a["destino"], relacion=a["relacion"])

        if g.number_of_nodes() > 0:
            centralidad = nx.degree_centrality(g)
            nodo_central = max(centralidad, key=centralidad.get)
            sugerencias.append(f"Nodo con más conexiones (posible pivote clave): {nodo_central}")

    return sugerencias


def generar_grafo_de_ataque(context, findings, credenciales, folder):
    grafo = construir_grafo(context, findings, credenciales)
    guardar_grafo(grafo, folder)

    sugerencias = sugerir_caminos(grafo)
    if sugerencias:
        print(colored("\n[+] Caminos de ataque sugeridos:", "cyan"))
        for s in sugerencias:
            print(f"    - {s}")

    return grafo

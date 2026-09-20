#!/usr/bin/env python3
"""
Corre en paralelo los módulos de servicio que no dependen entre sí
(SMB, FTP, DNS, SNMP, LDAP, SMTP, databases todos leen los mismos
puertos ya escaneados y escriben en carpetas distintas, así que no hay
condición de carrera real entre ellos).

Nmap TCP/UDP y el enum de servicios detallado (nmap -sCV) SIGUEN siendo
secuenciales porque son prerequisito de todo lo demás.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored


def correr_en_paralelo(tareas, max_workers=6):
    """
    `tareas` es una lista de tuplas (nombre, func, args_tuple).
    Cada func se ejecuta en su propio thread. Como todas estas tareas
    son I/O-bound (esperan a subprocess/nmap/curl), threads son
    suficientes -- no hace falta multiprocessing.
    """
    resultados = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futuros = {
            executor.submit(func, *args): nombre
            for nombre, func, args in tareas
        }

        for futuro in as_completed(futuros):
            nombre = futuros[futuro]
            try:
                resultados[nombre] = futuro.result()
            except Exception as e:
                print(colored(f"[!] Error en módulo paralelo '{nombre}': {e}", "red"))
                resultados[nombre] = None

    return resultados

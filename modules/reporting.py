#!/usr/bin/env python3
"""Genera README.md y attack-surface.md a partir de los resultados de recon."""

from termcolor import colored

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 139: "SMB", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3268: "LDAP-GC",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-alt", 27017: "MongoDB",
}


def generar_attack_surface(ip, folder, puertos_tcp, puertos_udp, hostnames):
    lines = [
        "# Attack Surface", "",
        "## Network", "", ip, "",
        "## TCP", "",
    ]
    for p in puertos_tcp:
        lines.append(f"{p}\t{SERVICE_NAMES.get(p, '?')}")

    lines += ["", "## UDP", ""]
    for p in puertos_udp:
        lines.append(f"{p}\t{SERVICE_NAMES.get(p, '?')}")

    if hostnames:
        lines += ["", "## Hostnames", ""]
        lines += [f"- {h}" for h in hostnames]

    lines += ["", "## Potential entry points", ""]
    entry_points = sorted(set(SERVICE_NAMES.get(p, str(p)) for p in puertos_tcp))
    lines += [f"{i+1}. {ep}" for i, ep in enumerate(entry_points)]

    output = folder / "attack-surface.md"
    output.write_text("\n".join(lines), encoding="utf-8")
    print(colored(f"[+] attack-surface.md generado en {output}", "green"))


def generar_readme(ip, folder, puertos_tcp, hostnames):
    nombre_maquina = folder.nombre.name if hasattr(folder, "nombre") else folder.name

    lines = [
        f"# {nombre_maquina}", "",
        "## Target", "", ip, "",
        "## Open Ports", "",
        "| Port | Protocol | Service |",
        "|------|----------|---------|",
    ]
    for p in puertos_tcp:
        lines.append(f"| {p} | TCP | {SERVICE_NAMES.get(p, '?')} |")

    if hostnames:
        lines += ["", "## Hostnames", ""]
        lines += [f"- {h}" for h in hostnames]

    lines += [
        "", "## Web", "", "(completar tras revisar 04_web/)",
        "", "## Potential Vulnerabilities", "",
        "(ver 06_vulnerabilities/nmap-vuln.txt)",
        "", "## Credentials", "", "- ...",
        "", "## Notes", "", "",
    ]

    output = folder / "README.md" if not hasattr(folder, "nombre") else folder.nombre / "README.md"
    output.write_text("\n".join(lines), encoding="utf-8")
    print(colored(f"[+] README.md generado en {output}", "green"))

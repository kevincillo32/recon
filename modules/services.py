#!/usr/bin/env python3
"""Módulos de enumeración por servicio: SMB, FTP, DNS, SNMP, LDAP, SMTP, DBs."""

from termcolor import colored

from modules.utils import run_command, tool_exists

SMB_PORTS = {139, 445}
FTP_PORTS = {21}
DNS_PORTS = {53}
SNMP_PORTS = {161}
LDAP_PORTS = {389, 636, 3268, 3269}
SMTP_PORTS = {25, 465, 587}
DB_PORTS = {
    3306: "mysql", 5432: "postgres", 1433: "mssql",
    6379: "redis", 27017: "mongodb", 9200: "elasticsearch",
}


def smb_recon(ip, folder, puertos):
    if not (set(puertos) & SMB_PORTS):
        return

    smb_folder = folder / "05_services" / "smb"
    smb_folder.mkdir(parents=True, exist_ok=True)

    run_command([
        "nmap", "-p", "139,445", "--script",
        "smb-os-discovery,smb-protocols,smb-security-mode,smb-enum-shares,smb-enum-users",
        ip, "-oN", str(smb_folder / "nmap-smb.txt")
    ])

    if tool_exists("smbclient"):
        run_command(["smbclient", "-L", f"//{ip}/", "-N"], smb_folder / "smbclient.txt")

    if tool_exists("enum4linux-ng"):
        run_command(["enum4linux-ng", "-A", ip], smb_folder / "enum4linux-ng.txt")

    if tool_exists("smbmap"):
        run_command(["smbmap", "-H", ip], smb_folder / "smbmap.txt")


def ftp_recon(ip, folder, puertos):
    if FTP_PORTS.isdisjoint(puertos):
        return

    ftp_folder = folder / "05_services" / "ftp"
    ftp_folder.mkdir(parents=True, exist_ok=True)

    run_command([
        "nmap", "-p21", "--script", "ftp-anon,ftp-syst",
        ip, "-oN", str(ftp_folder / "nmap-ftp.txt")
    ])


def dns_recon(ip, folder, puertos):
    if DNS_PORTS.isdisjoint(puertos):
        return

    dns_folder = folder / "05_services" / "dns"
    dns_folder.mkdir(parents=True, exist_ok=True)

    if tool_exists("dig"):
        for record in ["A", "NS", "MX", "TXT"]:
            run_command([
                "dig", f"@{ip}", record, "localhost"
            ], dns_folder / f"dig-{record}.txt")

    run_command([
        "nmap", "-p53", "--script", "dns-recursion,dns-service-discovery",
        ip, "-oN", str(dns_folder / "nmap-dns.txt")
    ])


def snmp_recon(ip, folder, puertos):
    if SNMP_PORTS.isdisjoint(puertos):
        return

    snmp_folder = folder / "05_services" / "snmp"
    snmp_folder.mkdir(parents=True, exist_ok=True)

    if tool_exists("snmpwalk"):
        run_command(["snmpwalk", "-v2c", "-c", "public", ip], snmp_folder / "snmpwalk-public.txt")

    run_command([
        "nmap", "-sU", "-p161", "--script", "snmp-info",
        ip, "-oN", str(snmp_folder / "nmap-snmp.txt")
    ])


def ldap_recon(ip, folder, puertos):
    if not (set(puertos) & LDAP_PORTS):
        return

    ldap_folder = folder / "05_services" / "ldap"
    ldap_folder.mkdir(parents=True, exist_ok=True)

    run_command([
        "nmap", "-p", "389,636,3268,3269", "--script",
        "ldap-rootdse,ldap-search",
        ip, "-oN", str(ldap_folder / "nmap-ldap.txt")
    ])

    if tool_exists("ldapsearch"):
        run_command([
            "ldapsearch", "-x", "-H", f"ldap://{ip}", "-s", "base", "namingcontexts"
        ], ldap_folder / "ldapsearch-rootdse.txt")


def smtp_recon(ip, folder, puertos):
    if not (set(puertos) & SMTP_PORTS):
        return

    smtp_folder = folder / "05_services" / "smtp"
    smtp_folder.mkdir(parents=True, exist_ok=True)

    ports = ",".join(str(p) for p in sorted(set(puertos) & SMTP_PORTS))
    run_command([
        "nmap", "-p", ports, "--script", "smtp-commands,smtp-enum-users",
        ip, "-oN", str(smtp_folder / "nmap-smtp.txt")
    ])


def database_recon(ip, folder, puertos):
    detected = {p: name for p, name in DB_PORTS.items() if p in puertos}
    if not detected:
        return

    db_folder = folder / "05_services" / "databases"
    db_folder.mkdir(parents=True, exist_ok=True)

    for port, name in detected.items():
        run_command([
            "nmap", "-sV", "-p", str(port), "--script", f"{name}-info" if name in ("mysql", "mongodb") else "banner",
            ip, "-oN", str(db_folder / f"nmap-{name}.txt")
        ])
        print(colored(f"[+] Base de datos detectada: {name} en puerto {port}", "green"))

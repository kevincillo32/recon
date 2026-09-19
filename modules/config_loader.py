#!/usr/bin/env python3
"""Carga config/tools.conf y expone valores con fallback seguro."""

import configparser
from pathlib import Path

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "tools.conf"

_DEFAULTS = {
    "wordlists": {
        "dir_common": "/usr/share/wordlists/dirb/common.txt",
        "dir_medium": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "subdomains": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    },
    "nmap": {
        "min_rate": "5000",
        "udp_top_ports_normal": "100",
        "udp_top_ports_deep": "1000",
    },
    "web": {
        "gobuster_threads": "50",
    },
    "nvd": {
        "delay_seconds": "6",
    },
    "github": {
        "delay_seconds": "2",
    },
}


def load_config():
    parser = configparser.ConfigParser()

    # Precargar defaults para que exista siempre la sección/clave aunque
    # el .conf no se pueda leer o falte alguna entrada.
    parser.read_dict(_DEFAULTS)

    if _CONFIG_PATH.exists():
        parser.read(_CONFIG_PATH)

    return parser


CONFIG = load_config()

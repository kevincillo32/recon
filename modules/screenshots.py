#!/usr/bin/env python3
"""Screenshots automáticos de cada URL web detectada (incluye vhosts)."""

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

from modules.utils import run_command, tool_exists


def tomar_screenshots(urls, folder):
    if not urls:
        return

    shots_folder = folder / "screenshots"
    shots_folder.mkdir(parents=True, exist_ok=True)

    if tool_exists("gowitness"):
        urls_file = shots_folder / "urls.txt"
        urls_file.write_text("\n".join(urls), encoding="utf-8")

        run_command([
            "gowitness", "file", "-f", str(urls_file),
            "-P", str(shots_folder), "--no-http"
        ])
        print(colored(f"[+] Screenshots (gowitness) en {shots_folder}", "green"))
        return

    if tool_exists("eyewitness"):
        urls_file = shots_folder / "urls.txt"
        urls_file.write_text("\n".join(urls), encoding="utf-8")

        run_command([
            "eyewitness", "--web", "-f", str(urls_file),
            "-d", str(shots_folder / "eyewitness"), "--no-prompt"
        ])
        print(colored(f"[+] Screenshots (eyewitness) en {shots_folder}", "green"))
        return

    print(colored("[!] Ni gowitness ni eyewitness instalados, se omiten screenshots.", "yellow"))

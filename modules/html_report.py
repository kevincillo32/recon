#!/usr/bin/env python3
"""
Convierte README.md + attack-surface.md + findings.md +
misconfigurations.md + screenshots en un único report.html navegable.
No usa librerías externas de markdown (para no añadir otra dependencia
dura) -- hace un render simple, suficiente para lectura, no para
publicación editorial.
"""

import base64
import html
try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored


def _leer(path):
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _markdown_simple_a_html(texto):
    """Render minimalista: encabezados, listas y párrafos. No es un
    parser de markdown completo, solo lo suficiente para estos reportes
    generados internamente (formato controlado)."""
    lineas_html = []
    for linea in texto.splitlines():
        esc = html.escape(linea)
        if esc.startswith("### "):
            lineas_html.append(f"<h3>{esc[4:]}</h3>")
        elif esc.startswith("## "):
            lineas_html.append(f"<h2>{esc[3:]}</h2>")
        elif esc.startswith("# "):
            lineas_html.append(f"<h1>{esc[2:]}</h1>")
        elif esc.startswith("- "):
            lineas_html.append(f"<li>{esc[2:]}</li>")
        elif esc.strip() == "":
            lineas_html.append("<br>")
        else:
            lineas_html.append(f"<p>{esc}</p>")
    return "\n".join(lineas_html)


def _embeber_imagenes(shots_folder):
    """Convierte cada .png/.jpg de screenshots/ a base64 embebido, para
    que el HTML final sea un solo archivo portable."""
    bloques = []
    if not shots_folder.exists():
        return ""

    for img in sorted(shots_folder.rglob("*")):
        if img.suffix.lower() not in (".png", ".jpg", ".jpeg"):
            continue
        try:
            data = base64.b64encode(img.read_bytes()).decode()
            mime = "image/png" if img.suffix.lower() == ".png" else "image/jpeg"
            bloques.append(
                f'<div class="shot"><p>{html.escape(img.name)}</p>'
                f'<img src="data:{mime};base64,{data}" style="max-width:600px;"></div>'
            )
        except Exception:
            continue

    return "\n".join(bloques)


def generar_reporte_html(folder):
    readme = _leer(folder / "README.md")
    attack_surface = _leer(folder / "attack-surface.md")
    findings = _leer(folder / "06_vulnerabilities" / "findings.md")
    misconfig = _leer(folder / "06_vulnerabilities" / "misconfigurations.md")
    creds = _leer(folder / "07_credentials" / "credentials-found.md")

    screenshots_html = _embeber_imagenes(folder / "screenshots")

    nombre_maquina = folder.name

    html_doc = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Recon Report - {html.escape(nombre_maquina)}</title>
<style>
  body {{ font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; background:#0f172a; color:#e2e8f0; }}
  h1 {{ color: #38bdf8; border-bottom: 2px solid #38bdf8; padding-bottom: 8px; }}
  h2 {{ color: #7dd3fc; margin-top: 30px; }}
  h3 {{ color: #a5f3fc; }}
  li {{ margin-left: 20px; }}
  code, pre {{ background:#1e293b; padding: 2px 6px; border-radius: 4px; }}
  .section {{ background:#1e293b; padding: 20px; border-radius: 8px; margin-bottom: 24px; }}
  .shot {{ display:inline-block; margin: 10px; vertical-align: top; }}
  .shot img {{ border: 1px solid #334155; border-radius: 6px; }}
  nav a {{ color:#38bdf8; margin-right: 16px; }}
</style>
</head>
<body>
<h1>Recon Report — {html.escape(nombre_maquina)}</h1>
<nav>
  <a href="#overview">Overview</a>
  <a href="#surface">Attack Surface</a>
  <a href="#findings">Findings</a>
  <a href="#misconfig">Misconfigurations</a>
  <a href="#creds">Credentials</a>
  <a href="#shots">Screenshots</a>
</nav>

<div class="section" id="overview">{_markdown_simple_a_html(readme)}</div>
<div class="section" id="surface">{_markdown_simple_a_html(attack_surface)}</div>
<div class="section" id="findings">{_markdown_simple_a_html(findings) or "<p>Sin findings.</p>"}</div>
<div class="section" id="misconfig">{_markdown_simple_a_html(misconfig) or "<p>Sin misconfiguraciones detectadas.</p>"}</div>
<div class="section" id="creds">{_markdown_simple_a_html(creds) or "<p>Sin credenciales detectadas.</p>"}</div>
<div class="section" id="shots"><h2>Screenshots</h2>{screenshots_html or "<p>Sin screenshots.</p>"}</div>

</body>
</html>
"""

    output = folder / "report.html"
    output.write_text(html_doc, encoding="utf-8")
    print(colored(f"[+] Reporte HTML consolidado en {output}", "green"))
    return output

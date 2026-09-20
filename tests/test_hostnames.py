import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import hostnames as hn


def test_filtra_dominios_genericos(tmp_path):
    archivo = tmp_path / "output.txt"
    archivo.write_text(
        "Server: apache.example.com\n"
        "hostname: ghostlink.htb\n"
        "domain: internal.corp.local\n"
    )

    resultado = hn.extraer_hostnames(tmp_path)

    # .htb siempre se conserva (regla explícita del proyecto)
    assert "ghostlink.htb" in resultado
    # .com genérico debe filtrarse como ruido
    assert not any(h.endswith(".com") for h in resultado)


def test_no_falsos_positivos_con_texto_vacio(tmp_path):
    archivo = tmp_path / "vacio.txt"
    archivo.write_text("nada relevante aquí\n")

    resultado = hn.extraer_hostnames(tmp_path)
    assert resultado == []

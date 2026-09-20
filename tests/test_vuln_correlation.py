import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import vuln_correlation as vc


def test_confianza_alta_con_version_exacta():
    assert vc.calcular_confianza("2.4.49", "2.4.49") == "HIGH"


def test_confianza_media_con_rama_menor():
    assert vc.calcular_confianza("2.4", "2.4.49") == "MEDIUM"


def test_confianza_baja_sin_version():
    assert vc.calcular_confianza("", "2.4.49") == "LOW"


def test_extraer_servicios_desde_xml_real(tmp_path):
    xml_contenido = """<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" product="Apache httpd" version="2.4.49"/>
</port>
</ports>
</host>
</nmaprun>
"""
    xml_path = tmp_path / "targeted.xml"
    xml_path.write_text(xml_contenido)

    servicios = vc.extraer_servicios_desde_xml(xml_path)

    assert len(servicios) == 1
    assert servicios[0]["product"] == "Apache httpd"
    assert servicios[0]["version"] == "2.4.49"
    assert servicios[0]["port"] == "80"


def test_extraer_servicios_xml_inexistente(tmp_path):
    resultado = vc.extraer_servicios_desde_xml(tmp_path / "no_existe.xml")
    assert resultado == []

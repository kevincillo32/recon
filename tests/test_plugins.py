import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.plugin_loader import ejecutar_plugins


class _PluginFalso:
    __name__ = "recon_custom_falso"
    REQUIRES = ["puertos"]

    @staticmethod
    def run(ip, folder, context):
        if 80 in context["puertos"]:
            return {"encontrado": True}
        return None


def test_plugin_respeta_requires():
    plugin = _PluginFalso()
    context_sin_requisito = {}
    ejecutar_plugins([plugin], "10.10.10.10", Path("/tmp"), context_sin_requisito)
    # Sin 'puertos' en el contexto, el plugin no debe correr ni agregar nada
    assert "falso" not in context_sin_requisito


def test_plugin_corre_y_guarda_resultado():
    plugin = _PluginFalso()
    context = {"puertos": [22, 80]}
    ejecutar_plugins([plugin], "10.10.10.10", Path("/tmp"), context)
    # plugin_loader quita el prefijo 'recon_custom_' del __name__ del módulo
    # para decidir la clave bajo la que guarda el resultado en el contexto.
    assert context["falso"] == {"encontrado": True}


def test_plugin_que_devuelve_none_no_contamina_contexto():
    plugin = _PluginFalso()
    context = {"puertos": [22]}  # sin 80, el plugin devuelve None
    ejecutar_plugins([plugin], "10.10.10.10", Path("/tmp"), context)
    assert "falso" not in context

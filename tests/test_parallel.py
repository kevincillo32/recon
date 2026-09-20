import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.parallel import correr_en_paralelo


def _tarea(nombre, segundos, resultado):
    time.sleep(segundos)
    return resultado


def test_paralelismo_real_es_mas_rapido_que_secuencial():
    tareas = [
        ("a", _tarea, ("a", 0.2, "ra")),
        ("b", _tarea, ("b", 0.2, "rb")),
        ("c", _tarea, ("c", 0.2, "rc")),
    ]

    inicio = time.time()
    resultados = correr_en_paralelo(tareas)
    duracion = time.time() - inicio

    assert resultados == {"a": "ra", "b": "rb", "c": "rc"}
    # Si fuera secuencial tomaría ~0.6s; en paralelo debe quedar bien por debajo
    assert duracion < 0.5


def test_error_en_una_tarea_no_rompe_las_demas():
    def falla(*_):
        raise ValueError("boom")

    tareas = [
        ("ok", _tarea, ("ok", 0.05, "listo")),
        ("rota", falla, ()),
    ]

    resultados = correr_en_paralelo(tareas)

    assert resultados["ok"] == "listo"
    assert resultados["rota"] is None

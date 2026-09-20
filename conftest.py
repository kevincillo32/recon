import sys
from pathlib import Path

# Permite correr `pytest tests/` desde la raíz del proyecto sin instalar
# el paquete -- agrega la raíz al path para que `from modules import ...`
# funcione igual que en el runner manual usado durante el desarrollo.
sys.path.insert(0, str(Path(__file__).resolve().parent))

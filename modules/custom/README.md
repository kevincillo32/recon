# Plugins de usuario

Deja aquí cualquier archivo `.py` con una función `run(ip, folder, context)`
y se cargará automáticamente en la próxima corrida, sin tocar recon.py.

Ejemplo mínimo:

```python
PARALLEL_SAFE = True
REQUIRES = ["puertos"]

def run(ip, folder, context):
    puertos = context["puertos"]
    if 8080 not in puertos:
        return None
    # tu lógica aquí
    return {"nota": "encontre algo en 8080"}
```

`context` contiene, entre otras cosas: `puertos` (TCP), `puertos_udp`,
`urls` (web), `hostnames`. Lo que tu plugin devuelva queda disponible
para plugins que corran después, bajo `context["<nombre_de_tu_archivo>"]`.

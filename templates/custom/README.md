# Templates personalizados

Formato YAML simple para verificación activa, contribuible por la
comunidad sin tocar Python. Ver `modules/custom_templates.py` para el
motor que los ejecuta y `CVE-2021-41773.yaml` como ejemplo.

Solo se soporta matcher tipo "word" (con condition "word" o "regex")
sobre el body de la respuesta. Para necesidades más avanzadas, usa
nuclei real con --deep.

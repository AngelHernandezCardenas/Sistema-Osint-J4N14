"""
utilidades — Paquete de utilidades auxiliares de Recon365.

Contiene:
    - logger: Sistema de logging centralizado
    - gestor_archivos: Lectura/escritura de archivos (CSV, TXT, JSON)
"""

from utilidades.logger import obtener_logger
from utilidades.gestor_archivos import (
    leer_objetivos,
    guardar_reporte,
    guardar_captura,
    asegurar_directorios,
)

__all__: list[str] = [
    "obtener_logger",
    "leer_objetivos",
    "guardar_reporte",
    "guardar_captura",
    "asegurar_directorios",
]
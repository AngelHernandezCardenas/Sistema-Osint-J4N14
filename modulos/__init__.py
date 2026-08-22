<![CDATA["""
modulos — Paquete principal de módulos operativos de Recon365.

Contiene:
    - recolector: Scraping y recolección de datos públicos
    - perfilador_ia: Motor J4N14 de perfilamiento con IA local
    - generador_ataques: Generación de vectores de Spear Phishing
"""

from modulos.recolector import recolectar_objetivo
from modulos.perfilador_ia import analizar_perfil, inicializar_motor
from modulos.generador_ataques import crear_pretexto, generar_reporte_final

__all__: list[str] = [
    "recolectar_objetivo",
    "analizar_perfil",
    "inicializar_motor",
    "crear_pretexto",
    "generar_reporte_final",
]
]]>

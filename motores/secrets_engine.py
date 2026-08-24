"""
motores/secrets_engine.py — Motor de detección de secretos para Recon365.

Analiza texto, código fuente y metadatos en busca de información
sensible como contraseñas, tokens y claves de API usando
patrones de expresiones regulares.

Uso:
    from motores.secrets_engine import motor_secretos
    secretos = motor_secretos.escanear_texto("... texto ...", org_id=1, fuente="web")
"""

import re
from typing import Any, Optional

from utilidades.base_datos import BaseDatos
from utilidades.logger import obtener_logger
from modulos_osint.github_recon import PATRONES_SECRETOS

log = obtener_logger(__name__)

# Agregamos algunos patrones adicionales específicos para web
PATRONES_ADICIONALES: list[dict[str, str]] = [
    {"tipo": "email_corporativo", "patron": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "severidad": "informativo"},
]

TODOS_LOS_PATRONES = PATRONES_SECRETOS + PATRONES_ADICIONALES


class MotorSecretos:
    """Motor para la detección de información sensible."""

    def __init__(self, db: Optional[BaseDatos] = None):
        self.db = db or BaseDatos()
        # Precompilar regexs
        for p in TODOS_LOS_PATRONES:
            p["_re"] = re.compile(p["patron"])

    def escanear_texto(self, texto: str, org_id: Optional[int] = None, fuente: str = "texto_plano", contexto: str = "") -> list[dict[str, Any]]:
        """
        Escanea un bloque de texto en busca de secretos.

        Args:
            texto: Contenido a escanear.
            org_id: ID de la organización para guardar en DB.
            fuente: Origen del texto (URL, archivo, etc.).
            contexto: Información adicional de ubicación.

        Returns:
            Lista de secretos encontrados.
        """
        encontrados: list[dict[str, Any]] = []

        if not texto:
            return encontrados

        for patron_info in TODOS_LOS_PATRONES:
            regex = patron_info["_re"]
            matches = regex.finditer(texto)
            
            for match in matches:
                valor_real = match.group(0)
                
                # Ignorar emails genéricos o de ejemplo
                if patron_info["tipo"] == "email_corporativo":
                    if any(x in valor_real.lower() for x in ["example.com", "test.com", "domain.com", "email@"]):
                        continue
                        
                # Ofuscar el secreto para almacenamiento
                valor_ofuscado = self._ofuscar_secreto(valor_real, patron_info["tipo"])
                
                secreto = {
                    "tipo": patron_info["tipo"],
                    "valor_ofuscado": valor_ofuscado,
                    "severidad": patron_info["severidad"],
                    "fuente": fuente,
                    "ubicacion": contexto,
                    "confianza": 0.8,
                }
                encontrados.append(secreto)
                
                # Guardar en base de datos si se proporcionó org_id
                if org_id:
                    self.db.agregar_secreto(
                        org_id=org_id,
                        tipo=secreto["tipo"],
                        valor_ofuscado=secreto["valor_ofuscado"],
                        fuente=secreto["fuente"],
                        ubicacion=secreto["ubicacion"],
                        severidad=secreto["severidad"],
                        confianza=secreto["confianza"],
                    )
                    
        if encontrados:
            log.info(f"Se encontraron {len(encontrados)} secretos en {fuente}")
            
        return encontrados
        
    def _ofuscar_secreto(self, valor: str, tipo: str) -> str:
        """Ofusca un secreto para guardarlo de forma segura."""
        # Emails: j***@dominio.com
        if tipo == "email_corporativo" and "@" in valor:
            partes = valor.split("@")
            user = partes[0]
            if len(user) > 2:
                user = user[0] + "***" + user[-1]
            return f"{user}@{partes[1]}"
            
        # APIs largas: AKIA***...***XyZ
        if len(valor) > 8:
            return f"{valor[:4]}...{valor[-4:]}"
            
        # Cortos
        return "***"


motor_secretos = MotorSecretos()

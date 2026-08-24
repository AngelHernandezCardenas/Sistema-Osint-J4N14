"""
motores/threat_intel_engine.py — Motor de Inteligencia de Amenazas para Recon365.

Busca vulnerabilidades conocidas (CVEs) para las tecnologías detectadas
usando fuentes gratuitas (NVD API o base de datos local emulada).

Uso:
    from motores.threat_intel_engine import motor_amenazas
    await motor_amenazas.enriquecer_tecnologias(org_id)
"""

import asyncio
from typing import Any, Optional
import aiohttp

from utilidades.base_datos import BaseDatos
from utilidades.logger import obtener_logger

log = obtener_logger(__name__)

# Mock database of common CVEs for demo/free-tier without NVD API Key
MOCK_CVE_DB = {
    "WordPress": [
        {"cve": "CVE-2023-22622", "cvss": 7.5, "severidad": "alta", "desc": "WordPress core vulnerability before 6.2"},
    ],
    "Nginx": [
        {"cve": "CVE-2021-23017", "cvss": 7.5, "severidad": "alta", "desc": "1-byte memory overwrite in DNS resolver"},
    ],
    "Apache": [
        {"cve": "CVE-2021-41773", "cvss": 9.8, "severidad": "critica", "desc": "Path traversal in Apache HTTP Server 2.4.49"},
    ],
    "PHP": [
        {"cve": "CVE-2022-31626", "cvss": 8.1, "severidad": "alta", "desc": "Password_verify() vulnerability in PHP"},
    ]
}

class ThreatIntelEngine:
    """Motor de inteligencia de amenazas para enriquecer tecnologías con CVEs."""

    def __init__(self, db: Optional[BaseDatos] = None):
        self.db = db or BaseDatos()

    async def enriquecer_tecnologias(self, org_id: int) -> int:
        """
        Busca vulnerabilidades para todas las tecnologías detectadas
        en una organización.

        Args:
            org_id: ID de la organización.
            
        Returns:
            Número de vulnerabilidades encontradas.
        """
        log.info(f"Iniciando enriquecimiento Threat Intel para org_id={org_id}")
        
        techs = self.db.obtener_tecnologias(org_id)
        if not techs:
            log.info("No hay tecnologías para enriquecer.")
            return 0
            
        total_vulns = 0
        
        for tech in techs:
            tech_nombre = tech["nombre"]
            tech_version = tech.get("version", "")
            tech_id = tech["id"]
            
            # Buscar en el mock (en un sistema real se consultaría NVD)
            vulns = await self._buscar_cve(tech_nombre, tech_version)
            
            for v in vulns:
                self.db.agregar_vulnerabilidad(
                    tecnologia_id=tech_id,
                    cve_id=v["cve"],
                    descripcion=v["desc"],
                    cvss_score=v["cvss"],
                    severidad=v["severidad"],
                    explotada=v.get("explotada", False),
                    fuente="nvd_mock",
                )
                total_vulns += 1
                
        log.info(f"Threat Intel completado: {total_vulns} vulnerabilidades encontradas")
        return total_vulns
        
    async def _buscar_cve(self, nombre: str, version: str) -> list[dict[str, Any]]:
        """
        Busca CVEs para una tecnología.
        (Implementación mock/emulada por simplicidad sin API Key)
        """
        # Emular retraso de red
        await asyncio.sleep(0.1)
        
        # Búsqueda simple en el mock dictionary
        for key, vulns in MOCK_CVE_DB.items():
            if key.lower() in nombre.lower():
                return vulns
                
        return []


motor_amenazas = ThreatIntelEngine()

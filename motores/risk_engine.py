"""
motores/risk_engine.py — Motor de Evaluación de Riesgo para Recon365.

Calcula el riesgo de cada activo basándose en:
- Severidad de vulnerabilidades
- Tipo de activo
- Cantidad y severidad de secretos expuestos

Escala de 0 a 100.
"""

from typing import Any, Optional

from utilidades.base_datos import BaseDatos
from utilidades.logger import obtener_logger

log = obtener_logger(__name__)


class RiskEngine:
    """Evalúa el riesgo de la superficie de ataque."""

    def __init__(self, db: Optional[BaseDatos] = None):
        self.db = db or BaseDatos()

    def evaluar_organizacion(self, org_id: int) -> dict[str, Any]:
        """
        Calcula y guarda el riesgo de la organización.
        """
        log.info(f"Evaluando riesgo para org_id={org_id}")
        
        # Recopilar datos
        vulns = self.db.obtener_vulnerabilidades(org_id)
        secretos = self.db.obtener_secretos(org_id)
        
        score_base = 10.0 # Riesgo base
        
        # Factores
        vulns_criticas = len([v for v in vulns if v.get("severidad", "").lower() == "critica" or v.get("cvss_score", 0) >= 9.0])
        vulns_altas = len([v for v in vulns if v.get("severidad", "").lower() == "alta" or (7.0 <= v.get("cvss_score", 0) < 9.0)])
        
        secretos_criticos = len([s for s in secretos if s.get("severidad", "").lower() == "critica"])
        secretos_altos = len([s for s in secretos if s.get("severidad", "").lower() == "alta"])
        
        # Penalizaciones
        score_base += (vulns_criticas * 20.0)
        score_base += (vulns_altas * 10.0)
        score_base += (secretos_criticos * 25.0)
        score_base += (secretos_altos * 15.0)
        
        # Normalizar a 100
        score_final = min(max(score_base, 0.0), 100.0)
        
        # Nivel de riesgo
        if score_final <= 20:
            nivel = "Informativo"
        elif score_final <= 40:
            nivel = "Bajo"
        elif score_final <= 60:
            nivel = "Medio"
        elif score_final <= 80:
            nivel = "Alto"
        else:
            nivel = "Critico"
            
        factores = {
            "vulnerabilidades_criticas": vulns_criticas,
            "vulnerabilidades_altas": vulns_altas,
            "secretos_criticos": secretos_criticos,
            "secretos_altos": secretos_altos,
        }
        
        # Guardar en BD
        self.db.agregar_evaluacion_riesgo(
            org_id=org_id,
            entidad_tipo="organizacion",
            entidad_id=org_id,
            score=score_final,
            nivel=nivel,
            factores=factores
        )
        
        log.info(f"Riesgo evaluado: {score_final} ({nivel})")
        return {"score": score_final, "nivel": nivel, "factores": factores}


motor_riesgo = RiskEngine()

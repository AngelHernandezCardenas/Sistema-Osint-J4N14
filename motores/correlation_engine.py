"""
motores/correlation_engine.py — Motor de Correlación para Recon365.

Construye un grafo de relaciones (nodes & edges) conectando:
    Organización → Dominio → IP → Tecnología → Vulnerabilidad
    Organización → Repositorio → Secreto

Exporta el grafo en un formato compatible con librerías de
visualización frontend (vis.js, d3.js).

Uso:
    from motores.correlation_engine import motor_correlacion
    grafo = motor_correlacion.construir_grafo(org_id)
"""

from typing import Any, Optional

import networkx as nx

from utilidades.base_datos import BaseDatos
from utilidades.logger import obtener_logger

log = obtener_logger(__name__)


class CorrelationEngine:
    """Construye y analiza grafos de correlación de activos."""

    def __init__(self, db: Optional[BaseDatos] = None):
        self.db = db or BaseDatos()

    def construir_grafo(self, org_id: int) -> dict[str, Any]:
        """
        Construye el grafo de relaciones y lo exporta para frontend.

        Args:
            org_id: ID de la organización.

        Returns:
            Diccionario con "nodes" y "edges" para vis.js/d3.
        """
        log.info(f"Construyendo grafo de correlación para org_id={org_id}")
        
        datos = self.db.exportar_grafo(org_id)
        org = datos.get("organizacion")
        
        if not org:
            return {"nodes": [], "edges": []}

        G = nx.Graph()

        # Nodo Raíz (Organización)
        id_org = f"org_{org['id']}"
        G.add_node(
            id_org,
            label=org["nombre"],
            group="organizacion",
            title=f"Dominio principal: {org['dominio_principal']}"
        )

        # Dominios y Subdominios
        ips_creadas = set()
        
        for dom in datos.get("dominios", []):
            id_dom = f"dom_{dom['id']}"
            grupo = "dominio" if dom["tipo"] == "principal" else "subdominio"
            
            G.add_node(
                id_dom,
                label=dom["dominio"],
                group=grupo,
                title=f"Fuente: {dom.get('fuente', 'manual')}"
            )
            G.add_edge(id_org, id_dom)
            
            # IPs
            ip = dom.get("ip_resuelta")
            if ip:
                id_ip = f"ip_{ip}"
                if id_ip not in ips_creadas:
                    G.add_node(id_ip, label=ip, group="ip", title="Dirección IP")
                    ips_creadas.add(id_ip)
                G.add_edge(id_dom, id_ip)

        # Tecnologías
        techs_por_dominio = {}
        for tech in datos.get("tecnologias", []):
            id_dom = f"dom_{tech['dominio_id']}"
            # Agrupar techs iguales para no saturar el grafo
            id_tech = f"tech_{tech['nombre'].replace(' ', '_')}"
            
            if id_tech not in G:
                G.add_node(
                    id_tech,
                    label=tech["nombre"],
                    group="tecnologia",
                    title=f"Categoría: {tech.get('categoria', '')}"
                )
            
            G.add_edge(id_dom, id_tech)
            techs_por_dominio[tech['id']] = id_tech

        # Vulnerabilidades
        for vuln in datos.get("vulnerabilidades", []):
            id_tech = techs_por_dominio.get(vuln['tecnologia_id'])
            if id_tech:
                id_vuln = f"vuln_{vuln['cve_id']}"
                if id_vuln not in G:
                    G.add_node(
                        id_vuln,
                        label=vuln["cve_id"],
                        group="vulnerabilidad",
                        title=f"CVSS: {vuln.get('cvss_score', 0)} ({vuln.get('severidad', '')})"
                    )
                G.add_edge(id_tech, id_vuln)

        # Repositorios
        for repo in datos.get("repositorios", []):
            id_repo = f"repo_{repo['id']}"
            G.add_node(
                id_repo,
                label=repo["nombre"],
                group="repositorio",
                title=f"Lenguaje: {repo.get('lenguaje', '')}"
            )
            G.add_edge(id_org, id_repo)

        # Secretos
        for sec in datos.get("secretos", []):
            id_sec = f"sec_{sec['id']}"
            G.add_node(
                id_sec,
                label=sec["tipo"],
                group="secreto",
                title=f"Ubicación: {sec.get('ubicacion', '')}"
            )
            # Conectar a repo si vino de github, o a org por defecto
            if sec.get("ubicacion") and "/" in str(sec.get("ubicacion")):
                # Intento simple de conectarlo al nodo repo si coincide
                nombre_repo_buscado = str(sec.get("ubicacion")).split("/")[-1]
                encontrado = False
                for nodo, attr in G.nodes(data=True):
                    if attr.get("group") == "repositorio" and attr.get("label") == nombre_repo_buscado:
                        G.add_edge(nodo, id_sec)
                        encontrado = True
                        break
                if not encontrado:
                    G.add_edge(id_org, id_sec)
            else:
                G.add_edge(id_org, id_sec)

        # Formatear salida para el frontend (nodes: [{id, label, group, title}], edges: [{from, to}])
        resultado = {
            "nodes": [
                {"id": n, **attr} for n, attr in G.nodes(data=True)
            ],
            "edges": [
                {"from": u, "to": v} for u, v in G.edges()
            ]
        }
        
        log.info(f"Grafo generado: {len(resultado['nodes'])} nodos, {len(resultado['edges'])} aristas")
        return resultado


motor_correlacion = CorrelationEngine()

"""
motores/osint_engine.py — Motor de orquestación OSINT para Recon365.

Orquesta la recolección pasiva sobre una organización:
    1. Resuelve DNS del dominio principal
    2. Descubre subdominios (crt.sh, bruteforce)
    3. Para cada dominio activo descubierto:
       a. Fingerprinting tecnológico
       b. Metadata web
       c. Certificados TLS
    4. Consulta WHOIS del dominio
    5. Guarda todo en la base de datos central.

Uso:
    from motores.osint_engine import motor_osint
    await motor_osint.analizar_organizacion(org_id, "example.com")
"""

import asyncio
from typing import Any, Optional

from modulos_osint import (
    cert_transparency,
    dns_enum,
    github_recon,
    subdomain_discovery,
    tech_fingerprint,
    web_metadata,
    whois_lookup,
)
from utilidades.base_datos import BaseDatos
from utilidades.logger import obtener_logger

log = obtener_logger(__name__)


class MotorOSINT:
    """Motor de orquestación de recolección OSINT pasiva."""

    def __init__(self, db: Optional[BaseDatos] = None):
        self.db = db or BaseDatos()

    async def analizar_organizacion(self, org_id: int, dominio_principal: str) -> dict[str, Any]:
        """
        Ejecuta el pipeline completo de OSINT sobre una organización.

        Args:
            org_id: ID de la organización en la BD.
            dominio_principal: Dominio base a analizar.

        Returns:
            Estadísticas de la recolección.
        """
        log.info(f"Iniciando Motor OSINT para org_id={org_id}, dominio={dominio_principal}")

        # 1. DNS del dominio principal
        await self._fase_dns(org_id, dominio_principal)

        # 2. WHOIS
        await self._fase_whois(org_id, dominio_principal)

        # 3. Certificados TLS (Dominio base)
        await self._fase_certificados(org_id, dominio_principal)

        # 4. Descubrimiento de subdominios
        subdominios = await self._fase_subdominios(org_id, dominio_principal)

        # 5. Análisis web de cada subdominio activo (limitado concurrencia)
        activos = [s for s in subdominios if s.get("activo")]
        log.info(f"Iniciando análisis web profundo para {len(activos)} subdominios activos...")
        
        # Agregar el dominio principal a la lista a escanear
        doms_a_escanear = [{"subdominio": dominio_principal}] + activos

        semaforo = asyncio.Semaphore(5)  # Máx 5 análisis concurrentes
        
        async def escanear_dominio(dom_info: dict) -> None:
            async with semaforo:
                await self._fase_analisis_web(org_id, dom_info["subdominio"])

        tareas = [escanear_dominio(d) for d in doms_a_escanear]
        await asyncio.gather(*tareas)

        # 6. GitHub Recon
        org = self.db.obtener_organizacion(org_id)
        if org:
            await self._fase_github(org_id, org["nombre"])

        # Generar snapshot después de recolectar todo
        self.db.crear_snapshot(org_id)
        
        log.info(f"Motor OSINT completado para {dominio_principal}")
        return self.db.obtener_estadisticas(org_id)

    async def _fase_dns(self, org_id: int, dominio: str) -> None:
        """Fase 1: Enumeración DNS."""
        log.info(f"Fase 1: DNS de {dominio}")
        dom_id = self.db.obtener_dominio_id(org_id, dominio)
        if not dom_id:
            dom_id = self.db.agregar_dominio(org_id, dominio, tipo="principal")

        resultados_dns = await dns_enum.enumerar_dns(dominio)
        
        # Guardar registros DNS
        for reg in resultados_dns.get("registros", []):
            self.db.agregar_registro_dns(
                dominio_id=dom_id,
                tipo=reg["tipo"],
                valor=reg["valor"],
                ttl=reg.get("ttl"),
            )
            
        # Si no había IP y encontramos una, la guardamos
        if resultados_dns.get("ips"):
            self.db.agregar_dominio(org_id, dominio, ip=resultados_dns["ips"][0])

    async def _fase_whois(self, org_id: int, dominio: str) -> None:
        """Fase 2: Información WHOIS."""
        log.info(f"Fase 2: WHOIS de {dominio}")
        dom_id = self.db.obtener_dominio_id(org_id, dominio)
        
        if dom_id:
            info_whois = await whois_lookup.consultar_whois(dominio)
            if info_whois.get("exitoso"):
                self.db.agregar_whois(
                    dominio_id=dom_id,
                    registrante=info_whois.get("registrante", ""),
                    organizacion=info_whois.get("organizacion", ""),
                    nameservers=",".join(info_whois.get("nameservers", [])),
                    fecha_creacion=info_whois.get("fecha_creacion", ""),
                    fecha_expiracion=info_whois.get("fecha_expiracion", ""),
                    raw_data=info_whois.get("raw", ""),
                )

    async def _fase_certificados(self, org_id: int, dominio: str) -> None:
        """Fase 3: Transparencia de certificados."""
        log.info(f"Fase 3: CT Logs para {dominio}")
        resultados_ct = await cert_transparency.analizar_certificados(dominio)
        
        for cert in resultados_ct.get("certificados", []):
            self.db.agregar_certificado(
                org_id=org_id,
                dominio_comun=cert.get("dominio_comun", ""),
                sans=",".join(cert.get("sans", [])),
                emisor=cert.get("emisor", ""),
                fecha_emision=cert.get("fecha_emision", ""),
                fecha_expiracion=cert.get("fecha_expiracion", ""),
                serial=cert.get("serial", ""),
            )

    async def _fase_subdominios(self, org_id: int, dominio: str) -> list[dict]:
        """Fase 4: Descubrimiento de subdominios."""
        log.info(f"Fase 4: Descubrimiento de subdominios para {dominio}")
        resultados_subs = await subdomain_discovery.descubrir_subdominios(dominio)
        subdominios = resultados_subs.get("subdominios", [])
        
        for sub_info in subdominios:
            self.db.agregar_dominio(
                org_id=org_id,
                dominio=sub_info["subdominio"],
                tipo="subdominio",
                ip=sub_info.get("ip"),
                fuente="descubrimiento",
            )
            
        return subdominios

    async def _fase_analisis_web(self, org_id: int, dominio: str) -> None:
        """Fase 5: Fingerprinting y metadata web para un dominio específico."""
        log.info(f"Fase 5: Análisis web de {dominio}")
        dom_id = self.db.obtener_dominio_id(org_id, dominio)
        if not dom_id:
            return

        # Fingerprinting tecnológico
        techs = await tech_fingerprint.fingerprint_tecnologico(f"https://{dominio}")
        
        for tech in techs.get("tecnologias", []):
            self.db.agregar_tecnologia(
                dominio_id=dom_id,
                nombre=tech["nombre"],
                version=tech.get("version", ""),
                categoria=tech.get("categoria", ""),
                fuente=tech.get("fuente", ""),
                confianza=tech.get("confianza", 0.5),
            )
            
        for header in techs.get("headers_seguridad", []):
            self.db.agregar_header_seguridad(
                dominio_id=dom_id,
                header=header["header"],
                valor=header.get("valor", ""),
                presente=header.get("presente", False),
                recomendacion=header.get("recomendacion", ""),
            )

        # Metadata Web (robots, sitemap)
        metadata = await web_metadata.analizar_metadata_web(f"https://{dominio}")
        
        # Extraer rutas interesantes de robots.txt a la DB (se pueden guardar como alertas o secretos informativos)
        robots = metadata.get("robots_txt", {})
        if robots.get("encontrado") and robots.get("rutas_interesantes"):
            rutas_str = ", ".join(robots["rutas_interesantes"][:10])
            self.db.crear_alerta(
                org_id=org_id,
                tipo="rutas_sensibles_descubiertas",
                titulo=f"Rutas sensibles en robots.txt de {dominio}",
                descripcion=f"Se encontraron rutas potencialmente sensibles: {rutas_str}",
                severidad="info",
                entidad_tipo="dominio",
                entidad_id=dom_id,
            )

    async def _fase_github(self, org_id: int, nombre_org: str) -> None:
        """Fase 6: Reconocimiento en GitHub."""
        log.info(f"Fase 6: GitHub recon para {nombre_org}")
        github_res = await github_recon.recon_github(nombre_org)
        
        for repo in github_res.get("repositorios", []):
            self.db.agregar_repositorio(
                org_id=org_id,
                nombre=repo["nombre"],
                url=repo["url"],
                descripcion=repo.get("descripcion", ""),
                lenguaje=repo.get("lenguaje", ""),
                es_fork=repo.get("es_fork", False),
                estrellas=repo.get("estrellas", 0),
            )
            
        for sec in github_res.get("secretos_potenciales", []):
            self.db.agregar_secreto(
                org_id=org_id,
                tipo=sec["tipo"],
                valor_ofuscado=sec.get("archivo", "Desconocido"), # El valor de archivo como proxy ofuscado
                fuente=sec.get("url", "GitHub"),
                ubicacion=sec.get("repo", ""),
                severidad=sec.get("severidad", "media"),
                confianza=sec.get("confianza", 0.5),
            )


motor_osint = MotorOSINT()

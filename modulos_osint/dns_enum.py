"""
modulos_osint/dns_enum.py — Enumeración DNS para Recon365.

Realiza consultas DNS completas sobre un dominio:
    - Registros A, AAAA, MX, NS, TXT, CNAME, SOA, SRV
    - Análisis de configuraciones de seguridad (SPF, DMARC, DKIM)
    - Resolución inversa de IPs

Uso:
    from modulos_osint.dns_enum import enumerar_dns
    resultados = await enumerar_dns("example.com")
"""

import asyncio
import socket
from typing import Any, Optional

from utilidades.logger import obtener_logger

log = obtener_logger(__name__)

# Tipos de registros DNS a consultar
TIPOS_DNS: list[str] = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"]


async def resolver_dns(dominio: str, tipo: str) -> list[dict[str, Any]]:
    """
    Resuelve un tipo de registro DNS específico usando dnspython.

    Args:
        dominio: Dominio a consultar.
        tipo: Tipo de registro (A, MX, NS, etc.)

    Returns:
        Lista de registros encontrados.
    """
    registros: list[dict[str, Any]] = []

    try:
        import dns.resolver
        respuesta = await asyncio.get_event_loop().run_in_executor(
            None, lambda: dns.resolver.resolve(dominio, tipo)
        )
        for rdata in respuesta:
            registro: dict[str, Any] = {
                "tipo": tipo,
                "valor": str(rdata),
                "ttl": respuesta.rrset.ttl if respuesta.rrset else None,
            }
            # Información extra para MX
            if tipo == "MX":
                registro["prioridad"] = rdata.preference
                registro["valor"] = str(rdata.exchange)
            registros.append(registro)

    except ImportError:
        # Fallback sin dnspython: usar socket para registros A
        if tipo == "A":
            try:
                ips = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: socket.getaddrinfo(dominio, None, socket.AF_INET)
                )
                for ip_info in ips:
                    ip = ip_info[4][0]
                    if {"tipo": "A", "valor": ip, "ttl": None} not in registros:
                        registros.append({"tipo": "A", "valor": ip, "ttl": None})
            except socket.gaierror:
                pass
    except Exception as error:
        error_name = type(error).__name__
        if "NXDOMAIN" not in error_name and "NoAnswer" not in error_name:
            log.debug(f"DNS {tipo} para {dominio}: {error_name}")

    return registros


async def enumerar_dns(dominio: str) -> dict[str, Any]:
    """
    Realiza enumeración DNS completa de un dominio.

    Args:
        dominio: Dominio a analizar.

    Returns:
        Diccionario con todos los registros DNS encontrados y análisis.
    """
    log.info(f"Enumeración DNS: {dominio}")

    resultado: dict[str, Any] = {
        "dominio": dominio,
        "registros": [],
        "ips": [],
        "nameservers": [],
        "mail_servers": [],
        "analisis_seguridad": {},
    }

    # Resolver todos los tipos en paralelo
    tareas = [resolver_dns(dominio, tipo) for tipo in TIPOS_DNS]
    resultados_dns = await asyncio.gather(*tareas, return_exceptions=True)

    for i, registros in enumerate(resultados_dns):
        if isinstance(registros, Exception):
            continue
        for registro in registros:
            resultado["registros"].append(registro)

            # Clasificar
            if registro["tipo"] == "A":
                resultado["ips"].append(registro["valor"])
            elif registro["tipo"] == "AAAA":
                resultado["ips"].append(registro["valor"])
            elif registro["tipo"] == "NS":
                resultado["nameservers"].append(registro["valor"])
            elif registro["tipo"] == "MX":
                resultado["mail_servers"].append(registro["valor"])

    # Eliminar duplicados
    resultado["ips"] = list(set(resultado["ips"]))
    resultado["nameservers"] = list(set(resultado["nameservers"]))
    resultado["mail_servers"] = list(set(resultado["mail_servers"]))

    # Análisis de seguridad DNS
    resultado["analisis_seguridad"] = _analizar_seguridad_dns(resultado["registros"])

    total = len(resultado["registros"])
    log.info(f"DNS completado para {dominio}: {total} registros encontrados")

    return resultado


def _analizar_seguridad_dns(registros: list[dict]) -> dict[str, Any]:
    """Analiza configuraciones de seguridad en registros TXT."""
    analisis: dict[str, Any] = {
        "spf": {"presente": False, "valor": ""},
        "dmarc": {"presente": False, "valor": ""},
        "dkim": {"presente": False, "valor": ""},
        "problemas": [],
    }

    for reg in registros:
        if reg["tipo"] != "TXT":
            continue
        valor = reg["valor"].strip('"').strip("'")

        if valor.startswith("v=spf1"):
            analisis["spf"] = {"presente": True, "valor": valor}
            # Verificar ~all vs -all
            if "~all" in valor:
                analisis["problemas"].append(
                    "SPF usa softfail (~all) en lugar de hardfail (-all)"
                )
            elif "+all" in valor:
                analisis["problemas"].append(
                    "SPF permite todos los servidores (+all) — muy inseguro"
                )
        elif valor.startswith("v=DMARC1"):
            analisis["dmarc"] = {"presente": True, "valor": valor}
            if "p=none" in valor:
                analisis["problemas"].append(
                    "DMARC tiene política 'none' — no bloquea correos fraudulentos"
                )
        elif "DKIM" in valor.upper() or valor.startswith("v=DKIM1"):
            analisis["dkim"] = {"presente": True, "valor": valor}

    # Verificar ausencias
    if not analisis["spf"]["presente"]:
        analisis["problemas"].append("No se detectó registro SPF — riesgo de spoofing")
    if not analisis["dmarc"]["presente"]:
        analisis["problemas"].append("No se detectó registro DMARC — sin protección anti-phishing")

    return analisis


async def resolucion_inversa(ip: str) -> Optional[str]:
    """Realiza resolución inversa de una IP."""
    try:
        hostname = await asyncio.get_event_loop().run_in_executor(
            None, lambda: socket.gethostbyaddr(ip)
        )
        return hostname[0]
    except (socket.herror, socket.gaierror):
        return None

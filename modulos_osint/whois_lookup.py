"""
modulos_osint/whois_lookup.py — Consultas WHOIS/RDAP para Recon365.

Obtiene información de registro de dominios e IPs:
    - Registrante, organización, contacto
    - Fechas de registro/expiración
    - Nameservers
    - ASN e información del proveedor (para IPs)

Uso:
    from modulos_osint.whois_lookup import consultar_whois
    info = await consultar_whois("example.com")
"""

import asyncio
import re
import socket
from typing import Any, Optional

import aiohttp

from utilidades.logger import obtener_logger

log = obtener_logger(__name__)

# Servidores RDAP conocidos
RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/"


async def consultar_whois(dominio: str) -> dict[str, Any]:
    """
    Consulta WHOIS para un dominio usando python-whois o fallback RDAP.

    Args:
        dominio: Dominio a consultar.

    Returns:
        Diccionario con información WHOIS.
    """
    log.info(f"WHOIS lookup: {dominio}")

    resultado: dict[str, Any] = {
        "dominio": dominio,
        "registrante": "",
        "organizacion": "",
        "email_contacto": "",
        "nameservers": [],
        "fecha_creacion": "",
        "fecha_expiracion": "",
        "registrar": "",
        "pais": "",
        "raw": "",
        "exitoso": False,
    }

    # Intentar python-whois primero
    try:
        import whois
        w = await asyncio.get_event_loop().run_in_executor(
            None, lambda: whois.whois(dominio)
        )
        if w:
            resultado["registrante"] = _extraer_str(w.get("name", ""))
            resultado["organizacion"] = _extraer_str(w.get("org", ""))
            resultado["email_contacto"] = _extraer_str(w.get("emails", ""))
            resultado["registrar"] = _extraer_str(w.get("registrar", ""))
            resultado["pais"] = _extraer_str(w.get("country", ""))

            ns = w.get("name_servers", [])
            if isinstance(ns, list):
                resultado["nameservers"] = [str(n).lower() for n in ns if n]
            elif ns:
                resultado["nameservers"] = [str(ns).lower()]

            fc = w.get("creation_date")
            if isinstance(fc, list):
                fc = fc[0]
            resultado["fecha_creacion"] = str(fc) if fc else ""

            fe = w.get("expiration_date")
            if isinstance(fe, list):
                fe = fe[0]
            resultado["fecha_expiracion"] = str(fe) if fe else ""

            resultado["raw"] = str(w.text)[:2000] if hasattr(w, "text") else ""
            resultado["exitoso"] = True

            log.info(f"WHOIS exitoso para {dominio}: registrar={resultado['registrar']}")
            return resultado

    except ImportError:
        log.debug("python-whois no instalado, intentando RDAP...")
    except Exception as error:
        log.debug(f"WHOIS falló para {dominio}: {error}, intentando RDAP...")

    # Fallback: RDAP
    resultado = await _consultar_rdap(dominio, resultado)

    return resultado


async def _consultar_rdap(dominio: str, resultado: dict[str, Any]) -> dict[str, Any]:
    """Consulta RDAP como fallback para WHOIS."""
    url = f"{RDAP_BOOTSTRAP_URL}{dominio}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    datos = await resp.json(content_type=None)

                    # Extraer nameservers
                    for ns in datos.get("nameservers", []):
                        nombre = ns.get("ldhName", "")
                        if nombre:
                            resultado["nameservers"].append(nombre.lower())

                    # Extraer entidades (registrante, registrar)
                    for entidad in datos.get("entities", []):
                        roles = entidad.get("roles", [])
                        vcard = entidad.get("vcardArray", [])

                        if "registrar" in roles:
                            if isinstance(vcard, list) and len(vcard) > 1:
                                for item in vcard[1]:
                                    if item[0] == "fn":
                                        resultado["registrar"] = item[3]
                        elif "registrant" in roles:
                            if isinstance(vcard, list) and len(vcard) > 1:
                                for item in vcard[1]:
                                    if item[0] == "fn":
                                        resultado["organizacion"] = item[3]

                    # Fechas
                    for evento in datos.get("events", []):
                        if evento.get("eventAction") == "registration":
                            resultado["fecha_creacion"] = evento.get("eventDate", "")
                        elif evento.get("eventAction") == "expiration":
                            resultado["fecha_expiracion"] = evento.get("eventDate", "")

                    resultado["exitoso"] = True
                    log.info(f"RDAP exitoso para {dominio}")

    except Exception as error:
        log.warning(f"RDAP falló para {dominio}: {error}")

    return resultado


async def consultar_ip_info(ip: str) -> dict[str, Any]:
    """
    Consulta información de una IP (ASN, proveedor, ubicación).

    Args:
        ip: Dirección IP a consultar.

    Returns:
        Diccionario con información de la IP.
    """
    resultado: dict[str, Any] = {
        "ip": ip,
        "hostname": "",
        "organizacion": "",
        "asn": "",
        "isp": "",
        "pais": "",
        "ciudad": "",
        "exitoso": False,
    }

    # Usar ip-api.com (gratuito, 45 req/min)
    try:
        async with aiohttp.ClientSession() as session:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,reverse,hosting"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    datos = await resp.json()
                    if datos.get("status") == "success":
                        resultado["hostname"] = datos.get("reverse", "")
                        resultado["organizacion"] = datos.get("org", "")
                        resultado["asn"] = datos.get("as", "")
                        resultado["isp"] = datos.get("isp", "")
                        resultado["pais"] = datos.get("country", "")
                        resultado["ciudad"] = datos.get("city", "")
                        resultado["exitoso"] = True

    except Exception as error:
        log.warning(f"IP info falló para {ip}: {error}")

    return resultado


def _extraer_str(valor: Any) -> str:
    """Extrae un string de un valor que puede ser lista, None, etc."""
    if valor is None:
        return ""
    if isinstance(valor, list):
        return str(valor[0]) if valor else ""
    return str(valor)

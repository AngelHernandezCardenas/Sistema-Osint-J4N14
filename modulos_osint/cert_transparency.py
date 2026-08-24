"""
modulos_osint/cert_transparency.py — Certificate Transparency para Recon365.

Consulta logs de Certificate Transparency para descubrir:
    - Certificados emitidos para un dominio
    - Subject Alternative Names (SANs) — revelan subdominios
    - Emisores y fechas de validez
    - Certificados expirados o próximos a expirar

Usa crt.sh como fuente primaria (gratuito, sin API key).

Uso:
    from modulos_osint.cert_transparency import analizar_certificados
    certs = await analizar_certificados("example.com")
"""

import asyncio
from datetime import datetime
from typing import Any

import aiohttp

from utilidades.logger import obtener_logger

log = obtener_logger(__name__)


async def consultar_crtsh_detallado(dominio: str) -> list[dict[str, Any]]:
    """
    Consulta crt.sh para obtener certificados detallados.

    Args:
        dominio: Dominio a buscar.

    Returns:
        Lista de certificados con metadata.
    """
    certificados: list[dict[str, Any]] = []
    url = f"https://crt.sh/?q=%.{dominio}&output=json"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    datos = await resp.json(content_type=None)

                    # Deduplicar por serial number
                    seriales_vistos: set[str] = set()

                    for entrada in datos:
                        serial = str(entrada.get("serial_number", ""))
                        if serial in seriales_vistos:
                            continue
                        seriales_vistos.add(serial)

                        # Extraer SANs del name_value
                        name_value = entrada.get("name_value", "")
                        sans = [
                            s.strip().lower()
                            for s in name_value.split("\n")
                            if s.strip() and not s.strip().startswith("*")
                        ]

                        cert: dict[str, Any] = {
                            "dominio_comun": entrada.get("common_name", ""),
                            "sans": sans,
                            "emisor": entrada.get("issuer_name", ""),
                            "fecha_emision": entrada.get("not_before", ""),
                            "fecha_expiracion": entrada.get("not_after", ""),
                            "serial": serial,
                            "id_crtsh": entrada.get("id", 0),
                        }

                        # Analizar estado
                        cert["estado"] = _analizar_estado_cert(cert)
                        certificados.append(cert)

        log.info(
            f"Certificate Transparency: {len(certificados)} certificados "
            f"únicos para {dominio}"
        )

    except asyncio.TimeoutError:
        log.warning(f"Timeout consultando crt.sh para {dominio}")
    except Exception as error:
        log.warning(f"Error en CT para {dominio}: {error}")

    return certificados


def _analizar_estado_cert(cert: dict[str, Any]) -> str:
    """Determina el estado de un certificado."""
    try:
        fecha_exp_str = cert.get("fecha_expiracion", "")
        if fecha_exp_str:
            # crt.sh devuelve formato ISO
            fecha_exp = datetime.fromisoformat(
                fecha_exp_str.replace("T", " ").split(".")[0]
            )
            ahora = datetime.now()

            if fecha_exp < ahora:
                return "expirado"

            dias_restantes = (fecha_exp - ahora).days
            if dias_restantes < 30:
                return "proximo_a_expirar"

            return "valido"
    except (ValueError, TypeError):
        pass

    return "desconocido"


async def analizar_certificados(dominio: str) -> dict[str, Any]:
    """
    Análisis completo de certificados para un dominio.

    Args:
        dominio: Dominio a analizar.

    Returns:
        Diccionario con certificados, subdominios descubiertos y problemas.
    """
    log.info(f"Análisis de certificados: {dominio}")

    certs = await consultar_crtsh_detallado(dominio)

    # Extraer todos los subdominios únicos de SANs
    subdominios_descubiertos: set[str] = set()
    emisores: set[str] = set()
    expirados: int = 0
    proximos_a_expirar: int = 0
    problemas: list[str] = []

    for cert in certs:
        for san in cert.get("sans", []):
            if san.endswith(dominio):
                subdominios_descubiertos.add(san)

        emisor = cert.get("emisor", "")
        if emisor:
            emisores.add(emisor)

        estado = cert.get("estado", "")
        if estado == "expirado":
            expirados += 1
        elif estado == "proximo_a_expirar":
            proximos_a_expirar += 1

    # Detectar problemas
    if expirados > 0:
        problemas.append(
            f"Se detectaron {expirados} certificados expirados"
        )
    if proximos_a_expirar > 0:
        problemas.append(
            f"{proximos_a_expirar} certificados próximos a expirar (< 30 días)"
        )
    if len(emisores) > 3:
        problemas.append(
            f"Múltiples emisores de certificados ({len(emisores)}) — "
            "posible gestión descentralizada"
        )

    resultado: dict[str, Any] = {
        "dominio": dominio,
        "total_certificados": len(certs),
        "certificados": certs[:50],  # Limitar a los primeros 50
        "subdominios_descubiertos": sorted(subdominios_descubiertos),
        "emisores": sorted(emisores),
        "expirados": expirados,
        "proximos_a_expirar": proximos_a_expirar,
        "problemas": problemas,
    }

    log.info(
        f"CT completado para {dominio}: {len(certs)} certs, "
        f"{len(subdominios_descubiertos)} subdominios vía SANs"
    )

    return resultado

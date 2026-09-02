"""
modulos/enviador.py — Módulo de envío de correos para Recon365.

Envía los correos de Spear Phishing generados por J4N14 a través de
un servidor SMTP configurado por el operador.

Soporta:
    - SMTP con TLS (Gmail, Outlook, servidores corporativos)
    - SMTP sin autenticación (MailHog, servidores locales de prueba)
    - Generación de archivos .eml para preview offline

Uso:
    from modulos.enviador import enviar_correo, generar_eml
    exito = enviar_correo(config_smtp, remitente, destinatario, asunto, cuerpo)
    ruta = generar_eml(remitente, destinatario, asunto, cuerpo, "preview")

ADVERTENCIA: Solo para auditorías de seguridad AUTORIZADAS.
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any, Optional

from utilidades.logger import obtener_logger
from configuracion import RUTA_OUTPUTS

log = obtener_logger(__name__)


# TIPOS

class ConfigSMTP:
    """Configuración de conexión SMTP."""

    def __init__(
        self,
        servidor: str = "localhost",
        puerto: int = 587,
        usuario: str = "",
        password: str = "",
        usar_tls: bool = True,
    ):
        self.servidor = servidor
        self.puerto = puerto
        self.usuario = usuario
        self.password = password
        self.usar_tls = usar_tls

    def __repr__(self) -> str:
        return (
            f"SMTP({self.servidor}:{self.puerto}, "
            f"TLS={'Sí' if self.usar_tls else 'No'}, "
            f"usuario='{self.usuario or 'ninguno'}')"
        )


# FUNCIÓN DE CONSTRUCCIÓN DEL EMAIL

def _construir_mensaje(
    remitente: str,
    nombre_remitente: str,
    destinatario: str,
    asunto: str,
    cuerpo: str,
) -> MIMEMultipart:
    """
    Construye un mensaje MIME listo para enviar.

    Args:
        remitente: Dirección de correo del remitente.
        nombre_remitente: Nombre visible del remitente.
        destinatario: Dirección de correo del destinatario.
        asunto: Asunto del correo.
        cuerpo: Cuerpo del correo en texto plano.

    Returns:
        Objeto MIMEMultipart configurado.
    """
    mensaje = MIMEMultipart("alternative")
    mensaje["From"] = f"{nombre_remitente} <{remitente}>"
    mensaje["To"] = destinatario
    mensaje["Subject"] = asunto
    mensaje["Date"] = formatdate(localtime=True)
    mensaje["Message-ID"] = make_msgid(domain=remitente.split("@")[-1] if "@" in remitente else "recon365.local")

    # Headers para que parezca más legítimo
    mensaje["X-Mailer"] = "Microsoft Outlook 16.0"
    mensaje["X-Priority"] = "1"  # Alta prioridad

    # Cuerpo en texto plano
    parte_texto = MIMEText(cuerpo, "plain", "utf-8")
    mensaje.attach(parte_texto)

    # Cuerpo en HTML (mismo contenido pero con formato)
    cuerpo_html = cuerpo.replace("\n", "<br>\n")
    cuerpo_html = f"""
    <html>
    <body style="font-family: Calibri, Arial, sans-serif; font-size: 14px; color: #333;">
    <p>{cuerpo_html}</p>
    </body>
    </html>
    """
    parte_html = MIMEText(cuerpo_html, "html", "utf-8")
    mensaje.attach(parte_html)

    return mensaje


# ENVÍO POR SMTP

def enviar_correo(
    config: ConfigSMTP,
    remitente: str,
    nombre_remitente: str,
    destinatario: str,
    asunto: str,
    cuerpo: str,
) -> bool:
    """
    Envía un correo electrónico vía SMTP.

    Args:
        config: Configuración del servidor SMTP.
        remitente: Dirección de correo del remitente.
        nombre_remitente: Nombre visible del remitente.
        destinatario: Dirección de correo destino.
        asunto: Asunto del correo.
        cuerpo: Cuerpo del correo.

    Returns:
        True si el envío fue exitoso, False en caso contrario.
    """
    mensaje = _construir_mensaje(
        remitente, nombre_remitente, destinatario, asunto, cuerpo
    )

    try:
        log.info(f"Conectando a {config}...")

        if config.usar_tls:
            # SMTP con STARTTLS (Gmail, Outlook, etc.)
            contexto_ssl = ssl.create_default_context()
            with smtplib.SMTP(config.servidor, config.puerto, timeout=30) as servidor:
                servidor.ehlo()
                servidor.starttls(context=contexto_ssl)
                servidor.ehlo()
                if config.usuario and config.password:
                    servidor.login(config.usuario, config.password)
                servidor.sendmail(remitente, destinatario, mensaje.as_string())
        else:
            # SMTP sin TLS (servidores locales, MailHog, etc.)
            with smtplib.SMTP(config.servidor, config.puerto, timeout=30) as servidor:
                servidor.ehlo()
                if config.usuario and config.password:
                    servidor.login(config.usuario, config.password)
                servidor.sendmail(remitente, destinatario, mensaje.as_string())

        log.info(f"Correo enviado exitosamente a {destinatario}")
        return True

    except smtplib.SMTPAuthenticationError as e:
        log.error(
            f"Error de autenticación SMTP: {e}. "
            f"Verifica usuario/contraseña. Para Gmail usa una App Password."
        )
        return False
    except smtplib.SMTPRecipientsRefused as e:
        log.error(f"Destinatario rechazado: {e}")
        return False
    except smtplib.SMTPException as e:
        log.error(f"Error SMTP: {e}")
        return False
    except ConnectionRefusedError:
        log.error(
            f"No se pudo conectar a {config.servidor}:{config.puerto}. "
            f"Verifica que el servidor SMTP esté activo."
        )
        return False
    except Exception as e:
        log.error(f"Error inesperado al enviar correo: {e}")
        return False


# GENERADOR DE ARCHIVOS .EML (PREVIEW OFFLINE)

def generar_eml(
    remitente: str,
    nombre_remitente: str,
    destinatario: str,
    asunto: str,
    cuerpo: str,
    nombre_archivo: str = "preview",
) -> Optional[Path]:
    """
    Genera un archivo .eml que se puede abrir en Outlook/Thunderbird.

    Args:
        remitente: Dirección del remitente.
        nombre_remitente: Nombre visible del remitente.
        destinatario: Dirección del destinatario.
        asunto: Asunto del correo.
        cuerpo: Cuerpo del correo.
        nombre_archivo: Nombre base del archivo .eml.

    Returns:
        Path al archivo .eml generado, o None si falla.
    """
    mensaje = _construir_mensaje(
        remitente, nombre_remitente, destinatario, asunto, cuerpo
    )

    try:
        ruta_eml = RUTA_OUTPUTS / f"{nombre_archivo}.eml"
        ruta_eml.parent.mkdir(parents=True, exist_ok=True)

        with open(ruta_eml, "w", encoding="utf-8") as f:
            f.write(mensaje.as_string())

        log.info(f"Archivo .eml generado: {ruta_eml}")
        return ruta_eml

    except Exception as e:
        log.error(f"Error al generar .eml: {e}")
        return None

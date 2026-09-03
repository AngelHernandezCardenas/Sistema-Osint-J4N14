"""
enviar_prueba.py — Script interactivo para probar correos de J4N14.

Genera un correo de Spear Phishing con el Motor J4N14 (Dolphin)
y lo envía a la dirección que indiques vía SMTP.

Uso:
    python enviar_prueba.py

ADVERTENCIA: Solo para pruebas con tu propio correo en auditorías autorizadas.
"""

import io
import sys
import getpass
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Forzar UTF-8 en la terminal de Windows
if sys.stdout and hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "buffer"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm

from modulos.generador_ataques import crear_pretexto, _generar_con_ia
from modulos.enviador import ConfigSMTP, enviar_correo, generar_eml
from configuracion import NOMBRE_MOTOR

consola = Console()


def mostrar_banner():
    """Muestra el banner del script."""
    consola.print()
    consola.print(Panel.fit(
        "[bold cyan]Recon365 — Prueba de Envío de Correos[/bold cyan]\n"
        f"[dim]Motor {NOMBRE_MOTOR} + Dolphin[/dim]\n"
        "[yellow] Solo para pruebas autorizadas con tu propio correo[/yellow]",
        border_style="cyan",
    ))
    consola.print()


def solicitar_perfil() -> dict:
    """Solicita los datos del perfil objetivo al usuario."""
    consola.print("[bold]═══ DATOS DEL PERFIL OBJETIVO ═══[/bold]\n")

    nombre = Prompt.ask("[cyan]Nombre del objetivo[/cyan]", default="Juan Pérez")
    rol = Prompt.ask("[cyan]Rol / Cargo[/cyan]", default="Director de TI")
    empresa = Prompt.ask("[cyan]Empresa[/cyan]", default="TechCorp")
    industria = Prompt.ask("[cyan]Industria[/cyan]", default="Tecnología")
    intereses = Prompt.ask(
        "[cyan]Intereses (separados por coma)[/cyan]",
        default="Python, Cloud Computing, Ciberseguridad"
    )

    consola.print("\n[bold]Categorías disponibles:[/bold]")
    consola.print("  [magenta]1.[/magenta] JERARQUIA — Urgencia corporativa, auditorías")
    consola.print("  [magenta]2.[/magenta] ESTILO_VIDA — Premios, sorteos, ofertas")
    consola.print("  [magenta]3.[/magenta] TECNOLOGICO — Alertas de seguridad, actualizaciones")

    cat_opcion = Prompt.ask(
        "\n[cyan]Categoría[/cyan]",
        choices=["1", "2", "3"],
        default="3"
    )

    categorias = {"1": "JERARQUIA", "2": "ESTILO_VIDA", "3": "TECNOLOGICO"}
    categoria = categorias[cat_opcion]

    return {
        "nombre_objetivo": nombre,
        "rol_detectado": rol,
        "empresa": empresa,
        "industria": industria,
        "intereses": [i.strip() for i in intereses.split(",")],
        "vulnerabilidades": [
            "Susceptible a mensajes que explotan su rol profesional",
            "Reacciona a urgencias relacionadas con su industria",
        ],
        "necesidades_inferidas": [
            "Mantenerse actualizado en su campo",
            "Proteger los activos de su empresa",
        ],
        "categoria_predictiva": categoria,
        "confianza": 0.85,
    }


def solicitar_smtp() -> tuple[ConfigSMTP, str, str]:
    """Solicita la configuración SMTP al usuario.

    Si las variables de entorno SMTP_* están definidas, las usa automáticamente
    sin pedir contraseña interactiva (modo pruebas rápidas).

    Variables de entorno soportadas:
        SMTP_SERVIDOR   — ej. smtp.gmail.com
        SMTP_PUERTO     — ej. 587
        SMTP_USUARIO    — ej. tu@gmail.com
        SMTP_PASSWORD   — App Password (nunca en el repo)
        SMTP_REMITENTE  — Email del "from" spoofed (opcional)
        SMTP_NOMBRE     — Nombre del remitente (opcional)
    """
    consola.print("\n[bold]═══ CONFIGURACIÓN SMTP ═══[/bold]\n")

    consola.print("[dim]Proveedores comunes:[/dim]")
    tabla = Table(show_header=True, header_style="bold")
    tabla.add_column("Proveedor")
    tabla.add_column("Servidor")
    tabla.add_column("Puerto")
    tabla.add_column("Nota")
    tabla.add_row("Gmail", "smtp.gmail.com", "587", "Requiere App Password")
    tabla.add_row("Outlook", "smtp.office365.com", "587", "Requiere App Password")
    tabla.add_row("Yahoo", "smtp.mail.yahoo.com", "587", "Requiere App Password")
    tabla.add_row("MailHog (local)", "localhost", "1025", "Sin autenticación")
    consola.print(tabla)
    consola.print()

    # ── Autocompletado desde variables de entorno (modo pruebas) ────────────
    _env_servidor  = os.environ.get("SMTP_SERVIDOR", "")
    _env_puerto    = os.environ.get("SMTP_PUERTO", "")
    _env_usuario   = os.environ.get("SMTP_USUARIO", "")
    _env_password  = os.environ.get("SMTP_PASSWORD", "")

    if _env_password:
        consola.print(
            "[dim green]ℹ  Credenciales cargadas desde variables de entorno "
            "(SMTP_PASSWORD detectado). Saltando prompt interactivo.[/dim green]\n"
        )

    servidor = Prompt.ask(
        "[cyan]Servidor SMTP[/cyan]",
        default=_env_servidor if _env_servidor else "smtp.gmail.com",
    )
    puerto = int(Prompt.ask(
        "[cyan]Puerto[/cyan]",
        default=_env_puerto if _env_puerto else "587",
    ))

    usar_tls = True
    usuario = ""
    password = ""

    if servidor == "localhost":
        usar_tls = False
        consola.print("[dim]Modo local: sin TLS ni autenticación.[/dim]")
    else:
        usar_tls = Confirm.ask("[cyan]¿Usar TLS?[/cyan]", default=True)
        usuario = Prompt.ask(
            "[cyan]Usuario (email)[/cyan]",
            default=_env_usuario if _env_usuario else "",
        )
        if _env_password:
            # Usar la contraseña del entorno sin prompt interactivo
            password = _env_password
            consola.print("[dim]  Contraseña/App Password: [green]*** (desde SMTP_PASSWORD)[/green][/dim]")
        else:
            password = getpass.getpass("  Contraseña/App Password: ")

    config = ConfigSMTP(
        servidor=servidor,
        puerto=puerto,
        usuario=usuario,
        password=password,
        usar_tls=usar_tls,
    )

    # Remitente (el "from" del correo)
    _env_remitente = os.environ.get("SMTP_REMITENTE", "")
    _env_nombre    = os.environ.get("SMTP_NOMBRE", "")

    consola.print("\n[bold]═══ IDENTIDAD DEL REMITENTE ═══[/bold]\n")
    nombre_remitente = Prompt.ask(
        "[cyan]Nombre del remitente (spoofed)[/cyan]",
        default=_env_nombre if _env_nombre else "Equipo de Seguridad TI",
    )
    email_remitente = Prompt.ask(
        "[cyan]Email del remitente[/cyan]",
        default=_env_remitente if _env_remitente else (usuario if usuario else "seguridad@techcorp.com"),
    )

    return config, email_remitente, nombre_remitente


def main():
    """Flujo principal interactivo."""
    mostrar_banner()

    # 1. Perfil del objetivo
    perfil = solicitar_perfil()
    categoria = perfil["categoria_predictiva"]

    # 2. Generar correo con J4N14
    consola.print(f"\n[bold cyan]Generando correo con {NOMBRE_MOTOR} + Dolphin...[/bold cyan]\n")

    vector = crear_pretexto(perfil)

    asunto = vector.get("asunto", "Sin asunto")
    cuerpo = vector.get("cuerpo", "Sin cuerpo")
    generado_por = vector.get("generado_por", "desconocido")

    # 3. Preview del correo
    consola.print(Panel(
        f"[bold yellow]Asunto:[/bold yellow] {asunto}\n\n"
        f"[white]{cuerpo}[/white]\n\n"
        f"[dim]Generado por: {generado_por} | Categoría: {categoria}[/dim]",
        title="[bold green] PREVIEW DEL CORREO[/bold green]",
        border_style="green",
    ))

    # 4. ¿Enviar o solo guardar?
    consola.print()
    accion = Prompt.ask(
        "[cyan]¿Qué deseas hacer?[/cyan]",
        choices=["enviar", "guardar_eml", "ambos", "cancelar"],
        default="ambos"
    )

    if accion == "cancelar":
        consola.print("[yellow]Cancelado.[/yellow]")
        return

    # 5. Destinatario
    destinatario = Prompt.ask("\n[cyan] Email destino (tu correo)[/cyan]", default="angelus@mail.com")

    # 6. Guardar .eml
    if accion in ("guardar_eml", "ambos"):
        nombre_eml = f"phishing_test_{perfil['nombre_objetivo'].replace(' ', '_').lower()}"
        ruta = generar_eml(
            "seguridad@techcorp.com", "Equipo de Seguridad TI",
            destinatario, asunto, cuerpo, nombre_eml
        )
        if ruta:
            consola.print(f"\n[green] Archivo .eml guardado: {ruta}[/green]")
            consola.print(f"[dim]Puedes abrirlo con Outlook/Thunderbird para preview.[/dim]")

    # 7. Enviar por SMTP
    if accion in ("enviar", "ambos"):
        config, email_remitente, nombre_remitente = solicitar_smtp()

        consola.print(f"\n[bold]═══ CONFIRMACIÓN FINAL ═══[/bold]")
        consola.print(f"  De: {nombre_remitente} <{email_remitente}>")
        consola.print(f"  Para: {destinatario}")
        consola.print(f"  Asunto: {asunto}")
        consola.print(f"  SMTP: {config}")
        consola.print()

        if Confirm.ask("[bold red]¿Confirmar envío?[/bold red]", default=False):
            exito = enviar_correo(
                config, email_remitente, nombre_remitente,
                destinatario, asunto, cuerpo
            )
            if exito:
                consola.print("\n[bold green] ¡Correo enviado! Revisa tu bandeja.[/bold green]")
                consola.print("[dim]Si usas Gmail, revisa Spam también.[/dim]")
            else:
                consola.print("\n[bold red] Error al enviar. Revisa la configuración SMTP.[/bold red]")
        else:
            consola.print("[yellow]Envío cancelado.[/yellow]")

    consola.print("\n[dim]Fin de la prueba.[/dim]\n")


if __name__ == "__main__":
    main()

"""
utilidades/base_datos.py — Capa de persistencia para Recon365 OSINT/ASM.

Almacena todos los hallazgos del sistema en SQLite con soporte para:
    - Organizaciones, dominios, subdominios, IPs, servicios, tecnologías
    - Hallazgos de secretos y vulnerabilidades
    - Alertas y cambios detectados
    - Snapshots para monitoreo continuo
    - Grafo de relaciones entre entidades

Uso:
    from utilidades.base_datos import BaseDatos
    db = BaseDatos()
    org_id = db.crear_organizacion("Empresa X", "empresa.com")
    db.agregar_subdominio(org_id, "mail.empresa.com", "192.168.1.1")
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from configuracion import RUTA_BASE
from utilidades.logger import obtener_logger

log = obtener_logger(__name__)

RUTA_DB: Path = RUTA_BASE / "data" / "db" / "recon365.db"


class BaseDatos:
    """Gestor de base de datos SQLite para Recon365."""

    def __init__(self, ruta: Optional[Path] = None):
        self.ruta: Path = ruta or RUTA_DB
        self.ruta.parent.mkdir(parents=True, exist_ok=True)
        self._conexion: Optional[sqlite3.Connection] = None
        self._inicializar()

    # CONEXIÓN

    def _conectar(self) -> sqlite3.Connection:
        """Obtiene o crea una conexión SQLite."""
        if self._conexion is None:
            self._conexion = sqlite3.connect(str(self.ruta))
            self._conexion.row_factory = sqlite3.Row
            self._conexion.execute("PRAGMA journal_mode=WAL")
            self._conexion.execute("PRAGMA foreign_keys=ON")
        return self._conexion

    def cerrar(self) -> None:
        """Cierra la conexión a la base de datos."""
        if self._conexion:
            self._conexion.close()
            self._conexion = None

    # INICIALIZACIÓN DE ESQUEMA

    def _inicializar(self) -> None:
        """Crea las tablas si no existen."""
        conn = self._conectar()
        conn.executescript("""
            -- Organizaciones objetivo
            CREATE TABLE IF NOT EXISTS organizaciones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                dominio_principal TEXT NOT NULL UNIQUE,
                descripcion TEXT DEFAULT '',
                creado_en TEXT NOT NULL DEFAULT (datetime('now')),
                actualizado_en TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- Dominios descubiertos
            CREATE TABLE IF NOT EXISTS dominios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                dominio TEXT NOT NULL,
                tipo TEXT DEFAULT 'subdominio',
                ip_resuelta TEXT,
                activo INTEGER DEFAULT 1,
                fuente TEXT DEFAULT 'manual',
                primera_vez TEXT NOT NULL DEFAULT (datetime('now')),
                ultima_vez TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (org_id) REFERENCES organizaciones(id),
                UNIQUE(org_id, dominio)
            );

            -- Registros DNS
            CREATE TABLE IF NOT EXISTS registros_dns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dominio_id INTEGER NOT NULL,
                tipo TEXT NOT NULL,
                valor TEXT NOT NULL,
                ttl INTEGER,
                creado_en TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (dominio_id) REFERENCES dominios(id)
            );

            -- Información WHOIS
            CREATE TABLE IF NOT EXISTS whois_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dominio_id INTEGER NOT NULL,
                registrante TEXT,
                organizacion_registrante TEXT,
                nameservers TEXT,
                fecha_creacion TEXT,
                fecha_expiracion TEXT,
                raw_data TEXT,
                creado_en TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (dominio_id) REFERENCES dominios(id)
            );

            -- Certificados TLS
            CREATE TABLE IF NOT EXISTS certificados (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                dominio_comun TEXT NOT NULL,
                sans TEXT,
                emisor TEXT,
                fecha_emision TEXT,
                fecha_expiracion TEXT,
                serial TEXT,
                fuente TEXT DEFAULT 'crt.sh',
                creado_en TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (org_id) REFERENCES organizaciones(id)
            );

            -- Tecnologías detectadas
            CREATE TABLE IF NOT EXISTS tecnologias (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dominio_id INTEGER NOT NULL,
                nombre TEXT NOT NULL,
                version TEXT,
                categoria TEXT,
                fuente TEXT DEFAULT 'headers',
                confianza REAL DEFAULT 0.5,
                creado_en TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (dominio_id) REFERENCES dominios(id)
            );

            -- Servicios/puertos expuestos
            CREATE TABLE IF NOT EXISTS servicios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dominio_id INTEGER NOT NULL,
                puerto INTEGER NOT NULL,
                protocolo TEXT DEFAULT 'tcp',
                servicio TEXT,
                banner TEXT,
                creado_en TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (dominio_id) REFERENCES dominios(id)
            );

            -- Secretos / información sensible detectada
            CREATE TABLE IF NOT EXISTS secretos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                tipo TEXT NOT NULL,
                valor_ofuscado TEXT NOT NULL,
                fuente TEXT NOT NULL,
                ubicacion TEXT,
                severidad TEXT DEFAULT 'media',
                confianza REAL DEFAULT 0.5,
                estado TEXT DEFAULT 'nuevo',
                creado_en TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (org_id) REFERENCES organizaciones(id)
            );

            -- Vulnerabilidades (CVEs)
            CREATE TABLE IF NOT EXISTS vulnerabilidades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tecnologia_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                descripcion TEXT,
                cvss_score REAL,
                severidad TEXT,
                explotada_activamente INTEGER DEFAULT 0,
                fuente TEXT DEFAULT 'nvd',
                creado_en TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (tecnologia_id) REFERENCES tecnologias(id)
            );

            -- Evaluaciones de riesgo por activo
            CREATE TABLE IF NOT EXISTS evaluaciones_riesgo (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                entidad_tipo TEXT NOT NULL,
                entidad_id INTEGER NOT NULL,
                score_riesgo REAL NOT NULL,
                nivel TEXT NOT NULL,
                factores TEXT,
                creado_en TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (org_id) REFERENCES organizaciones(id)
            );

            -- Alertas
            CREATE TABLE IF NOT EXISTS alertas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                tipo TEXT NOT NULL,
                titulo TEXT NOT NULL,
                descripcion TEXT,
                severidad TEXT DEFAULT 'info',
                entidad_tipo TEXT,
                entidad_id INTEGER,
                evidencia TEXT,
                estado TEXT DEFAULT 'nueva',
                creado_en TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (org_id) REFERENCES organizaciones(id)
            );

            -- Snapshots para monitoreo
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                datos_json TEXT NOT NULL,
                total_dominios INTEGER DEFAULT 0,
                total_ips INTEGER DEFAULT 0,
                total_servicios INTEGER DEFAULT 0,
                total_tecnologias INTEGER DEFAULT 0,
                total_secretos INTEGER DEFAULT 0,
                total_vulnerabilidades INTEGER DEFAULT 0,
                creado_en TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (org_id) REFERENCES organizaciones(id)
            );

            -- Repositorios GitHub
            CREATE TABLE IF NOT EXISTS repositorios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL,
                nombre TEXT NOT NULL,
                url TEXT NOT NULL,
                descripcion TEXT,
                lenguaje TEXT,
                es_fork INTEGER DEFAULT 0,
                estrellas INTEGER DEFAULT 0,
                creado_en TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (org_id) REFERENCES organizaciones(id)
            );

            -- Headers de seguridad
            CREATE TABLE IF NOT EXISTS headers_seguridad (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dominio_id INTEGER NOT NULL,
                header TEXT NOT NULL,
                valor TEXT,
                presente INTEGER DEFAULT 0,
                recomendacion TEXT,
                creado_en TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (dominio_id) REFERENCES dominios(id)
            );

            -- Índices para rendimiento
            CREATE INDEX IF NOT EXISTS idx_dominios_org ON dominios(org_id);
            CREATE INDEX IF NOT EXISTS idx_dominios_dominio ON dominios(dominio);
            CREATE INDEX IF NOT EXISTS idx_tecnologias_dominio ON tecnologias(dominio_id);
            CREATE INDEX IF NOT EXISTS idx_secretos_org ON secretos(org_id);
            CREATE INDEX IF NOT EXISTS idx_alertas_org ON alertas(org_id);
            CREATE INDEX IF NOT EXISTS idx_vulnerabilidades_tech ON vulnerabilidades(tecnologia_id);
        """)
        conn.commit()
        log.debug(f"Base de datos inicializada: {self.ruta}")

    # ORGANIZACIONES

    def crear_organizacion(
        self, nombre: str, dominio_principal: str, descripcion: str = ""
    ) -> int:
        """Crea una organización y retorna su ID."""
        conn = self._conectar()
        try:
            cursor = conn.execute(
                "INSERT INTO organizaciones (nombre, dominio_principal, descripcion) "
                "VALUES (?, ?, ?)",
                (nombre, dominio_principal, descripcion),
            )
            conn.commit()
            org_id = cursor.lastrowid
            log.info(f"Organización creada: '{nombre}' (ID: {org_id})")

            # Crear el dominio principal como primer dominio
            self.agregar_dominio(org_id, dominio_principal, tipo="principal", fuente="manual")
            return org_id
        except sqlite3.IntegrityError:
            # Ya existe, retornar ID existente
            row = conn.execute(
                "SELECT id FROM organizaciones WHERE dominio_principal = ?",
                (dominio_principal,),
            ).fetchone()
            log.info(f"Organización ya existe: '{nombre}' (ID: {row['id']})")
            return row["id"]

    def obtener_organizacion(self, org_id: int) -> Optional[dict]:
        """Obtiene una organización por ID."""
        conn = self._conectar()
        row = conn.execute(
            "SELECT * FROM organizaciones WHERE id = ?", (org_id,)
        ).fetchone()
        return dict(row) if row else None

    def listar_organizaciones(self) -> list[dict]:
        """Lista todas las organizaciones."""
        conn = self._conectar()
        rows = conn.execute("SELECT * FROM organizaciones ORDER BY creado_en DESC").fetchall()
        return [dict(r) for r in rows]

    # DOMINIOS Y SUBDOMINIOS

    def agregar_dominio(
        self, org_id: int, dominio: str, tipo: str = "subdominio",
        ip: Optional[str] = None, fuente: str = "descubrimiento",
    ) -> int:
        """Agrega un dominio/subdominio descubierto."""
        conn = self._conectar()
        try:
            cursor = conn.execute(
                "INSERT INTO dominios (org_id, dominio, tipo, ip_resuelta, fuente) "
                "VALUES (?, ?, ?, ?, ?)",
                (org_id, dominio, tipo, ip, fuente),
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            # Actualizar última vez visto y la IP si cambió
            conn.execute(
                "UPDATE dominios SET ultima_vez = datetime('now'), "
                "ip_resuelta = COALESCE(?, ip_resuelta) "
                "WHERE org_id = ? AND dominio = ?",
                (ip, org_id, dominio),
            )
            conn.commit()
            row = conn.execute(
                "SELECT id FROM dominios WHERE org_id = ? AND dominio = ?",
                (org_id, dominio),
            ).fetchone()
            return row["id"] if row else 0

    def obtener_dominios(self, org_id: int) -> list[dict]:
        """Obtiene todos los dominios de una organización."""
        conn = self._conectar()
        rows = conn.execute(
            "SELECT * FROM dominios WHERE org_id = ? ORDER BY tipo, dominio",
            (org_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def obtener_dominio_id(self, org_id: int, dominio: str) -> Optional[int]:
        """Obtiene el ID de un dominio por nombre."""
        conn = self._conectar()
        row = conn.execute(
            "SELECT id FROM dominios WHERE org_id = ? AND dominio = ?",
            (org_id, dominio),
        ).fetchone()
        return row["id"] if row else None

    # REGISTROS DNS

    def agregar_registro_dns(
        self, dominio_id: int, tipo: str, valor: str, ttl: Optional[int] = None,
    ) -> int:
        """Agrega un registro DNS."""
        conn = self._conectar()
        cursor = conn.execute(
            "INSERT INTO registros_dns (dominio_id, tipo, valor, ttl) VALUES (?, ?, ?, ?)",
            (dominio_id, tipo, valor, ttl),
        )
        conn.commit()
        return cursor.lastrowid

    def obtener_registros_dns(self, dominio_id: int) -> list[dict]:
        """Obtiene los registros DNS de un dominio."""
        conn = self._conectar()
        rows = conn.execute(
            "SELECT * FROM registros_dns WHERE dominio_id = ? ORDER BY tipo",
            (dominio_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # WHOIS

    def agregar_whois(
        self, dominio_id: int, registrante: str = "", organizacion: str = "",
        nameservers: str = "", fecha_creacion: str = "",
        fecha_expiracion: str = "", raw_data: str = "",
    ) -> int:
        """Agrega información WHOIS."""
        conn = self._conectar()
        cursor = conn.execute(
            "INSERT INTO whois_info "
            "(dominio_id, registrante, organizacion_registrante, nameservers, "
            "fecha_creacion, fecha_expiracion, raw_data) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (dominio_id, registrante, organizacion, nameservers,
             fecha_creacion, fecha_expiracion, raw_data),
        )
        conn.commit()
        return cursor.lastrowid

    # CERTIFICADOS

    def agregar_certificado(
        self, org_id: int, dominio_comun: str, sans: str = "",
        emisor: str = "", fecha_emision: str = "", fecha_expiracion: str = "",
        serial: str = "", fuente: str = "crt.sh",
    ) -> int:
        """Agrega un certificado TLS descubierto."""
        conn = self._conectar()
        cursor = conn.execute(
            "INSERT INTO certificados "
            "(org_id, dominio_comun, sans, emisor, fecha_emision, "
            "fecha_expiracion, serial, fuente) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (org_id, dominio_comun, sans, emisor, fecha_emision,
             fecha_expiracion, serial, fuente),
        )
        conn.commit()
        return cursor.lastrowid

    def obtener_certificados(self, org_id: int) -> list[dict]:
        """Obtiene certificados de una organización."""
        conn = self._conectar()
        rows = conn.execute(
            "SELECT * FROM certificados WHERE org_id = ? ORDER BY creado_en DESC",
            (org_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # TECNOLOGÍAS

    def agregar_tecnologia(
        self, dominio_id: int, nombre: str, version: str = "",
        categoria: str = "", fuente: str = "headers", confianza: float = 0.5,
    ) -> int:
        """Agrega una tecnología detectada."""
        conn = self._conectar()
        cursor = conn.execute(
            "INSERT INTO tecnologias "
            "(dominio_id, nombre, version, categoria, fuente, confianza) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (dominio_id, nombre, version, categoria, fuente, confianza),
        )
        conn.commit()
        return cursor.lastrowid

    def obtener_tecnologias(self, org_id: int) -> list[dict]:
        """Obtiene todas las tecnologías de una organización (join con dominios)."""
        conn = self._conectar()
        rows = conn.execute(
            "SELECT t.*, d.dominio FROM tecnologias t "
            "JOIN dominios d ON t.dominio_id = d.id "
            "WHERE d.org_id = ? ORDER BY t.nombre",
            (org_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # SECRETOS

    def agregar_secreto(
        self, org_id: int, tipo: str, valor_ofuscado: str,
        fuente: str, ubicacion: str = "", severidad: str = "media",
        confianza: float = 0.5,
    ) -> int:
        """Agrega un secreto/dato sensible detectado."""
        conn = self._conectar()
        cursor = conn.execute(
            "INSERT INTO secretos "
            "(org_id, tipo, valor_ofuscado, fuente, ubicacion, severidad, confianza) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (org_id, tipo, valor_ofuscado, fuente, ubicacion, severidad, confianza),
        )
        conn.commit()
        return cursor.lastrowid

    def obtener_secretos(self, org_id: int) -> list[dict]:
        """Obtiene secretos detectados para una organización."""
        conn = self._conectar()
        rows = conn.execute(
            "SELECT * FROM secretos WHERE org_id = ? ORDER BY severidad DESC, creado_en DESC",
            (org_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # VULNERABILIDADES

    def agregar_vulnerabilidad(
        self, tecnologia_id: int, cve_id: str, descripcion: str = "",
        cvss_score: float = 0.0, severidad: str = "media",
        explotada: bool = False, fuente: str = "nvd",
    ) -> int:
        """Agrega una vulnerabilidad CVE."""
        conn = self._conectar()
        cursor = conn.execute(
            "INSERT INTO vulnerabilidades "
            "(tecnologia_id, cve_id, descripcion, cvss_score, severidad, "
            "explotada_activamente, fuente) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tecnologia_id, cve_id, descripcion, cvss_score, severidad,
             1 if explotada else 0, fuente),
        )
        conn.commit()
        return cursor.lastrowid

    def obtener_vulnerabilidades(self, org_id: int) -> list[dict]:
        """Obtiene vulnerabilidades de una organización (join completo)."""
        conn = self._conectar()
        rows = conn.execute(
            "SELECT v.*, t.nombre as tech_nombre, t.version as tech_version, "
            "d.dominio FROM vulnerabilidades v "
            "JOIN tecnologias t ON v.tecnologia_id = t.id "
            "JOIN dominios d ON t.dominio_id = d.id "
            "WHERE d.org_id = ? ORDER BY v.cvss_score DESC",
            (org_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # RIESGO

    def agregar_evaluacion_riesgo(
        self, org_id: int, entidad_tipo: str, entidad_id: int,
        score: float, nivel: str, factores: dict,
    ) -> int:
        """Agrega una evaluación de riesgo."""
        conn = self._conectar()
        cursor = conn.execute(
            "INSERT INTO evaluaciones_riesgo "
            "(org_id, entidad_tipo, entidad_id, score_riesgo, nivel, factores) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (org_id, entidad_tipo, entidad_id, score, nivel, json.dumps(factores)),
        )
        conn.commit()
        return cursor.lastrowid

    # ALERTAS

    def crear_alerta(
        self, org_id: int, tipo: str, titulo: str, descripcion: str = "",
        severidad: str = "info", entidad_tipo: str = "",
        entidad_id: int = 0, evidencia: str = "",
    ) -> int:
        """Crea una nueva alerta."""
        conn = self._conectar()
        cursor = conn.execute(
            "INSERT INTO alertas "
            "(org_id, tipo, titulo, descripcion, severidad, "
            "entidad_tipo, entidad_id, evidencia) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (org_id, tipo, titulo, descripcion, severidad,
             entidad_tipo, entidad_id, evidencia),
        )
        conn.commit()
        return cursor.lastrowid

    def obtener_alertas(self, org_id: int) -> list[dict]:
        """Obtiene alertas de una organización."""
        conn = self._conectar()
        rows = conn.execute(
            "SELECT * FROM alertas WHERE org_id = ? ORDER BY creado_en DESC",
            (org_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # REPOSITORIOS

    def agregar_repositorio(
        self, org_id: int, nombre: str, url: str, descripcion: str = "",
        lenguaje: str = "", es_fork: bool = False, estrellas: int = 0,
    ) -> int:
        """Agrega un repositorio GitHub descubierto."""
        conn = self._conectar()
        cursor = conn.execute(
            "INSERT INTO repositorios "
            "(org_id, nombre, url, descripcion, lenguaje, es_fork, estrellas) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (org_id, nombre, url, descripcion, lenguaje,
             1 if es_fork else 0, estrellas),
        )
        conn.commit()
        return cursor.lastrowid

    def obtener_repositorios(self, org_id: int) -> list[dict]:
        """Obtiene repositorios de una organización."""
        conn = self._conectar()
        rows = conn.execute(
            "SELECT * FROM repositorios WHERE org_id = ? ORDER BY estrellas DESC",
            (org_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # HEADERS DE SEGURIDAD

    def agregar_header_seguridad(
        self, dominio_id: int, header: str, valor: str = "",
        presente: bool = False, recomendacion: str = "",
    ) -> int:
        """Agrega un análisis de header de seguridad."""
        conn = self._conectar()
        cursor = conn.execute(
            "INSERT INTO headers_seguridad "
            "(dominio_id, header, valor, presente, recomendacion) "
            "VALUES (?, ?, ?, ?, ?)",
            (dominio_id, header, valor, 1 if presente else 0, recomendacion),
        )
        conn.commit()
        return cursor.lastrowid

    # SNAPSHOTS Y MONITOREO

    def crear_snapshot(self, org_id: int) -> int:
        """Crea un snapshot del estado actual para comparación futura."""
        conn = self._conectar()
        dominios = self.obtener_dominios(org_id)
        techs = self.obtener_tecnologias(org_id)
        secretos = self.obtener_secretos(org_id)
        vulns = self.obtener_vulnerabilidades(org_id)

        ips_unicas = set(d.get("ip_resuelta", "") for d in dominios if d.get("ip_resuelta"))

        datos = {
            "dominios": [d["dominio"] for d in dominios],
            "ips": list(ips_unicas),
            "tecnologias": [f"{t['nombre']}:{t.get('version', '')}" for t in techs],
            "secretos_count": len(secretos),
            "vulnerabilidades": [v["cve_id"] for v in vulns],
        }

        cursor = conn.execute(
            "INSERT INTO snapshots "
            "(org_id, datos_json, total_dominios, total_ips, total_servicios, "
            "total_tecnologias, total_secretos, total_vulnerabilidades) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (org_id, json.dumps(datos), len(dominios), len(ips_unicas),
             0, len(techs), len(secretos), len(vulns)),
        )
        conn.commit()
        return cursor.lastrowid

    def obtener_ultimo_snapshot(self, org_id: int) -> Optional[dict]:
        """Obtiene el snapshot más reciente."""
        conn = self._conectar()
        row = conn.execute(
            "SELECT * FROM snapshots WHERE org_id = ? ORDER BY creado_en DESC LIMIT 1",
            (org_id,),
        ).fetchone()
        if row:
            resultado = dict(row)
            resultado["datos"] = json.loads(resultado["datos_json"])
            return resultado
        return None

    def comparar_snapshots(self, org_id: int) -> dict[str, Any]:
        """Compara el estado actual con el último snapshot."""
        ultimo = self.obtener_ultimo_snapshot(org_id)
        if not ultimo:
            return {"cambios": False, "mensaje": "No hay snapshots previos"}

        dominios_actuales = set(d["dominio"] for d in self.obtener_dominios(org_id))
        dominios_previos = set(ultimo["datos"].get("dominios", []))

        nuevos = dominios_actuales - dominios_previos
        eliminados = dominios_previos - dominios_actuales

        return {
            "cambios": bool(nuevos or eliminados),
            "nuevos_dominios": list(nuevos),
            "dominios_eliminados": list(eliminados),
            "total_actual": len(dominios_actuales),
            "total_previo": len(dominios_previos),
        }

    # ESTADÍSTICAS

    def obtener_estadisticas(self, org_id: int) -> dict[str, int]:
        """Obtiene estadísticas generales de una organización."""
        conn = self._conectar()

        stats = {}
        queries = {
            "total_dominios": "SELECT COUNT(*) FROM dominios WHERE org_id = ?",
            "total_subdominios": "SELECT COUNT(*) FROM dominios WHERE org_id = ? AND tipo = 'subdominio'",
            "total_tecnologias": (
                "SELECT COUNT(*) FROM tecnologias t "
                "JOIN dominios d ON t.dominio_id = d.id WHERE d.org_id = ?"
            ),
            "total_secretos": "SELECT COUNT(*) FROM secretos WHERE org_id = ?",
            "total_vulnerabilidades": (
                "SELECT COUNT(*) FROM vulnerabilidades v "
                "JOIN tecnologias t ON v.tecnologia_id = t.id "
                "JOIN dominios d ON t.dominio_id = d.id WHERE d.org_id = ?"
            ),
            "total_certificados": "SELECT COUNT(*) FROM certificados WHERE org_id = ?",
            "total_alertas": "SELECT COUNT(*) FROM alertas WHERE org_id = ?",
            "total_repositorios": "SELECT COUNT(*) FROM repositorios WHERE org_id = ?",
        }

        for key, query in queries.items():
            row = conn.execute(query, (org_id,)).fetchone()
            stats[key] = row[0] if row else 0

        # IPs únicas
        ips = conn.execute(
            "SELECT DISTINCT ip_resuelta FROM dominios "
            "WHERE org_id = ? AND ip_resuelta IS NOT NULL AND ip_resuelta != ''",
            (org_id,),
        ).fetchall()
        stats["total_ips_unicas"] = len(ips)

        return stats

    # EXPORTACIÓN PARA GRAFO

    def exportar_grafo(self, org_id: int) -> dict[str, Any]:
        """Exporta datos para construir el grafo de correlación."""
        org = self.obtener_organizacion(org_id)
        dominios = self.obtener_dominios(org_id)
        techs = self.obtener_tecnologias(org_id)
        certs = self.obtener_certificados(org_id)
        vulns = self.obtener_vulnerabilidades(org_id)
        repos = self.obtener_repositorios(org_id)
        secretos = self.obtener_secretos(org_id)

        return {
            "organizacion": org,
            "dominios": dominios,
            "tecnologias": techs,
            "certificados": certs,
            "vulnerabilidades": vulns,
            "repositorios": repos,
            "secretos": secretos,
        }

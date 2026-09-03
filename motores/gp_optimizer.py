"""
motores/gp_optimizer.py — Motor de Programación Genética para Recon365.

Evoluciona funciones de puntuación (árboles GP) que aprenden a seleccionar
la plantilla de Spear Phishing óptima para cada tipo de perfil objetivo.

Inspirado en el paradigma de optimización dinámica multi-entorno:
- Cada "fase" corresponde a un tipo de categoría predictiva del perfil.
- Cada "objeto" del knapsack es una plantilla de ataque con sus métricas.
- El "fitness" es la capacidad del árbol de ordenar plantillas por efectividad.

Sin GPU. 100% CPU. Requiere: pip install deap numpy

Uso interno (desde generador_ataques.py):
    from motores.gp_optimizer import seleccionar_plantilla_con_gp
    vector = seleccionar_plantilla_con_gp(perfil, categoria)

Activación:
    Establecer USAR_GP_OPTIMIZER = True en configuracion.py
"""

import operator
import random
import logging
from typing import Any, Optional

from utilidades.logger import obtener_logger

log = obtener_logger(__name__)

# ── Importación condicional de DEAP ──────────────────────────────────────────
try:
    import numpy as np
    from deap import base, creator, tools, gp, algorithms
    _DEAP_DISPONIBLE = True
except ImportError:
    _DEAP_DISPONIBLE = False
    log.debug("[GP] DEAP o NumPy no instalados. GP Optimizer desactivado.")


# ── Representación interna de plantillas como "objetos" del GP ───────────────

class PlantillaItem:
    """
    Representa una plantilla de phishing como un objeto evaluable por el GP.

    Atributos:
        id_plantilla (str): Identificador único de la plantilla.
        score_historico (float): Tasa de efectividad acumulada (0.0 - 1.0).
        complejidad (float): Número de variables en la plantilla (normalizado).
        ratio (float): score_historico / complejidad — ganancia por unidad de complejidad.
        asunto (str): Asunto de la plantilla.
        cuerpo (str): Cuerpo de la plantilla.
        tipo (str): Tipo de vector (ej. "urgencia_financiera").
    """

    def __init__(
        self,
        id_plantilla: str,
        score_historico: float,
        complejidad: float,
        asunto: str,
        cuerpo: str,
        tipo: str,
    ):
        self.id = id_plantilla
        self.score_historico = max(score_historico, 1e-6)
        self.complejidad = max(complejidad, 1e-6)
        self.ratio = self.score_historico / self.complejidad
        self.asunto = asunto
        self.cuerpo = cuerpo
        self.tipo = tipo


class SesionSeleccion:
    """
    Análogo a KnapsackState: acumula selecciones de plantillas durante la evaluación.

    El "peso" es la complejidad total acumulada.
    La "ganancia" es el score_historico acumulado de las plantillas seleccionadas.
    """

    def __init__(self, capacidad: float = 10.0):
        self.capacidad = capacidad
        self.complejidad_actual = 0.0
        self.score_actual = 0.0
        self.plantilla_elegida: Optional[PlantillaItem] = None

    def seleccionar(self, plantilla: PlantillaItem) -> None:
        """Selecciona la plantilla si hay capacidad disponible."""
        if self.complejidad_actual + plantilla.complejidad <= self.capacidad:
            self.complejidad_actual += plantilla.complejidad
            self.score_actual += plantilla.score_historico
            if self.plantilla_elegida is None:
                self.plantilla_elegida = plantilla


# ── Construcción del conjunto primitivo GP ───────────────────────────────────

def _div_segura(izq: float, der: float) -> float:
    """División protegida contra cero."""
    return izq / der if abs(der) > 1e-6 else 1.0


def _construir_pset():
    """
    Construye el conjunto de primitivos para el árbol GP.

    Argumentos del árbol (análogo al problema knapsack):
        S  = score_historico de la plantilla
        C  = complejidad de la plantilla
        SC = ratio score/complejidad
    """
    pset = gp.PrimitiveSet("MAIN", 3)
    pset.addPrimitive(operator.add, 2)
    pset.addPrimitive(operator.sub, 2)
    pset.addPrimitive(operator.mul, 2)
    pset.addPrimitive(_div_segura, 2)
    pset.renameArguments(ARG0="S", ARG1="C", ARG2="SC")
    return pset


def _inicializar_deap(pset):
    """Inicializa el toolbox de DEAP con las estructuras y operadores GP."""
    from configuracion import GP_MAX_TREE_HEIGHT

    # Evitar redefinición si ya fue creado (DEAP usa singletons en creator)
    if not hasattr(creator, "FitnessMaxGP"):
        creator.create("FitnessMaxGP", base.Fitness, weights=(1.0,))
    if not hasattr(creator, "IndividualGP"):
        creator.create("IndividualGP", gp.PrimitiveTree, fitness=creator.FitnessMaxGP)

    toolbox = base.Toolbox()
    toolbox.register("expr", gp.genHalfAndHalf, pset=pset, min_=1, max_=3)
    toolbox.register("individual", tools.initIterate, creator.IndividualGP, toolbox.expr)
    toolbox.register("population", tools.initRepeat, list, toolbox.individual)
    toolbox.register("compile", gp.compile, pset=pset)
    toolbox.register("select", tools.selTournament, tournsize=3)
    toolbox.register("mate", gp.cxOnePoint)
    toolbox.register("mutate", gp.mutUniform, expr=toolbox.expr, pset=pset)

    # Control de bloat: descartar árboles que excedan altura máxima
    toolbox.decorate(
        "mate",
        gp.staticLimit(key=operator.attrgetter("height"), max_value=GP_MAX_TREE_HEIGHT),
    )
    toolbox.decorate(
        "mutate",
        gp.staticLimit(key=operator.attrgetter("height"), max_value=GP_MAX_TREE_HEIGHT),
    )

    return toolbox


# ── Función de fitness ────────────────────────────────────────────────────────

def _evaluar_individuo(individuo, plantillas, toolbox):
    """
    Fitness = score acumulado de plantillas seleccionadas por el árbol GP,
    penalizado por el tamaño del árbol (control de bloat).
    """
    try:
        funcion_score = toolbox.compile(expr=individuo)
    except Exception:
        return (-float("inf"),)

    sesion = SesionSeleccion(capacidad=float(len(plantillas)))
    plantillas_puntuadas = []

    for plantilla in plantillas:
        try:
            puntuacion = funcion_score(
                plantilla.score_historico,
                plantilla.complejidad,
                plantilla.ratio,
            )
            plantillas_puntuadas.append((puntuacion, plantilla))
        except Exception:
            continue

    plantillas_puntuadas.sort(key=lambda x: x[0], reverse=True)

    for _, plantilla in plantillas_puntuadas:
        sesion.seleccionar(plantilla)

    penalizacion = len(individuo) * 0.01
    return (sesion.score_actual - penalizacion,)


# ── Bucle evolutivo ──────────────────────────────────────────────────────────

def _evolucionar_fase(plantillas, toolbox, elite_anterior=None):
    """
    Ejecuta una fase evolutiva sobre las plantillas disponibles.

    Implementa seeding: reutiliza la élite de la fase anterior y completa
    con nuevos individuos para mantener diversidad.

    Returns:
        Lista con los mejores individuos (élite) de esta fase.
    """
    from configuracion import GP_TAM_POBLACION, GP_GEN_POR_FASE, GP_TAM_ELITE
    import numpy as np_local

    # Seeding: reutilizar élite anterior + nuevos individuos
    if elite_anterior:
        poblacion = [toolbox.clone(ind) for ind in elite_anterior]
        while len(poblacion) < GP_TAM_POBLACION:
            poblacion.append(toolbox.individual())
    else:
        poblacion = toolbox.population(n=GP_TAM_POBLACION)

    # Registrar evaluador con las plantillas de esta fase
    toolbox.register(
        "evaluate",
        _evaluar_individuo,
        plantillas=plantillas,
        toolbox=toolbox,
    )

    # Invalidar fitness heredado: nuevo entorno requiere nueva evaluación
    for ind in poblacion:
        del ind.fitness.values

    estadisticas = tools.Statistics(
        lambda ind: ind.fitness.values[0] if ind.fitness.valid else -float("inf")
    )
    estadisticas.register("Promedio", np_local.mean)
    estadisticas.register("Max", np_local.max)
    salon_fama = tools.HallOfFame(GP_TAM_ELITE)

    algorithms.eaSimple(
        poblacion,
        toolbox,
        cxpb=0.7,
        mutpb=0.2,
        ngen=GP_GEN_POR_FASE,
        stats=estadisticas,
        halloffame=salon_fama,
        verbose=False,  # Silencioso en producción
    )

    return list(salon_fama)


# ── Adaptador: plantillas Recon365 → PlantillaItem ───────────────────────────

def _convertir_plantillas(plantillas_raw, tipo_categoria):
    """
    Convierte las plantillas estáticas de Recon365 al formato PlantillaItem.

    El score_historico inicial es uniforme (0.5) — sin historial previo.
    La complejidad se estima por el número de variables de formato en la plantilla.
    """
    items = []
    for i, plantilla in enumerate(plantillas_raw):
        cuerpo = plantilla.get("cuerpo", "")
        asunto = plantilla.get("asunto", "")
        tipo = plantilla.get("tipo", f"tipo_{i}")

        # Estimar complejidad por número de placeholders en la plantilla
        num_vars = asunto.count("{") + cuerpo.count("{")
        complejidad = max(float(num_vars), 1.0) / 10.0  # Normalizado

        items.append(PlantillaItem(
            id_plantilla=f"{tipo_categoria}_{tipo}_{i}",
            score_historico=0.5,  # Score uniforme inicial (sin historial)
            complejidad=complejidad,
            asunto=asunto,
            cuerpo=cuerpo,
            tipo=tipo,
        ))
    return items


# ── Función pública principal ─────────────────────────────────────────────────

# Estado interno del motor GP (persiste entre llamadas en la misma sesión)
_pool_elite = None
_toolbox_cache = None
_pset_cache = None


def seleccionar_plantilla_con_gp(perfil, categoria):
    """
    Selecciona la plantilla óptima para el perfil dado usando el motor GP.

    Si DEAP no está instalado, retorna None y el pipeline usa el fallback
    de selección aleatoria existente en generador_ataques.py.

    Args:
        perfil (dict): Perfil psicográfico del objetivo.
        categoria (str): Categoría predictiva ("JERARQUIA", "ESTILO_VIDA", "TECNOLOGICO").

    Returns:
        dict con {tipo_vector, asunto, cuerpo} seleccionado por GP, o None.
    """
    global _pool_elite, _toolbox_cache, _pset_cache

    if not _DEAP_DISPONIBLE:
        log.debug("[GP] DEAP no disponible. Retornando None.")
        return None

    # Importar plantillas según la categoría
    try:
        from modulos.generador_ataques import (
            PLANTILLAS_JERARQUIA,
            PLANTILLAS_ESTILO_VIDA,
            PLANTILLAS_TECNOLOGICO,
        )
    except ImportError as e:
        log.warning(f"[GP] No se pudieron importar plantillas: {e}")
        return None

    mapa_plantillas = {
        "JERARQUIA": PLANTILLAS_JERARQUIA,
        "ESTILO_VIDA": PLANTILLAS_ESTILO_VIDA,
        "TECNOLOGICO": PLANTILLAS_TECNOLOGICO,
    }
    plantillas_raw = mapa_plantillas.get(categoria, PLANTILLAS_ESTILO_VIDA)
    plantillas = _convertir_plantillas(plantillas_raw, categoria)

    if not plantillas:
        log.warning("[GP] No hay plantillas para esta categoría.")
        return None

    # Inicializar toolbox (cachear para no recrear en cada llamada)
    if _toolbox_cache is None or _pset_cache is None:
        _pset_cache = _construir_pset()
        _toolbox_cache = _inicializar_deap(_pset_cache)
        log.info("[GP] Motor GP inicializado.")

    # Ejecutar una fase evolutiva
    try:
        log.info(f"[GP] Ejecutando fase evolutiva para categoría: {categoria}")
        _pool_elite = _evolucionar_fase(plantillas, _toolbox_cache, _pool_elite)
    except Exception as e:
        log.warning(f"[GP] Error en fase evolutiva: {e}")
        return None

    if not _pool_elite:
        return None

    # Usar el mejor individuo para seleccionar la plantilla óptima
    mejor_individuo = _pool_elite[0]
    try:
        funcion_score = _toolbox_cache.compile(expr=mejor_individuo)
    except Exception as e:
        log.warning(f"[GP] Error al compilar mejor individuo: {e}")
        return None

    # Puntuar todas las plantillas con el mejor árbol GP
    puntuadas = []
    for plantilla in plantillas:
        try:
            puntuacion = funcion_score(
                plantilla.score_historico,
                plantilla.complejidad,
                plantilla.ratio,
            )
            puntuadas.append((puntuacion, plantilla))
        except Exception:
            continue

    if not puntuadas:
        return None

    puntuadas.sort(key=lambda x: x[0], reverse=True)
    mejor_plantilla = puntuadas[0][1]

    log.info(
        f"[GP] Plantilla seleccionada: {mejor_plantilla.tipo} "
        f"(score: {puntuadas[0][0]:.4f})"
    )

    return {
        "tipo_vector": f"{categoria} — gp_{mejor_plantilla.tipo}",
        "asunto": mejor_plantilla.asunto,
        "cuerpo": mejor_plantilla.cuerpo,
    }
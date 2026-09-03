# Recon365 — Rama `light`

> **Para máquinas sin GPU / sin LM Studio instalado.**
> Genera vectores de Spear Phishing usando plantillas estáticas predefinidas.
> Sin dependencias pesadas. Sin 8 GB de VRAM. Sin IA local.

---

## ¿Qué es el modo light?

La rama `light` activa el flag `MODO_LIGHT = True` en `configuracion.py`.
Esto hace que el sistema omita cualquier intento de llamada a LM Studio / Ollama
y use directamente el pipeline de plantillas estáticas que siempre existió en el proyecto.

El modo light es **100% funcional**: genera correos de phishing personalizados
usando las 9 plantillas predefinidas (JERARQUIA × 3, ESTILO_VIDA × 3, TECNOLOGICO × 3).

---

## Comparativa `main` vs `light`

| Característica | `main` (GPU) | `light` (CPU) |
|---|---|---|
| Motor de generación | J4N14 + Dolphin (LLM) | Plantillas estáticas |
| GPU necesaria | 8 GB VRAM mínimo | **No** |
| LM Studio / Ollama | Requerido | **No** |
| Dependencias | `requirements.txt` completo | `requirements_light.txt` |
| Calidad de correos | Dinámica y única | Personalizada con variables |
| `enviar_prueba.py` | ✅ | ✅ |
| GP Optimizer (DEAP) | Opcional | **Incluido desactivado** |

---

## Instalación rápida

```bash
# 1. Cambiar a la rama light
git checkout light

# 2. Instalar solo las dependencias necesarias
pip install -r requirements_light.txt

# 3. Ejecutar la prueba de envío
python ejecutables/enviar_prueba.py
```

---

## GP Optimizer (Programación Genética)

La rama `light` incluye el módulo `motores/gp_optimizer.py` — un motor evolutivo
que aprende a seleccionar la plantilla óptima para cada perfil objetivo.

**Funciona 100% en CPU. Sin GPU. Sin IA local.**

### Activación

```bash
# 1. Instalar DEAP y NumPy
pip install deap numpy

# 2. En configuracion.py, cambiar:
USAR_GP_OPTIMIZER = True
```

### ¿Cómo funciona?

El GP evoluciona árboles de expresión que aprenden a puntuar y ordenar
las plantillas disponibles (análogo al problema del Knapsack):

```
Knapsack GP               → Recon365 light
──────────────────────────────────────────
Item (profit/weight)      → Plantilla (score/complejidad)
KnapsackState             → SesionSeleccion
Fase / entorno            → Categoría de perfil (JERARQUIA, ESTILO_VIDA, TECNOLOGICO)
Fitness (ganancia)        → Score acumulado de plantillas seleccionadas
```

El motor persiste la élite evolutiva entre llamadas, mejorando con el uso.

---

## Estructura de archivos relevantes (rama `light`)

```
recon365/
├── configuracion.py          ← MODO_LIGHT=True, USAR_GP_OPTIMIZER=False
├── requirements_light.txt    ← Dependencias mínimas
├── ejecutables/
│   └── enviar_prueba.py      ← Script de prueba (funciona sin GPU)
├── modulos/
│   └── generador_ataques.py  ← Plantillas estáticas + hook GP
└── motores/
    └── gp_optimizer.py       ← Motor GP (desactivado por defecto)
```

---

## Advertencia legal

Este software es exclusivamente para **auditorías de seguridad autorizadas**,
red teaming y pentesting con autorización explícita del propietario del sistema.
El uso no autorizado es ilegal. Ver `LICENSE` para más detalles.
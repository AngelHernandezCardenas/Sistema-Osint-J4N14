<div align="center">

# 🗺️ M.A.P.A. — Módulo de Análisis de Perfiles Abiertos

### Sistema OSINT J4N14

**Módulo de reconocimiento OSINT/SOCMINT y perfilamiento psicológico automatizado.**
**Impulsado por el motor de inferencia J4N14 para generar vectores de ingeniería social mediante IA local.**

---

*M.A.P.A. funciona gracias al algoritmo clasificador J4N14 que analiza la huella digital.*

</div>

---

## 📋 Descripción

**Recon365** es un framework de reconocimiento OSINT diseñado para auditorías de seguridad ofensiva y ejercicios de Red Teaming. El sistema automatiza:

1. **Recolección** de datos públicos de objetivos corporativos (SOCMINT)
2. **Perfilamiento psicográfico** mediante IA local (Motor J4N14)
3. **Generación de vectores** de Spear Phishing personalizados

Todo el procesamiento de IA es **100% offline**, garantizando la privacidad de los datos durante la auditoría.

## ⚠️ Disclaimer Legal

> **ADVERTENCIA:** Esta herramienta está diseñada **exclusivamente** para uso en auditorías de seguridad autorizadas, ejercicios de Red Teaming y pruebas de penetración con **autorización previa por escrito** del cliente.
>
> El uso no autorizado de esta herramienta para acceder, recopilar o manipular información de terceros sin su consentimiento es **ilegal** y viola leyes de privacidad y ciberseguridad en la mayoría de jurisdicciones.
>
> Los autores no se hacen responsables del mal uso de esta herramienta.

## 🏗️ Arquitectura

```
recon365/
├── data/
│   ├── inputs/               # Listas de objetivos (.txt, .csv)
│   └── outputs/              # Reportes JSON generados
├── modulos/
│   ├── __init__.py
│   ├── recolector.py         # Scraping con Playwright (headless)
│   ├── perfilador_ia.py      # Motor J4N14 — LLM local vía Ollama
│   └── generador_ataques.py  # Generación de vectores Spear Phishing
├── utilidades/
│   ├── __init__.py
│   ├── logger.py             # Logging profesional con Rich
│   └── gestor_archivos.py    # I/O de archivos (CSV, TXT, JSON)
├── configuracion.py          # Variables globales
├── main.py                   # Orquestador principal
└── requirements.txt          # Dependencias
```

## 🧠 Motor J4N14

El **Motor J4N14** es el cerebro del sistema. Utiliza un modelo de lenguaje (LLM) ejecutado localmente a través de [Ollama](https://ollama.ai) para analizar la información recolectada y generar perfiles psicográficos.

### Modelos Predictivos

| Categoría | Trigger | Vector Generado |
|-----------|---------|-----------------|
| 🏢 **JERARQUÍA** | CEO, Director, Gerente | Correo urgente con autoridad |
| 🌴 **ESTILO_VIDA** | Viajes, deportes, hobbies | Premio falso, promoción |
| 💻 **TECNOLÓGICO** | Programación, certs, hardware | Falsa actualización de seguridad |

### Optimización GPU

- Modelo: `llama3.1:8b` (optimizado para 8 GB VRAM)
- 35 capas en GPU por defecto
- Procesamiento 100% local — sin envío de datos a la nube

## 🚀 Instalación

### Prerrequisitos

- Python 3.11+
- [Ollama](https://ollama.ai) instalado con el modelo `llama3.1:8b`
- GPU NVIDIA con 8 GB VRAM (recomendado)

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/AngelHernandezCardenas/Sistema-Osint-J4N14.git
cd Sistema-Osint-J4N14/recon365

# 2. Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# 3. Instalar dependencias
pip install -r requirements.txt
playwright install chromium

# 4. Descargar el modelo de IA
ollama pull llama3.1:8b

# 5. Ejecutar
python main.py
```

## 📖 Uso

### Preparar objetivos

Crea un archivo en `data/inputs/objetivos.txt` con una URL por línea:

```
https://ejemplo.com/perfil/persona1
https://ejemplo.com/perfil/persona2
```

O un archivo `.csv` con columnas `nombre,url,empresa`:

```csv
nombre,url,empresa
Juan Pérez,https://ejemplo.com/perfil/juanperez,Empresa X
María López,https://ejemplo.com/perfil/marialopez,Empresa Y
```

### Ejecutar análisis

```bash
python main.py
```

Los reportes se generarán en `data/outputs/` en formato JSON.

## 📄 Licencia

Este proyecto se distribuye bajo una licencia de uso ético. Ver [LICENSE](LICENSE) para más detalles.

---

<div align="center">

**Desarrollado para auditorías de seguridad autorizadas.**

*Recon365 × J4N14 Engine*

</div>
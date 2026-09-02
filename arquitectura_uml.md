# Arquitectura de Recon365

A continuación se presenta el diagrama UML de la arquitectura del proyecto utilizando **Mermaid**. Este diagrama muestra la separación entre el pipeline clásico de Phishing impulsado por IA (Motor J4N14) y el nuevo pipeline de OSINT/ASM, además de su interacción con las interfaces y las utilidades compartidas.

```mermaid
graph TD
    %% Estilos
    classDef interface fill:#e1f5fe,stroke:#039be5,stroke-width:2px;
    classDef orchestrator fill:#fff3e0,stroke:#f57c00,stroke-width:2px;
    classDef phishing fill:#fce4ec,stroke:#d81b60,stroke-width:2px;
    classDef osint fill:#e8f5e9,stroke:#43a047,stroke-width:2px;
    classDef core fill:#eceff1,stroke:#607d8b,stroke-width:2px;
    classDef external fill:#f3e5f5,stroke:#8e24aa,stroke-width:2px,stroke-dasharray: 5 5;

    %% Nodos Principales
    subgraph Interfaces [Interfaces de Usuario]
        CLI[ejecutables/main.py]:::interface
        BAT[ejecutar.bat]:::interface
        API[ejecutables/servidor.py<br/>FastAPI / Web UI]:::interface
    end

    Orchestrator((Orquestador Central)):::orchestrator

    %% Conexiones Interface -> Orquestador
    BAT -->|Llama| CLI
    CLI -->|--archivo u --org| Orchestrator
    API -->|Consultas Web| Orchestrator

    %% Pipeline de Phishing
    subgraph Pipeline_Phishing [Módulos Spear Phishing & Perfilamiento]
        REC[modulos/recolector.py]:::phishing
        PERF[modulos/perfilador_ia.py<br/>Motor J4N14]:::phishing
        GEN[modulos/generador_ataques.py]:::phishing
    end

    %% Pipeline OSINT/ASM
    subgraph Pipeline_OSINT [Motores OSINT & Threat Intel]
        ENG_OSINT[motores/osint_engine.py]:::osint
        ENG_THREAT[motores/threat_intel_engine.py]:::osint
        ENG_RISK[motores/risk_engine.py]:::osint
        ENG_CORR[motores/correlation_engine.py]:::osint
    end

    %% Utilidades Core
    subgraph Core [Núcleo y Utilidades]
        CONF[configuracion.py]:::core
        ARCH[utilidades/gestor_archivos.py]:::core
        DB[utilidades/base_datos.py]:::core
        LOG[utilidades/logger.py]:::core
    end

    %% Servicios Externos (IA)
    OLLAMA[Ollama Local<br/>Puerto 11434]:::external
    LMSTUDIO[LM Studio Local<br/>Puerto 1234]:::external

    %% Flujo Phishing
    Orchestrator -->|--archivo| REC
    REC -->|Texto crudo| PERF
    PERF -->|Perfil JSON| GEN
    PERF -.->|Consultas LLM| OLLAMA
    GEN -.->|Redacción (Fallback o IA)| LMSTUDIO

    %% Flujo OSINT
    Orchestrator -->|--org| ENG_OSINT
    ENG_OSINT -->|Datos Base| ENG_THREAT
    ENG_THREAT -->|Vulnerabilidades| ENG_RISK
    ENG_OSINT -.-> ENG_CORR

    %% Flujo a Core
    Pipeline_Phishing -->|Guarda Reportes| ARCH
    Pipeline_OSINT -->|Guarda Estado| DB
    Orchestrator -.-> CONF
    Pipeline_Phishing -.-> CONF
    Pipeline_OSINT -.-> CONF
```

## Resumen de los Componentes

- **Interfaces**: Puntos de entrada para el usuario (Terminal CLI, Scripts `.bat` y la API Web).
- **Módulos de Phishing (Motor J4N14)**: Recolecta datos (generalmente usando *Playwright*), genera un perfil psicológico conectándose a *Ollama*, y diseña un ataque utilizando *LM Studio* o plantillas de emergencia (fallback).
- **Motores OSINT/ASM**: La nueva arquitectura orientada a la enumeración de subdominios, inteligencia de amenazas (CVEs), y puntuación de riesgo organizacional.
- **Núcleo (Core)**: Proveedor de configuraciones estáticas (`configuracion.py`), conexión a SQLite (`base_datos.py`), manipulación de archivos (`gestor_archivos.py`) y trazabilidad de logs.

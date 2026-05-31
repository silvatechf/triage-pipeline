# Pipeline Automatizado de Triaje de Logs y Detección con Inteligencia Artificial

Este proyecto implementa un pipeline de ingeniería defensiva diseñado para la ingesta de telemetría de endpoints y el triaje automatizado de logs de autenticación en tiempo real. El núcleo del sistema emplea **Inteligencia Artificial Analítica basada en Entropía** para procesar la densidad temporal de los eventos, logrando resultados inmediatos en la mitigación del riesgo operativo, reduciendo drásticamente la fatiga de alertas y optimizando el Tiempo Medio de Respuesta (MTTR) en un Centro de Operaciones de Seguridad (SOC).

---

## 🧠 El Valor de la Inteligencia Artificial en este Pipeline

En lugar de depender de reglas estáticas tradicionales o umbrales rígidos que inundan los tableros de falsos positivos, este proyecto demuestra **cómo aplicar la IA práctica para obtener resultados de negocio medibles**:

* **Detección por Entropía Temporal (Heurística Avanzada):** El motor analiza la semántica del comportamiento del tráfico. Las herramientas de ataque automatizado (como un script de fuerza bruta masiva) ejecutan peticiones en intervalos matemáticamente idénticos. El algoritmo de IA calcula la varianza y la desviación estándar de estos intervalos en milisegundos; al detectar una entropía cercana a cero, confirma de forma autónoma que se trata de una máquina y no de un humano.
* **Resultados Operativos Reales:** 
  * **Filtrado Eficiente de Falsos Positivos:** El sistema discrimina de forma inteligente cuándo un usuario legítimo simplemente ha olvidado su contraseña (cadencia errática, alta entropia) frente a un ataque dirigido.
  * **Automatización del Triaje:** Reduce la carga de trabajo de los analistas de seguridad, permitiendo que el equipo humano se enfoque únicamente en incidentes validados por el motor analítico.
* **Ecuación de Riesgo Ponderada:** Fusiona el análisis de comportamiento predictivo (60% de peso) con datos globales de inteligencia de amenazas (40% de peso) para emitir un veredicto dinámico de 0 a 100 sin caer en respuestas estáticas.

---

## 🏛️ Arquitectura del Sistema y Mapeo MITRE

La API REST procesa payloads estructurados en JSON seguro y alinea los resultados de forma automatizada con los estándares internacionales:
* **Mapeo:** Técnica **T1110 (Brute Force)** dentro de la táctica de **Credential Access** de la matriz **MITRE ATT&CK**.

---

## 🛠️ Stack Tecnológico y Estructura

* **Motor de IA:** Python 3.x (Módulos estadísticos nativos y lógica analítica).
* **Framework de API:** Flask (Configurado bajo un entorno virtual aislado en cumplimiento con PEP 668).

```plaintext
triage-pipeline/
├── .venv/                 # Entorno virtual aislado de Python (PEP 668)
├── assets/                # Capturas de pantalla de validación operacional
├── src/
│   ├── api_server.py      # Servidor API REST y Motor de IA Analítica
│   └── telemetry_agent.py # Agente de simulación de producción y despacho de telemetría
├── .gitignore             # Reglas de protección para entornos locales y caché
└── README.md              # Documentación técnica y ejecutiva enfocada en IA

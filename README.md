# Sistema local de CTI con RAG

Este repositorio reúne una versión compacta del prototipo del TFM y los datos consolidados de su evaluación. El sistema utiliza Gemma desde LM Studio, Haystack para conectar los componentes, Chroma para recuperar documentación ATT&CK y fragmentos de informes CTI y SQLite para comprobar identificadores CVE

Permite ejecutar consultas individuales y recalcular las métricas principales publicadas. No incluye el ejecutor de las 1.650 solicitudes ni todos los programas de preparación del Dataset Maestro y los índices. Los resultados incluidos proceden de la ejecución experimental descrita en la memoria, no de nuevas ejecuciones de los ejemplos de este README

## Estructura

- `src/tfm_cti`: código principal
- `scripts/run.py`: ejecución de consultas DIRECT, B0 y R1
- `scripts/evaluate.py`: recálculo de las métricas principales
- `tools/collect_reports.py`: recolector de informes públicos de Mandiant y Unit 42
- `config/runtime.yaml`: configuración utilizada por el prototipo
- `data/reports`: cincuenta informes identificados como P01-P10, G01-G20 y U01-U20
- `data/Dataset_Maestro.xlsx`: referencias y particiones de las cuatro tareas
- `data/manifest.json`: recuentos, versiones, configuración de los índices y hashes
- `data/chroma`: índice vectorial persistente
- `data/cve_exact.sqlite`: instantánea local de identificadores CVE
- `results/Resultados_Evaluacion.xlsx`: datos consolidados de la evaluación
- `results/metricas_finales.json`: métricas finales verificadas

El Dataset Maestro contiene seis hojas: `informes`, `ioc`, `cve`, `attack`, `cti_qa` y `resumen_cierre`. Todas contienen los datos finales; las hojas de candidatos previas a la revisión no forman parte de esta entrega

El hash `chroma_tree` del manifiesto corresponde a la copia entregada. `chroma_tree_evaluation` conserva el hash registrado durante la evaluación. Chroma actualiza contadores internos al abrir la base, por lo que el hash del archivo puede cambiar sin que cambien los vectores, textos o metadatos. Estos contenidos se comprobaron contra la copia original y coinciden

## Instalación

La versión utilizada fue Python 3.14.5. Desde la raíz del proyecto:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Las versiones de las bibliotecas Python están fijadas en `requirements.txt`. La configuración del modelo, la recuperación y la generación está en `config/runtime.yaml`.

## Modelos y herramientas externas

- LM Studio con el runtime `llama.cpp-win-x86_64-nvidia-cuda12-avx2@2.27.1`
- Gemma 4 12B QAT en el archivo `gemma-4-12B-it-QAT-Q4_0.gguf`
- SHA-256 del archivo GGUF: `929fde4e951e520b74806268e8e8ffaa20a20fab955f3606d5ce7b2c35798501`
- Qwen3 Embedding 0.6B, revisión `97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3`

Los modelos no se incluyen en el repositorio. Qwen3 Embedding se descarga la primera vez que se realiza una consulta semántica. También se puede utilizar una copia local:

```powershell
$env:TFM_EMBEDDING_MODEL='C:\ruta\al\modelo'
```

## LM Studio

Antes de ejecutar una consulta:

1. Cargar `gemma-4-12B-it-QAT-Q4_0.gguf`
2. Asignar al modelo el identificador `tfm-gemma-4-12b-qat-q4_0`
3. Iniciar el servidor local en `http://127.0.0.1:1234/v1`
4. Utilizar una ventana de contexto de 8.192 tokens y mantener `thinking` desactivado

## Ejecución

Comprobación de un CVE mediante consulta exacta:

```powershell
python scripts/run.py --task T2 --variant R1 --case-id EJEMPLO-CVE --question "¿Aparece CVE-2024-3400 en la instantánea local?"
```

SQLite contiene 374.332 identificadores con su estado y procedencia. Solo los 100 CVE reales seleccionados para el Dataset Maestro tienen una descripción incorporada. Si otro registro no tiene descripción, se indica esa ausencia sin completar información que no está almacenada. Una consulta exacta comprueba la presencia del identificador en esta instantánea, no su situación actual en Internet

Mapeo ATT&CK mediante recuperación semántica:

```powershell
python scripts/run.py --task T3 --variant R1 --case-id EJEMPLO-ATTACK --question "Un adversario encadena varios servidores proxy para ocultar el origen del tráfico. ¿Qué subtécnica ATT&CK corresponde?"
```

Extracción directa de IoC desde un fragmento breve de un informe. Copia primero unos párrafos de `data/reports/G01.txt` en un archivo UTF-8 llamado `fragmento_cti.txt`, en la raíz del proyecto:

```powershell
python scripts/run.py --task T1 --variant DIRECT --case-id EJEMPLO-IOC --question "Extrae los IoC explícitos" --evidence-file fragmento_cti.txt
```

`run.py` lee completo el archivo indicado en `--evidence-file`: no lo divide en ventanas ni comprueba previamente su longitud en tokens. La entrada, las instrucciones y la salida deben caber en los 8.192 tokens de contexto, reservando hasta 2.048 para la respuesta. No debe utilizarse este ejemplo para enviar un informe largo completo

En la evaluación original, T1 procesó los 40 informes de evaluación mediante 70 ventanas, con tres repeticiones, y agrupó las salidas por informe y repetición. Esa división y agrupación no forman parte de este programa de consultas individuales

La respuesta estructurada aparece en la terminal y el registro completo se guarda en `runs`

## Evaluación

`Resultados_Evaluacion.xlsx` agrupa en seis hojas el resumen, las contribuciones de T1, las ejecuciones de T2-T4 y las latencias. Los datos consolidados permiten recalcular las métricas principales sin publicar los 1.650 archivos individuales

```powershell
python scripts/evaluate.py
```

Este comando no llama a Gemma ni repite el experimento. Calcula precisión, recall y F1 micro de T1; exactitud y abstención de T2 y T3; medidas de recuperación; medias factuales y fundamentación automática de T4; y medianas y percentiles de latencia. Parte de los recuentos y las puntuaciones ya registrados: no vuelve a evaluar las respuestas originales ni calcula los intervalos bootstrap, las métricas macro o la estabilidad entre repeticiones

`metricas_finales.json` conserva el conjunto más amplio de resultados del experimento original. La salida de `evaluate.py` es un resumen de sus métricas principales y no una copia completa de ese archivo. Si se quiere guardar el recálculo en JSON:

```powershell
python scripts/evaluate.py --output results/metricas_recalculadas.json
```

## Recolector

El recolector descarga fuentes públicas, comprueba `robots.txt` y guarda el texto extraído junto con un manifiesto. Registra la URL, el estado HTTP, el tipo de contenido, la fecha, el extractor y las huellas SHA-256.

```powershell
python tools/collect_reports.py mandiant --limit 20
python tools/collect_reports.py unit42 --limit 20
```

Los informes nuevos no se añaden automáticamente al Dataset Maestro ni al índice. Primero hay que revisarlos. El repositorio entrega el Dataset Maestro, Chroma y SQLite ya preparados, pero no incorpora el proceso completo para reconstruirlos desde las fuentes originales

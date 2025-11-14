#!/bin/bash

# Ruta al script Python
SCRIPT="/home/luis/Documentos/UMA/TFG/IoC_extractor_LLM/main.py"

# Directorio base de salida
BASE_OUTPUT="output/memoria"

# Número máximo de exploits
MAX_EXPLOIT=10

# Archivo de log para errores
LOGFILE="run_models.log"

# Modelos a probar
MODELS=(
    "gpt-5"
    "gpt-5-mini"
    "gpt-4"
    "deepseek-r1:7b"
)

# Limpiar log anterior
echo "=== Ejecutado el $(date) ===" > "$LOGFILE"

echo "[INFO] Iniciando ejecuciones..."

for MODEL in "${MODELS[@]}"; do
    OUTPUT_DIR="${BASE_OUTPUT}/${MODEL}"

    echo "[INFO] Ejecutando modelo: $MODEL"
    echo "[INFO] Output en: $OUTPUT_DIR"

    # Ejecutar el comando y capturar errores
    python3 "$SCRIPT" \
        --output-dir "$OUTPUT_DIR" \
        --model "$MODEL" \
        --max-exploit "$MAX_EXPLOIT" 10>> "$LOGFILE"

    # Comprobar código de salida
    if [ $? -ne 0 ]; then
        echo "[ERROR] Falló el modelo ${MODEL}. Consultar $LOGFILE"
        echo "[ERROR] Modelo ${MODEL} falló a las $(date)" >> "$LOGFILE"
    else
        echo "[OK] Modelo ${MODEL} completado correctamente."
    fi

    echo "---------------------------------------"
done

echo "[INFO] Ejecuciones finalizadas."

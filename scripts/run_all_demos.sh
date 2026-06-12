#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PY="$ROOT_DIR/venv/bin/python"

if [[ -f "$ROOT_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT_DIR/.env"
  set +a
fi

export PYTHONPATH="$ROOT_DIR/src"
export PYTHONUNBUFFERED=1

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_DIR="$ROOT_DIR/artifacts/logs/run_all/$TIMESTAMP"
mkdir -p "$LOG_DIR"

LOCAL_ITERS="${LOCAL_ITERS:-20}"
HYBRID_ITERS="${HYBRID_ITERS:-30}"
COMPARISON_ITERS="${COMPARISON_ITERS:-50}"
RUN_QR="${RUN_QR:-1}"
XMPP_HOST="${XMPP_HOST:-127.0.0.1}"
XMPP_PORT="${XMPP_PORT:-5222}"

TIMEOUT_DEMO1="${TIMEOUT_DEMO1:-420}"
TIMEOUT_DEMO2A="${TIMEOUT_DEMO2A:-240}"
TIMEOUT_DEMO2B="${TIMEOUT_DEMO2B:-480}"
TIMEOUT_DEMO2C="${TIMEOUT_DEMO2C:-480}"
TIMEOUT_DEMO3="${TIMEOUT_DEMO3:-180}"
TIMEOUT_COMPARISON="${TIMEOUT_COMPARISON:-180}"
STARTUP_TIMEOUT_XMPP="${STARTUP_TIMEOUT_XMPP:-20}"
READY_TIMEOUT_RECEIVER="${READY_TIMEOUT_RECEIVER:-30}"

RECEIVER_PID=""
CAPTURE_PID=""

cleanup() {
  if [[ -n "${RECEIVER_PID}" ]] && kill -0 "$RECEIVER_PID" 2>/dev/null; then
    kill "$RECEIVER_PID" || true
    wait "$RECEIVER_PID" 2>/dev/null || true
  fi
  if [[ -n "${CAPTURE_PID}" ]] && kill -0 "$CAPTURE_PID" 2>/dev/null; then
    kill -SIGINT "$CAPTURE_PID" || true
    wait "$CAPTURE_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

log() {
  echo "[$(date +%H:%M:%S)] $*"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: falta comando requerido: $1" >&2
    exit 1
  }
}

check_xmpp_connectivity() {
  local host="$1"
  local port="$2"

  if ! "$VENV_PY" - <<PY
import socket
host = "$host"
port = int("$port")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
try:
    s.connect((host, port))
    print("ok")
except Exception:
    raise SystemExit(1)
finally:
    s.close()
PY
  then
    echo "ERROR: no se puede conectar a XMPP en ${host}:${port}." >&2
    echo "       Arranca el servidor XMPP o ajusta XMPP_HOST/XMPP_PORT." >&2
    exit 1
  fi
}

require_file() {
  [[ -f "$1" ]] || {
    echo "ERROR: no existe archivo requerido: $1" >&2
    exit 1
  }
}

start_capture() {
  local pcap_file="$1"
  local filter="${2:-tcp port 5222}"
  log "Iniciando captura pcap: $(basename "$pcap_file")"
  tshark -i lo -f "$filter" -w "$pcap_file" > /dev/null 2>&1 &
  CAPTURE_PID=$!
  sleep 1
  if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
    echo "WARN: tshark no arrancó, continuando sin captura pcap" >&2
    CAPTURE_PID=""
  fi
}

stop_capture() {
  if [[ -n "${CAPTURE_PID}" ]] && kill -0 "$CAPTURE_PID" 2>/dev/null; then
    log "Parando captura pcap (PID=$CAPTURE_PID)"
    kill -SIGINT "$CAPTURE_PID" || true
    wait "$CAPTURE_PID" 2>/dev/null || true
  fi
  CAPTURE_PID=""
}

run_bg_receiver() {
  local name="$1"
  local cmd="$2"
  local log_file="$3"

  log "Iniciando receptor: $name"
  bash -lc "cd '$ROOT_DIR' && source '$ROOT_DIR/venv/bin/activate' && $cmd" >"$log_file" 2>&1 &
  RECEIVER_PID=$!
  sleep 1

  if ! kill -0 "$RECEIVER_PID" 2>/dev/null; then
    echo "ERROR: el receptor '$name' no arrancó correctamente. Revisa: $log_file" >&2
    exit 1
  fi

  local elapsed=0
  while true; do
    if grep -q "listo" "$log_file" 2>/dev/null; then
      break
    fi

    if ! kill -0 "$RECEIVER_PID" 2>/dev/null; then
      echo "ERROR: el receptor '$name' terminó antes de estar listo. Revisa: $log_file" >&2
      tail -n 40 "$log_file" >&2 || true
      exit 1
    fi

    if [[ "$elapsed" -ge "$READY_TIMEOUT_RECEIVER" ]]; then
      echo "ERROR: receptor '$name' no llegó a estado listo en ${READY_TIMEOUT_RECEIVER}s. Revisa: $log_file" >&2
      tail -n 40 "$log_file" >&2 || true
      exit 1
    fi

    sleep 1
    elapsed=$((elapsed + 1))
  done
}

stop_receiver() {
  if [[ -n "${RECEIVER_PID}" ]] && kill -0 "$RECEIVER_PID" 2>/dev/null; then
    log "Parando receptor (PID=$RECEIVER_PID)"
    kill "$RECEIVER_PID" || true
    wait "$RECEIVER_PID" 2>/dev/null || true
  fi
  RECEIVER_PID=""
}

run_fg() {
  local name="$1"
  local cmd="$2"
  local log_file="$3"
  local timeout_sec="$4"

  log "Ejecutando: $name (timeout=${timeout_sec}s)"
  set +e
  timeout "$timeout_sec" bash -lc "cd '$ROOT_DIR' && source '$ROOT_DIR/venv/bin/activate' && $cmd" >"$log_file" 2>&1
  local code=$?
  set -e
  if [[ "$code" -ne 0 ]]; then
    if [[ "$code" -eq 124 ]]; then
      echo "ERROR: timeout en '$name' tras ${timeout_sec}s. Revisa log: $log_file" >&2
    else
      echo "ERROR: fallo en '$name' (code=$code). Revisa log: $log_file" >&2
    fi
    echo "--- Últimas líneas de $log_file ---" >&2
    tail -n 40 "$log_file" >&2 || true
    echo "ERROR: fallo en '$name'. Revisa log: $log_file" >&2
    exit 1
  fi
}

main() {
  require_cmd bash
  require_cmd timeout
  require_file "$VENV_PY"

  log "ROOT_DIR=$ROOT_DIR"
  log "PYTHONPATH=$PYTHONPATH"
  log "PYTHONUNBUFFERED=$PYTHONUNBUFFERED"
  log "LOG_DIR=$LOG_DIR"
  log "LOCAL_ITERS=$LOCAL_ITERS"
  log "HYBRID_ITERS=$HYBRID_ITERS"
  log "COMPARISON_ITERS=$COMPARISON_ITERS"
  log "RUN_QR=$RUN_QR"
  log "XMPP_HOST=$XMPP_HOST"
  log "XMPP_PORT=$XMPP_PORT"
  log "STARTUP_TIMEOUT_XMPP=$STARTUP_TIMEOUT_XMPP"
  log "READY_TIMEOUT_RECEIVER=$READY_TIMEOUT_RECEIVER"

  # Limpieza de huellas QR previas
  rm -f "$ROOT_DIR/artifacts/csv/trusted_qr_fingerprints.txt"

  # Limpiar CSVs en modo append (acumulan datos de esquemas distintos entre ejecuciones)
  rm -f "$ROOT_DIR/artifacts/csv/hybrid_xmpp_sender_metrics.csv"
  rm -f "$ROOT_DIR/artifacts/csv/hybrid_xmpp_receiver_metrics.csv"

  # Preflight XMPP para evitar bloqueos silenciosos
  check_xmpp_connectivity "$XMPP_HOST" "$XMPP_PORT"

  # Demo 1: firmas PQC en XMPP
  start_capture "$ROOT_DIR/artifacts/pcap/demo1_signatures_xmpp.pcapng"
  run_bg_receiver \
    "Demo1 receptor" \
    "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/demo1_signatures_xmpp/receptor_bench.py' --host '$XMPP_HOST' --port '$XMPP_PORT' --startup-timeout '$STARTUP_TIMEOUT_XMPP'" \
    "$LOG_DIR/demo1_receptor.log"

  run_fg \
    "Demo1 emisor" \
    "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/demo1_signatures_xmpp/emisor_bench.py' --host '$XMPP_HOST' --port '$XMPP_PORT' --startup-timeout '$STARTUP_TIMEOUT_XMPP'" \
    "$LOG_DIR/demo1_emisor.log" \
    "$TIMEOUT_DEMO1"

  stop_receiver
  stop_capture

  # Demo 2A: handshake híbrido local
  run_fg \
    "Demo2A local" \
    "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/demo2_hybrid_kem_signed/kem_signed_bench.py' --iterations '$LOCAL_ITERS'" \
    "$LOG_DIR/demo2a_local.log" \
    "$TIMEOUT_DEMO2A"

  # Demo 2B: handshake híbrido XMPP (cert)
  start_capture "$ROOT_DIR/artifacts/pcap/demo2b_hybrid_xmpp_cert.pcapng"
  run_bg_receiver \
    "Demo2B receptor cert" \
    "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py' --verify-mode cert --host '$XMPP_HOST' --port '$XMPP_PORT' --startup-timeout '$STARTUP_TIMEOUT_XMPP'" \
    "$LOG_DIR/demo2b_receptor_cert.log"

  run_fg \
    "Demo2B emisor cert" \
    "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py' --verify-mode cert --iterations '$HYBRID_ITERS' --host '$XMPP_HOST' --port '$XMPP_PORT' --startup-timeout '$STARTUP_TIMEOUT_XMPP'" \
    "$LOG_DIR/demo2b_emisor_cert.log" \
    "$TIMEOUT_DEMO2B"

  stop_receiver
  stop_capture

  # Demo 2C: handshake híbrido XMPP (qr)
  if [[ "$RUN_QR" == "1" ]]; then
    start_capture "$ROOT_DIR/artifacts/pcap/demo2c_hybrid_xmpp_qr.pcapng"
    run_bg_receiver \
      "Demo2C receptor qr" \
      "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py' --verify-mode qr --trusted-fingerprints-file '$ROOT_DIR/artifacts/csv/trusted_qr_fingerprints.txt' --host '$XMPP_HOST' --port '$XMPP_PORT' --startup-timeout '$STARTUP_TIMEOUT_XMPP'" \
      "$LOG_DIR/demo2c_receptor_qr.log"

    run_fg \
      "Demo2C emisor qr" \
      "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py' --verify-mode qr --qr-fingerprint-output-file '$ROOT_DIR/artifacts/csv/trusted_qr_fingerprints.txt' --iterations '$HYBRID_ITERS' --host '$XMPP_HOST' --port '$XMPP_PORT' --startup-timeout '$STARTUP_TIMEOUT_XMPP'" \
      "$LOG_DIR/demo2c_emisor_qr.log" \
      "$TIMEOUT_DEMO2C"

    stop_receiver
    stop_capture
  else
    log "RUN_QR=0, saltando Demo2C QR"
  fi

  # Demo 3: análisis y resumen
  run_fg \
    "Demo3 plot_metrics" \
    "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/metrics/plot_metrics.py'" \
    "$LOG_DIR/demo3_plot_metrics.log" \
    "$TIMEOUT_DEMO3"

  run_fg \
    "Demo3 plot_kem_signed_metrics" \
    "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/metrics/plot_kem_signed_metrics.py'" \
    "$LOG_DIR/demo3_plot_kem_signed.log" \
    "$TIMEOUT_DEMO3"

  run_fg \
    "Demo3 plot_hybrid_xmpp_metrics" \
    "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/metrics/plot_hybrid_xmpp_metrics.py'" \
    "$LOG_DIR/demo3_plot_hybrid_xmpp.log" \
    "$TIMEOUT_DEMO3"

  run_fg \
    "Demo3 summarize_experiments" \
    "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/metrics/summarize_experiments.py'" \
    "$LOG_DIR/demo3_summary.log" \
    "$TIMEOUT_DEMO3"

  run_fg \
    "Demo3 analyze_results" \
    "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/metrics/analyze_results.py'" \
    "$LOG_DIR/demo3_analyze_results.log" \
    "$TIMEOUT_DEMO3"

  run_fg \
    "Demo3 analyze_pcap" \
    "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/demo3_analysis/analyze_pcap.py'" \
    "$LOG_DIR/demo3_analyze_pcap.log" \
    "$TIMEOUT_DEMO3"

  run_fg \
    "Demo3 crypto_comparison" \
    "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/metrics/crypto_comparison_bench.py' --mode all --iterations '$COMPARISON_ITERS'" \
    "$LOG_DIR/demo3_crypto_comparison.log" \
    "$TIMEOUT_COMPARISON"

  run_fg \
    "Demo3 plot_comparison" \
    "PYTHONPATH='$PYTHONPATH' '$VENV_PY' '$ROOT_DIR/src/metrics/plot_comparison.py'" \
    "$LOG_DIR/demo3_plot_comparison.log" \
    "$TIMEOUT_DEMO3"


  log "Ejecución completa ✅"
  log "Logs: $LOG_DIR"
  log "CSV:  $ROOT_DIR/artifacts/csv"
  log "FIGS: $ROOT_DIR/artifacts/figs"
}

main "$@"

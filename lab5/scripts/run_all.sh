#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_CTR="lab5-c4-s1"
cd "$ROOT"

die() { echo "ERROR: $*" >&2; exit 1; }
hr()  { printf '%s\n' "------------------------------------------------------------"; }

command -v docker >/dev/null || die "Docker no está instalado / no está en PATH."
docker info >/dev/null 2>&1   || die "El daemon de Docker no responde. ¿Está corriendo?"
# compose v2 (plugin) vs binario antiguo.
if docker compose version >/dev/null 2>&1; then COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then COMPOSE=(docker-compose)
else die "No encuentro 'docker compose' ni 'docker-compose'."; fi

hr; echo "[run_all] (1/5) Construyendo imágenes ..."; hr

if ! "${COMPOSE[@]}" build; then
  cat >&2 <<'MSG'

ERROR: Falló el build. Causas típicas:
  * Imagen base EOL no disponible: si 'ubuntu:16.10/18.10/20.10/22.10' ya no
    resuelve en Docker Hub, fija un digest o un tag comunitario en el Dockerfile
    correspondiente (ver sección "Imágenes EOL" del README).
  * apt 404: verifica que el sed a old-releases.ubuntu.com esté ANTES de
    'apt-get update' en el Dockerfile.
MSG
  exit 1
fi

hr; echo "[run_all] (2/5) Levantando contenedores ..."; hr
"${COMPOSE[@]}" up -d || die "No se pudieron levantar los contenedores."

# ---- Esperar a sshd ----------------------------------------------------------
echo "[run_all] Esperando a que sshd (S1) escuche en :22 ..."
for i in $(seq 1 60); do
  if docker exec "$SERVER_CTR" ss -tln 2>/dev/null | grep -q ':22'; then
    echo "[run_all] sshd listo."; break
  fi
  [[ $i -eq 60 ]] && die "sshd no quedó listo tras 60s. Revisa: docker logs $SERVER_CTR"
  sleep 1
done

# ---- (3/5) Versiones REALES de OpenSSH --------------------------------------
hr; echo "[run_all] (3/5) Versión REAL de OpenSSH por contenedor (ssh -V):"; hr
declare -A VER_CTR=( [C1]=lab5-c1 [C2]=lab5-c2 [C3]=lab5-c3 [C4/S1]=lab5-c4-s1 )
for label in C1 C2 C3 C4/S1; do
  ctr="${VER_CTR[$label]}"
  ver="$(docker exec "$ctr" ssh -V 2>&1 || echo '??')"
  printf '   %-6s (%s): %s\n' "$label" "$ctr" "$ver"
done
# (sshd no expone un flag de versión propio; la versión del servidor es la de
#  C4/S1 mostrada arriba, y se ve también como banner del server en los pcaps.)

# ---- (4/5) Capturas de los 4 escenarios -------------------------------------
hr; echo "[run_all] (4/5) Capturando los 4 escenarios ..."; hr
for c in c1 c2 c3 c4; do
  bash "$SCRIPT_DIR/capture.sh" "$c" || die "Falló la captura del escenario $c."
done

# ---- (5/5) Extracción de HASSH + resumen ------------------------------------
hr; echo "[run_all] (5/5) Extrayendo HASSH y generando CSV ..."; hr
bash "$SCRIPT_DIR/extract_hassh.sh" || die "Falló la extracción de HASSH."

hr
echo "[run_all] LISTO."
echo "  pcaps : $ROOT/capturas/*_a_s1.pcap"
echo "  csv   : $ROOT/capturas/hassh_summary.csv"
echo
echo "  Siguientes pasos (opcionales, ver README):"
echo "    - Parte 3 (KEXINIT server < 300B): bash scripts/shrink_server_kexinit.sh"
echo "    - Parte 2 (informante):            ver sección 'Parte 2' del README"
hr

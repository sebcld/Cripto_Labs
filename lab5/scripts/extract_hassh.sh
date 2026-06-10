#!/usr/bin/env bash

set -euo pipefail

SERVER_CTR="lab5-c4-s1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/capturas"
CSV="${CAP_DIR}/hassh_summary.csv"

die() { echo "ERROR: $*" >&2; exit 1; }

docker inspect "$SERVER_CTR" >/dev/null 2>&1 || die "Contenedor $SERVER_CTR no existe (docker compose up -d)."
command -v docker >/dev/null || die "docker no está en PATH."

# El KEXINIT del cliente viaja HACIA el puerto 22 (tcp.dstport==22) y es el
# único paquete que lleva poblado ssh.kex.hassh.
DISPLAY_FILTER='ssh.message_code==20 && tcp.dstport==22'

# Helper: ejecuta tshark dentro del contenedor sobre el pcap ya copiado.
tsh() { docker exec "$SERVER_CTR" tshark "$@"; }

# Encabezado CSV.
echo 'escenario,version_banner,hassh,tam_kexinit,kex_algs,enc_algs,mac_algs' > "$CSV"

# Escapado mínimo de CSV: envolver en comillas y duplicar comillas internas.
csv_q() { local s="${1//\"/\"\"}"; printf '"%s"' "$s"; }

shopt -s nullglob
PCAPS=("$CAP_DIR"/*_a_s1.pcap)
[[ ${#PCAPS[@]} -gt 0 ]] || die "No hay .pcap en $CAP_DIR. Corre antes scripts/run_all.sh o capture.sh."

for pcap in "${PCAPS[@]}"; do
  scn="$(basename "$pcap" .pcap)"            # p.ej. c1_a_s1
  in_ctr="/tmp/extract_${scn}.pcap"
  docker cp "$pcap" "${SERVER_CTR}:${in_ctr}"

  # --- Campos del KEXINIT del cliente (una sola línea, separador '|') --------
  read_fields="$(tsh -r "$in_ctr" -Y "$DISPLAY_FILTER" -T fields \
                    -e ssh.kex.hassh \
                    -e frame.len \
                    -e ssh.kex_algorithms \
                    -e ssh.encryption_algorithms_client_to_server \
                    -e ssh.mac_algorithms_client_to_server \
                    -E separator='|' 2>/dev/null | head -1 || true)"

  IFS='|' read -r hassh tam_kexinit kex_algs enc_algs mac_algs <<< "$read_fields"

  # --- Banner de versión del cliente (paquete "Protocol", hacia :22) ---------
  banner="$(tsh -r "$in_ctr" -Y 'ssh.protocol && tcp.dstport==22' -T fields \
               -e ssh.protocol 2>/dev/null | head -1 || true)"

  # Avisos no fatales si algo vino vacío (p.ej. captura incompleta).
  [[ -n "$hassh"       ]] || echo "[extract:$scn] (aviso) HASSH vacío"        >&2
  [[ -n "$tam_kexinit" ]] || echo "[extract:$scn] (aviso) tam_kexinit vacío"  >&2

  {
    printf '%s,'  "$(csv_q "$scn")"
    printf '%s,'  "$(csv_q "${banner:-}")"
    printf '%s,'  "$(csv_q "${hassh:-}")"
    printf '%s,'  "$(csv_q "${tam_kexinit:-}")"
    printf '%s,'  "$(csv_q "${kex_algs:-}")"
    printf '%s,'  "$(csv_q "${enc_algs:-}")"
    printf '%s\n' "$(csv_q "${mac_algs:-}")"
  } >> "$CSV"

  echo "[extract:$scn] banner='${banner:-?}'  hassh='${hassh:-?}'  kexinit=${tam_kexinit:-?}B"
  docker exec "$SERVER_CTR" rm -f "$in_ctr"
done

echo
echo "CSV generado: $CSV"
column -s, -t "$CSV" 2>/dev/null || cat "$CSV"

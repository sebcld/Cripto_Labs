#!/usr/bin/env bash

set -euo pipefail

CLIENT="${1:-}"
SERVER_CTR="lab5-c4-s1"          
SSH_USER="prueba"
SSH_PASS="prueba"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/capturas"
mkdir -p "$CAP_DIR"

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o GlobalKnownHostsFile=/dev/null
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o LogLevel=ERROR
)

die() { echo "ERROR: $*" >&2; exit 1; }

[[ -n "$CLIENT" ]] || die "Falta el escenario. Uso: $0 <c1|c2|c3|c4>"

case "$CLIENT" in
  c1|c2|c3)
    CLIENT_CTR="lab5-${CLIENT}"
    IFACE="eth0"
    TARGET="s1"
    CLIENT_IP="$(docker exec "$SERVER_CTR" getent hosts "$CLIENT" | awk '{print $1}' | head -1)"
    [[ -n "$CLIENT_IP" ]] || die "No pude resolver la IP de '$CLIENT' desde $SERVER_CTR (¿red levantada?)."
    BPF="tcp port 22 and host $CLIENT_IP"
    ;;
  c4)
    # C4 es el propio c4-s1; la conexión a S1 va por loopback.
    CLIENT_CTR="$SERVER_CTR"
    IFACE="lo"
    TARGET="localhost"
    BPF="tcp port 22"
    ;;
  *)
    die "Escenario inválido: '$CLIENT' (esperado c1|c2|c3|c4)"
    ;;
esac

SCN="${CLIENT}_a_s1"
PCAP_IN_CTR="/tmp/${SCN}.pcap"
PCAP_OUT="${CAP_DIR}/${SCN}.pcap"

docker inspect "$SERVER_CTR" >/dev/null 2>&1 || die "Contenedor $SERVER_CTR no existe. Corre antes: docker compose up -d"
docker inspect "$CLIENT_CTR" >/dev/null 2>&1 || die "Contenedor $CLIENT_CTR no existe. Corre antes: docker compose up -d"

echo "[capture:$CLIENT] Esperando a que sshd escuche en :22 ..."
for i in $(seq 1 30); do
  if docker exec "$SERVER_CTR" ss -tln 2>/dev/null | grep -q ':22'; then break; fi
  [[ $i -eq 30 ]] && die "sshd no está escuchando en :22 tras 30s."
  sleep 1
done

echo "[capture:$CLIENT] tcpdump en ${SERVER_CTR}:${IFACE}  filtro='${BPF}'"

docker exec "$SERVER_CTR" bash -c 'pkill -x tcpdump >/dev/null 2>&1 || true'
docker exec "$SERVER_CTR" rm -f "$PCAP_IN_CTR"

docker exec -d "$SERVER_CTR" tcpdump -i "$IFACE" -s 0 -U -w "$PCAP_IN_CTR" $BPF

for i in $(seq 1 15); do
  if docker exec "$SERVER_CTR" test -f "$PCAP_IN_CTR"; then break; fi
  [[ $i -eq 15 ]] && die "tcpdump no arrancó dentro de $SERVER_CTR."
  sleep 0.3
done
sleep 1

echo "[capture:$CLIENT] Conectando ${CLIENT}->S1 (${TARGET}) ..."
docker exec "$CLIENT_CTR" sshpass -p "$SSH_PASS" \
    ssh "${SSH_OPTS[@]}" "${SSH_USER}@${TARGET}" 'true' \
    || echo "[capture:$CLIENT] (aviso) ssh terminó con código !=0; el handshake igual quedó capturado."

sleep 1   

docker exec "$SERVER_CTR" bash -c 'pkill -INT -x tcpdump >/dev/null 2>&1 || true'
sleep 1

docker cp "${SERVER_CTR}:${PCAP_IN_CTR}" "$PCAP_OUT"
PKTS="$(docker exec "$SERVER_CTR" bash -c "tcpdump -r '$PCAP_IN_CTR' 2>/dev/null | wc -l" || echo '?')"
echo "[capture:$CLIENT] OK -> ${PCAP_OUT}  (${PKTS} paquetes)"
[[ "$PKTS" =~ ^[0-9]+$ && "$PKTS" -gt 0 ]] || die "El .pcap de $CLIENT quedó vacío (¿filtro o conexión incorrectos?)."

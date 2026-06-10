#!/usr/bin/env bash

set -euo pipefail

SERVER_CTR="lab5-c4-s1"
LIMIT=300
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/capturas"
PCAP_OUT="${CAP_DIR}/c4_a_s1_shrink.pcap"
PCAP_IN_CTR="/tmp/c4_a_s1_shrink.pcap"
mkdir -p "$CAP_DIR"

die() { echo "ERROR: $*" >&2; exit 1; }

docker inspect "$SERVER_CTR" >/dev/null 2>&1 || die "Contenedor $SERVER_CTR no existe (docker compose up -d)."

MARK='# === LAB5 PARTE3: KEXINIT del servidor < 300 bytes ==='

echo "[shrink] Aplicando configuración mínima de algoritmos a sshd_config ..."

docker exec -i "$SERVER_CTR" bash -s <<EOF
set -e
# Restaurar base limpia si existe la copia original.
[ -f /etc/ssh/sshd_config.orig ] && cp /etc/ssh/sshd_config.orig /etc/ssh/sshd_config
# Eliminar bloque previo (por si se corrió antes).
sed -i '/${MARK}/,\$d' /etc/ssh/sshd_config
cat >> /etc/ssh/sshd_config <<CFG

${MARK}
KexAlgorithms curve25519-sha256
HostKeyAlgorithms ssh-ed25519
HostKey /etc/ssh/ssh_host_ed25519_key
Ciphers aes128-ctr
MACs hmac-sha1
CFG
# Validar configuración antes de reiniciar.
sshd -t
# Reiniciar sshd: matar el demonio actual y volver a arrancarlo.
pkill -x sshd >/dev/null 2>&1 || true
sleep 1
/usr/sbin/sshd -e
EOF

# Esperar a que vuelva a escuchar.
echo "[shrink] Esperando a que sshd vuelva a escuchar en :22 ..."
for i in $(seq 1 30); do
  docker exec "$SERVER_CTR" ss -tln 2>/dev/null | grep -q ':22' && break
  [[ $i -eq 30 ]] && die "sshd no volvió a escuchar tras el reinicio."
  sleep 1
done

# ---- Recaptura de un handshake C4->S1 por loopback --------------------------
echo "[shrink] Recapturando handshake C4->S1 en lo ..."
docker exec "$SERVER_CTR" bash -c 'pkill -x tcpdump >/dev/null 2>&1 || true'
docker exec "$SERVER_CTR" rm -f "$PCAP_IN_CTR"
docker exec -d "$SERVER_CTR" tcpdump -i lo -s 0 -U -w "$PCAP_IN_CTR" tcp port 22
for i in $(seq 1 15); do
  docker exec "$SERVER_CTR" test -f "$PCAP_IN_CTR" && break
  sleep 0.3
done
sleep 1
docker exec "$SERVER_CTR" sshpass -p prueba ssh \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o LogLevel=ERROR prueba@localhost 'true' \
    || echo "[shrink] (aviso) ssh devolvió !=0; el handshake igual quedó capturado."
sleep 1
docker exec "$SERVER_CTR" bash -c 'pkill -INT -x tcpdump >/dev/null 2>&1 || true'
sleep 1
docker cp "${SERVER_CTR}:${PCAP_IN_CTR}" "$PCAP_OUT"

# ---- Medir el KEXINIT del SERVIDOR (tcp.srcport==22) ------------------------
# frame.len = tamaño en la columna "Length" de Wireshark (lo que pide el lab).
SIZE="$(docker exec "$SERVER_CTR" tshark -r "$PCAP_IN_CTR" \
          -Y 'ssh.message_code==20 && tcp.srcport==22' \
          -T fields -e frame.len 2>/dev/null | head -1 || true)"

[[ -n "$SIZE" ]] || die "No pude medir el KEXINIT del servidor en la recaptura."

echo
echo "=================================================================="
echo " KEXINIT del servidor (frame.len): ${SIZE} bytes   (límite < ${LIMIT})"
echo " pcap de evidencia: ${PCAP_OUT}"
echo "=================================================================="

if [[ "$SIZE" -lt "$LIMIT" ]]; then
  echo "[shrink] OK: el KEXINIT del servidor bajó de ${LIMIT} bytes."
  exit 0
else
  echo "[shrink] FALLO: el KEXINIT del servidor (${SIZE}B) NO bajó de ${LIMIT}B." >&2
  exit 1
fi

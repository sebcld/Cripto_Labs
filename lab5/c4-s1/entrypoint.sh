#!/usr/bin/env bash
# =============================================================================
# Entrypoint de C4/S1.
# Arranca sshd como demonio (NO en foreground) y luego deja el PID 1 dormido.
# Motivo: en la Parte 3 necesitamos poder reiniciar sshd (pkill + arrancar)
# sin que se caiga el contenedor; si sshd fuese el PID 1, matarlo terminaría
# el contenedor entero.
# =============================================================================
set -e

mkdir -p /run/sshd

# Restaurar sshd_config a su estado prístino en cada arranque. Así
# `docker compose restart c4-s1` revierte cualquier cambio de la Parte 3
# (el filesystem del contenedor NO se resetea solo al reiniciar).
if [ -f /etc/ssh/sshd_config.orig ]; then
  cp -f /etc/ssh/sshd_config.orig /etc/ssh/sshd_config
fi

# Validar configuración antes de arrancar (falla ruidosamente si está mal).
/usr/sbin/sshd -t

# Arrancar sshd como demonio, logueando a stderr/syslog.
/usr/sbin/sshd -e
echo "[c4-s1] sshd iniciado y escuchando en :22"

# Mantener el contenedor vivo.
exec sleep infinity

# C4 / S1 — Ubuntu 22.10 (kinetic)
#   - C4: cliente OpenSSH (escenario C4->S1 por loopback `lo`)
#   - S1: servidor OpenSSH (sshd) al que se conectan C1, C2, C3 y C4
#   - Además: tcpdump + tshark para capturar/analizar TODOS los handshakes
#             (es el único contenedor con CAP_NET_ADMIN/NET_RAW, ver compose).

FROM ubuntu:22.10

ARG DEBIAN_FRONTEND=noninteractive

# tshark/wireshark-common abre un prompt debconf (setuid para no-root). Como
# dentro del contenedor capturamos como root, lo preseedeamos en "false".
RUN echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections

# (1) Fuentes -> old-releases.  (2) Cliente + servidor + tcpdump + tshark.
#     iproute2 -> `ss` para chequear que sshd ya escucha en :22.
#     sshpass  -> login no-interactivo por contraseña en el escenario C4->S1.
RUN sed -i 's/archive.ubuntu.com/old-releases.ubuntu.com/g; s/security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        openssh-client openssh-server sshpass tcpdump tshark iproute2 \
 && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------------
# Usuario de prueba solicitado por el lab: prueba / prueba
# -----------------------------------------------------------------------------
RUN useradd -m -s /bin/bash prueba \
 && echo 'prueba:prueba' | chpasswd

# -----------------------------------------------------------------------------
# Configuración de sshd:
#   - PasswordAuthentication yes  (el lab pide login por contraseña)
#   - PermitRootLogin no          (solo accedemos como 'prueba')
#   - Puerto 22
#   - ssh-keygen -A genera las host keys por defecto (rsa/ecdsa/ed25519)
# -----------------------------------------------------------------------------
RUN mkdir -p /run/sshd \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/'  /etc/ssh/sshd_config \
 && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/'                 /etc/ssh/sshd_config \
 && sed -i 's/^#\?Port .*/Port 22/'                                       /etc/ssh/sshd_config \
 && ssh-keygen -A

# Guardamos una copia prístina del sshd_config para que shrink_server_kexinit.sh
# pueda partir siempre desde un estado limpio (idempotencia de la Parte 3).
RUN cp /etc/ssh/sshd_config /etc/ssh/sshd_config.orig

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22
# El entrypoint lanza sshd como demonio y deja PID 1 vivo (sleep infinity),
# de modo que se pueda reiniciar sshd (Parte 3) sin matar el contenedor.
CMD ["/usr/local/bin/entrypoint.sh"]


FROM ubuntu:16.10

# Evita prompts de debconf durante la instalación.
ARG DEBIAN_FRONTEND=noninteractive

# (1) Reescribir las fuentes apt hacia old-releases (repos EOL movidos).
# (2) Instalar el cliente OpenSSH disponible en apt + sshpass para automatizar
#     el login por contraseña no-interactivo durante la captura del handshake.
RUN sed -i 's/archive.ubuntu.com/old-releases.ubuntu.com/g; s/security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sshpass \
 && rm -rf /var/lib/apt/lists/*

# El contenedor debe mantenerse vivo para poder hacer `docker exec` la conexión.
CMD ["sleep", "infinity"]

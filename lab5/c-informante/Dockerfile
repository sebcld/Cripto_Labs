# hay que COMPILAR el cliente desde fuente cambiando ese string.
#
# Este Dockerfile compila openssh-portable y reescribe el banner COMPLETO de version
FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive


ARG SSH_BANNER="OpenSSH_7.4"
# OPENSSH_SRC : versión del tarball portable que se compila (define la huella).
ARG OPENSSH_SRC=9.6p1

# --- Dependencias de compilación 
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential wget ca-certificates \
        zlib1g-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN wget -q "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_SRC}.tar.gz" \
 && tar xzf "openssh-${OPENSSH_SRC}.tar.gz"
WORKDIR /usr/src/openssh-${OPENSSH_SRC}

# --- Reescritura del banner de versión (version.h) 

RUN cp version.h version.h.orig \
 && grep -vE '^#define (SSH_VERSION|SSH_PORTABLE)\b' version.h.orig > version.h \
 && printf '#define SSH_VERSION "%s"\n#define SSH_PORTABLE ""\n' "$SSH_BANNER" >> version.h \
 && echo "==> version.h reescrito:" \
 && grep -E '#define SSH_(VERSION|PORTABLE|RELEASE)' version.h

RUN ./configure --prefix=/opt/openssh >/dev/null \
 && make ssh >/dev/null \
 && install -D -m0755 ssh /opt/openssh/bin/ssh \
 && /opt/openssh/bin/ssh -V

RUN apt-get update && apt-get install -y --no-install-recommends sshpass \
 && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]


FROM ubuntu:20.10

ARG DEBIAN_FRONTEND=noninteractive

RUN sed -i 's/archive.ubuntu.com/old-releases.ubuntu.com/g; s/security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sshpass \
 && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]

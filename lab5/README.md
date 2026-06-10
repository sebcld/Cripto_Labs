# Lab 5 — fingerprints de versiones OpenSSH (HASSH + tamaños de paquete)

Infraestructura reproducible para levantar 4 clientes SSH con distintas versiones
de OpenSSH, capturar sus *handshakes* contra un servidor y demostrar que cada
versión deja una huella distinta (**HASSH** + tamaños de paquete).

---

## Arquitectura

| Rol | SO (Ubuntu) | Contenedor | Hostname / alias | Rol SSH |
|-----|-------------|------------|------------------|---------|
| C1 | 16.10 (yakkety) | `lab5-c1` | `c1` | cliente |
| C2 | 18.10 (cosmic)  | `lab5-c2` | `c2` | cliente |
| C3 | 20.10 (groovy)  | `lab5-c3` | `c3` | cliente |
| C4 / S1 | 22.10 (kinetic) | `lab5-c4-s1` | `c4` (+ alias `s1`) | cliente **y** servidor |

- **S1** = servidor `openssh-server` con usuario `prueba:prueba` y
  `PasswordAuthentication yes`, escuchando en `:22`.
- **4 escenarios:** `C1->S1`, `C2->S1`, `C3->S1`, `C4->S1`.
  El escenario `C4->S1` va por **loopback (`lo`)** porque C4 y S1 son el mismo host.

### Dónde se captura (decisión de diseño)

Sólo `c4-s1` tiene `CAP_NET_ADMIN/NET_RAW` y trae `tcpdump`/`tshark`. Por eso
**todas las capturas se hacen del lado del servidor**:

- `C1/C2/C3 -> S1`: `tcpdump` en `eth0` de `c4-s1`, filtrando por la IP del cliente.
- `C4 -> S1`: `tcpdump` en `lo`.

Una captura del lado servidor ve **ambos sentidos**, así que igual obtenemos el
banner, KEXINIT, HASSH del **cliente**, el KEX y las *New Keys*. Los clientes no
necesitan privilegios ni `tcpdump`.

---

## Requisitos

- Docker Engine + plugin `docker compose` (v2). También funciona con `docker-compose` v1.
- Conexión a internet la **primera vez** (pull de imágenes base + paquetes apt EOL).

---

## Uso rápido

```bash
cd lab5
bash scripts/run_all.sh
```

Esto:

1. Construye las imágenes y levanta la red.
2. Espera a que `sshd` (S1) esté listo.
3. Imprime la **versión REAL** de OpenSSH de cada contenedor (`ssh -V`).
4. Captura los 4 escenarios → `capturas/<cN>_a_s1.pcap`.
5. Extrae las huellas → `capturas/hassh_summary.csv`.


Abre los `.pcap` en Wireshark, o re-extrae sin recapturar:

```bash
bash scripts/extract_hassh.sh
```

### Capturar un solo escenario

```bash
bash scripts/capture.sh c2      # c1 | c2 | c3 | c4
```

### Apagar / limpiar

```bash
docker compose down            # apaga
docker compose down --rmi local --volumes   # apaga y borra imágenes/volúmenes
```

---

## Scripts

| Script | Qué hace |
|--------|----------|
| `scripts/run_all.sh` | Orquesta todo (build → up → `ssh -V` → 4 capturas → CSV). |
| `scripts/capture.sh <cN>` | Captura 1 escenario a `.pcap` (servidor-side; `lo` para C4). |
| `scripts/extract_hassh.sh` | `tshark` por pcap → HASSH, banner, tamaño KEXINIT y listas de algoritmos → CSV. |
| `scripts/shrink_server_kexinit.sh` | **Parte 3**: reduce algoritmos de `sshd` hasta KEXINIT del server < 300 B y lo verifica. |

---


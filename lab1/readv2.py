#!/usr/bin/env python3
"""
readv2.py — MitM: extrae mensaje infiltrado de paquetes ICMP y rompe cifrado César
Lee un archivo .pcapng, reconstruye el mensaje oculto en el byte[16] del payload
ICMP, luego prueba los 26 desplazamientos posibles e imprime en VERDE la opción
más probable de ser el texto en claro.

Uso:
    sudo python3 readv2.py cesar.pcapng
    sudo python3 readv2.py cesar.pcapng --src 192.168.1.5

Requerimientos:
    pip install scapy
"""

import sys
import struct
import argparse
import collections

try:
    from scapy.all import rdpcap, IP, ICMP, Raw, conf
except ImportError:
    print("[ERROR] Scapy no está instalado. Ejecute: pip install scapy")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────────────
# Pre-shared secret — debe coincidir exactamente con el valor en pingv4.py
# Embebido en los 16 bits bajos del campo ts_usec (bytes [8:10] del payload)
# ──────────────────────────────────────────────────────────────────────────────
MAGIC = 0xC0DE

# ──────────────────────────────────────────────────────────────────────────────
# Colores ANSI
# ──────────────────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ──────────────────────────────────────────────────────────────────────────────
# Frecuencia de letras del español (para scoring)
# ──────────────────────────────────────────────────────────────────────────────
FREQ_ESP = {
    'a': 12.53, 'e': 13.68, 'o': 8.68, 's': 7.98, 'r': 6.87,
    'n': 6.71,  'i': 6.25,  'd': 5.86, 'l': 4.97, 't': 4.63,
    'u': 3.93,  'c': 4.68,  'm': 3.15, 'p': 2.51, 'b': 1.42,
    'g': 1.01,  'v': 0.90,  'y': 0.90, 'q': 0.88, 'h': 0.70,
    'f': 0.69,  'z': 0.52,  'j': 0.44, 'x': 0.22, 'k': 0.11,
    'w': 0.02,
}

PALABRAS_ESP = {
    "de", "en", "el", "la", "los", "las", "un", "una", "y", "a",
    "que", "es", "con", "se", "por", "su", "para", "al", "del",
    "como", "no", "le", "lo", "si", "ya", "pero", "o", "ha",
    "fue", "ser", "redes", "seguridad", "clave", "datos", "red",
}


# ──────────────────────────────────────────────────────────────────────────────
# Funciones auxiliares
# ──────────────────────────────────────────────────────────────────────────────

def _tiene_magic(data: bytes) -> bool:
    """
    Verifica que los bytes [8:10] del payload coincidan con el pre-shared secret.

    Layout del timestamp en pingv4.py (struct '<qq', 16 bytes):
      [0:8]   ts_sec   — segundos epoch (int64 little-endian)
      [8:16]  ts_usec  — microsegundos  (int64 little-endian)
                         los 16 bits bajos (bytes [8:10]) contienen MAGIC

    Un ping real tendra cualquier valor aleatorio en [8:10]; la probabilidad
    de colision con MAGIC = 0xC0DE es 1/65536 ~ 0.0015%.
    """
    if len(data) < 10:
        return False
    valor, = struct.unpack("<H", data[8:10])
    return valor == MAGIC


def descifrar_cesar(texto: str, shift: int) -> str:
    """Descifra texto con desplazamiento César."""
    resultado = []
    for ch in texto:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            resultado.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            resultado.append(ch)
    return ''.join(resultado)


def score_texto(texto: str) -> float:
    """
    Puntua que tan probable es que el texto sea español.
    Combina analisis de frecuencia de letras + coincidencia de palabras comunes.
    """
    texto_l = texto.lower()
    letras  = [c for c in texto_l if c.isalpha()]

    if not letras:
        return 0.0

    conteo = collections.Counter(letras)
    total  = len(letras)

    score_freq = sum(
        (conteo.get(l, 0) / total) * freq
        for l, freq in FREQ_ESP.items()
    )

    palabras_texto = set(texto_l.split())
    bonus = sum(3.0 for p in PALABRAS_ESP if p in palabras_texto)

    return score_freq + bonus


def extraer_mensaje_icmp(pkts, src_filter=None):
    """
    Filtra paquetes ICMP Echo Request y extrae el caracter infiltrado.

    Layout del campo Data (56 bytes) generado por pingv4.py:
      [0:8]   ts_sec   — int64 little-endian
      [8:10]  MAGIC    — 0xC0DE  (pre-shared secret)  <- FILTRO
      [10:16] ts_usec resto
      [16]    caracter oculto  ord(char)               <- dato infiltrado
      [17:56] relleno estandar 0x11...0x37             <- intacto

    Solo se procesan paquetes cuyo data[8:10] == MAGIC.
    El resto (pings reales, otros procesos) se descartan silenciosamente.
    """
    encontrados = []
    descartados = 0

    for pkt in pkts:
        if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
            continue
        if pkt[ICMP].type != 8:
            continue
        if src_filter and pkt[IP].src != src_filter:
            continue
        if not pkt.haslayer(Raw):
            continue

        data = bytes(pkt[Raw].load)

        # ── Verificar pre-shared secret ───────────────────────────────
        if not _tiene_magic(data):
            descartados += 1
            continue
        # ─────────────────────────────────────────────────────────────

        if len(data) <= 16:
            continue

        char_byte = data[16]   # caracter siempre en offset fijo post-magic

        if not (32 <= char_byte <= 126):
            continue

        seq    = pkt[ICMP].seq
        src_ip = pkt[IP].src
        encontrados.append((seq, chr(char_byte), src_ip))

    encontrados.sort(key=lambda x: x[0])
    return encontrados, descartados


def imprimir_banner():
    print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  readv2.py — MitM ICMP Stealth Decoder{RESET}")
    print(f"{BOLD}{CYAN}  magic=0x{MAGIC:04X}  offset_char=data[16]{RESET}")
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}\n")


def imprimir_resultados_cesar(mensaje_cifrado: str, scores: list):
    """Imprime todas las combinaciones César, resaltando la mejor."""
    mejor_shift, mejor_texto, mejor_score = scores[0]

    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}  Fuerza bruta César — {len(scores)} combinaciones posibles{RESET}")
    print(f"{BOLD}{'─'*60}{RESET}")
    print(f"  {'Shift':>5}  {'Texto descifrado':<38}  {'Score':>7}")
    print(f"  {'─'*5}  {'─'*38}  {'─'*7}")

    for shift, texto, score in scores:
        es_mejor = (shift == mejor_shift)
        prefijo  = "► " if es_mejor else "  "
        color    = f"{GREEN}{BOLD}" if es_mejor else ""
        reset    = RESET if es_mejor else ""
        print(f"{color}{prefijo}{shift:>4}   {texto:<38}  {score:>7.2f}{reset}")

    print(f"\n{GREEN}{BOLD}  ✓ Opcion mas probable  →  shift={mejor_shift}  →  \"{mejor_texto}\"{RESET}")
    print(f"{'─'*60}\n")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="readv2.py — Extrae y descifra mensaje infiltrado via ICMP stealth"
    )
    parser.add_argument("pcap",              help="Archivo .pcapng / .pcap a analizar")
    parser.add_argument("--src", default=None, help="Filtrar por IP origen")
    parser.add_argument("--raw", action="store_true",
                        help="Mostrar byte raw (hex) de cada caracter")
    args = parser.parse_args()

    imprimir_banner()

    # ── 1. Leer captura ───────────────────────────────────────────────────────
    print(f"[*] Leyendo captura  : {args.pcap}")
    conf.verb = 0
    try:
        pkts = rdpcap(args.pcap)
    except FileNotFoundError:
        print(f"{RED}[ERROR] Archivo no encontrado: {args.pcap}{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}[ERROR] No se pudo leer el archivo: {e}{RESET}")
        sys.exit(1)

    icmp_req = [p for p in pkts if p.haslayer(ICMP) and p[ICMP].type == 8]
    print(f"[*] Paquetes totales : {len(pkts)}")
    print(f"[*] ICMP Echo Req.   : {len(icmp_req)}")

    # ── 2. Extraer sesion stealth por MAGIC ───────────────────────────────────
    extraidos, descartados = extraer_mensaje_icmp(pkts, src_filter=args.src)

    print(f"[*] Descartados (sin magic 0x{MAGIC:04X}): {descartados}")
    print(f"[*] Caracteres infiltrados       : {len(extraidos)}\n")

    if not extraidos:
        print(f"{RED}[!] No se encontro ningun paquete con magic=0x{MAGIC:04X}.{RESET}")
        print(f"    Verifique que MAGIC coincide con el valor en pingv4.py")
        sys.exit(1)

    # ── 3. Mostrar tabla de extraccion ────────────────────────────────────────
    print(f"{BOLD}  Extraccion data[16] — sesion magic=0x{MAGIC:04X}:{RESET}")
    print(f"  {'Seq':>4}  {'IP Origen':<16}  {'Byte':>4}  {'Char'}")
    print(f"  {'─'*4}  {'─'*16}  {'─'*4}  {'─'*4}")
    for seq, char, src in extraidos:
        byte_val = ord(char)
        raw_col  = f"  0x{byte_val:02x}" if args.raw else ""
        print(f"  {seq:>4}  {src:<16}  {byte_val:>4}  '{char}'{raw_col}")

    mensaje_cifrado = ''.join(ch for _, ch, _ in extraidos)
    print(f"\n{BOLD}  Mensaje reconstruido (cifrado): {YELLOW}\"{mensaje_cifrado}\"{RESET}")

    # ── 4. Fuerza bruta César ─────────────────────────────────────────────────
    scores = []
    for shift in range(26):
        texto = descifrar_cesar(mensaje_cifrado, shift)
        sc    = score_texto(texto)
        scores.append((shift, texto, sc))

    scores.sort(key=lambda x: x[2], reverse=True)
    imprimir_resultados_cesar(mensaje_cifrado, scores)


if __name__ == "__main__":
    main()
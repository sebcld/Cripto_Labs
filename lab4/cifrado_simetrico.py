"""
Laboratorio 4 - Cifrado simétrico
Implementación de DES, AES-256 y 3DES en modo CBC
"""
from Crypto.Cipher import DES, AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64



#1 validar y ajuste de la clave y IV
def ajustar_bytes(valor: bytes, tamano_requerido: int, nombre: str) -> bytes:
    
    if len(valor) < tamano_requerido:
        faltantes = tamano_requerido - len(valor)
        relleno = get_random_bytes(faltantes)
        valor_ajustado = valor + relleno
        print(f"[!] {nombre} mas corta de lo necesario. "
              f"Se agregaron {faltantes} byte(s) aleatorios.")
    elif len(valor) > tamano_requerido:
        valor_ajustado = valor[:tamano_requerido]
        print(f"[!] {nombre} más larga de lo necesario. "
              f"Se truncó a {tamano_requerido} bytes.")
    else:
        valor_ajustado = valor
        print(f"[OK] {nombre} tiene el tamaño correcto "
              f"({tamano_requerido} bytes).")
    return valor_ajustado


#2 funciones de cifrado y descifrado (CBC)

def cifrar_des(clave: bytes, iv: bytes, texto: bytes) -> bytes:
    cipher = DES.new(clave, DES.MODE_CBC, iv)
    return cipher.encrypt(pad(texto, DES.block_size))


def descifrar_des(clave: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = DES.new(clave, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES.block_size)


def cifrar_aes256(clave: bytes, iv: bytes, texto: bytes) -> bytes:
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(texto, AES.block_size))


def descifrar_aes256(clave: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


def cifrar_3des(clave: bytes, iv: bytes, texto: bytes) -> bytes:
    cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    return cipher.encrypt(pad(texto, DES3.block_size))


def descifrar_3des(clave: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES3.block_size)


#3mostrar resultados

def mostrar_resultado(nombre_algoritmo: str,
                      clave: bytes, iv: bytes,
                      ciphertext: bytes, plaintext: bytes):
    print("\n" + "=" * 60)
    print(f"  {nombre_algoritmo}")
    print("=" * 60)
    print(f"Clave final (hex)  : {clave.hex()}")
    print(f"IV    final (hex)  : {iv.hex()}")
    print(f"Texto cifrado (hex): {ciphertext.hex()}")
    print(f"Texto cifrado (b64): {base64.b64encode(ciphertext).decode()}")
    print(f"Texto descifrado   : {plaintext.decode('utf-8', errors='replace')}")


def main():
    print("=" * 60)
    print(" Laboratorio 4 - Cifrado simétrico (DES, AES-256, 3DES)")
    print("=" * 60)

    #entrada de datos desde la terminal 
    key_des_in   = input("Ingrese la KEY para DES        : ").encode()
    iv_des_in    = input("Ingrese el IV  para DES        : ").encode()

    key_aes_in   = input("Ingrese la KEY para AES-256    : ").encode()
    iv_aes_in    = input("Ingrese el IV  para AES-256    : ").encode()

    key_3des_in  = input("Ingrese la KEY para 3DES       : ").encode()
    iv_3des_in   = input("Ingrese el IV  para 3DES       : ").encode()

    texto_in     = input("Ingrese el TEXTO a cifrar      : ").encode()

    print("\n--- Ajustes DES ---")
    key_des = ajustar_bytes(key_des_in, 8, "Clave DES")
    iv_des  = ajustar_bytes(iv_des_in,  8, "IV DES")

    print("\n--- Ajustes AES-256 ---")
    key_aes = ajustar_bytes(key_aes_in, 32, "Clave AES-256")
    iv_aes  = ajustar_bytes(iv_aes_in,  16, "IV AES-256")


    print("\n--- Ajustes 3DES ---")
    key_3des = ajustar_bytes(key_3des_in, 24, "Clave 3DES")
    try:
        DES3.adjust_key_parity(key_3des)  # valida la clave
    except ValueError:
        print("[!] La clave 3DES tiene paridad débil. "
              "Se regenera aleatoriamente.")
        key_3des = DES3.adjust_key_parity(get_random_bytes(24))
    iv_3des = ajustar_bytes(iv_3des_in, 8, "IV 3DES")

    # DES
    ct_des = cifrar_des(key_des, iv_des, texto_in)
    pt_des = descifrar_des(key_des, iv_des, ct_des)
    mostrar_resultado("DES (CBC)", key_des, iv_des, ct_des, pt_des)

    # AES-256
    ct_aes = cifrar_aes256(key_aes, iv_aes, texto_in)
    pt_aes = descifrar_aes256(key_aes, iv_aes, ct_aes)
    mostrar_resultado("AES-256 (CBC)", key_aes, iv_aes, ct_aes, pt_aes)

    # 3DES
    ct_3des = cifrar_3des(key_3des, iv_3des, texto_in)
    pt_3des = descifrar_3des(key_3des, iv_3des, ct_3des)
    mostrar_resultado("3DES (CBC)", key_3des, iv_3des, ct_3des, pt_3des)

    print("\n" + "=" * 60)
    print(" Proceso finalizado correctamente.")
    print("=" * 60)


if __name__ == "__main__":
    main()
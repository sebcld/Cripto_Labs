# Uso del script Python de fuerza bruta en DVWA

## Descripción

Este proyecto contiene un script en Python que automatiza pruebas de inicio de sesión contra el formulario `vulnerabilities/brute` de DVWA, utilizando la librería `requests`.

El script prueba combinaciones de usuarios y contraseñas a partir de dos diccionarios externos:

- un archivo con nombres de usuario
- un archivo con contraseñas

El objetivo es detectar credenciales válidas en un entorno de laboratorio local.

---

## Requisitos

Antes de ejecutar el script, tener lo siguiente:

- Python 3
- pip
- DVWA ejecutándose en Docker
- nivel de seguridad configurado en `low`

Instalación de la librería necesaria:

```bash
pip install requests
```

---

## Archivos necesarios


- `dvwa_bruteforce.py`
- `users.txt`
- `passwords.txt`


---
## Ejecución básica

Ejemplo de ejecución:

```bash
python3 brute.py \
  --users users.txt \
  --passwords passwords.txt \
  --phpsessid 2f6af0b95c63f716e0b4e7eb81013a6e \
  --security low
```

---

## Qué hace el script

El script realiza lo siguiente:

1. Carga los usuarios desde `users.txt`
2. Carga las contraseñas desde `passwords.txt`
3. Construye solicitudes HTTP GET hacia:

```text
http://127.0.0.1:4280/vulnerabilities/brute/
```

4. Envía los parámetros:
   - `username`
   - `password`
   - `Login=Login`

5. Usa la cookie de sesión:
   - `PHPSESSID`
   - `security=low`

6. Analiza la respuesta HTML del servidor
7. Detecta credenciales válidas cuando aparece el mensaje:

```text
Welcome to the password protected area
```



---
## Ejemplo completo de uso

```bash
python3 brute.py \
  --base-url http://127.0.0.1:4280 \
  --users users.txt \
  --passwords passwords.txt \
  --phpsessid COOKIE_AQUI \
  --security low
```


---
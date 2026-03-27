# Laboratorio 1: Criptografía e Infiltración de Datos

Conjunto de herramientas Python para cifrado César, infiltración de datos vía paquetes ICMP y análisis de capturas de red.

## 📋 Contenido

- **cesar.py** — Cifrador/Descifrador César
- **ping.py** — inflitracion de datos vía ICMP
- **readv2.py** — Análisis y recuperación de mensajes ocultos

---

## 1. `cesar.py` — Cifrador César

Herramienta para cifrar y descifrar textos usando el algoritmo de cifrado César (sustitución simple con desplazamiento fijo).

### Características
- Cifra/descifra texto mediante desplazamiento de letras
- Preserva mayúsculas y minúsculas
- Mantiene caracteres no alfabéticos (espacios, puntuación, números)
- Desplazamientos modulares (0-25 caracteres)


### Uso

#### Cifrar un mensaje (desplazamiento positivo)
```bash
python3 cesar.py "mensaje secreto" 5
```
**Salida:** `rjsxfoj xjhwjyt`

**Explicación:** Cada letra se desplaza 5 posiciones en el alfabeto

#### Descifrar (desplazamiento negativo/opuesto)
```bash
python3 cesar.py "rjsxfoj xjhwjyt" -5
```
**Salida:** `mensaje secreto`

#### Ejemplos prácticos

Cifrar con desplazamiento 3:
```bash
python3 cesar.py "hola mundo" 3
```
**Salida:** `krod pxqgr`

Descifrar texto que fue cifrado con desplazamiento 3:
```bash
python3 cesar.py "krod pxqgr" 23  # 26 - 3 = 23 (desplazamiento inverso)
```
**Salida:** `hola mundo`

### Parámetros
| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `<texto>` | string | Texto a cifrar/descifrar (entre comillas si contiene espacios) |
| `<desplazamiento>` | int | Número de posiciones a desplazar (1-25 positivo, negativo para deshacer) |


---

## 2. `ping.py` 

### Requisitos
```bash
scapy
```

### Instalación de dependencias
```bash
pip install scapy
```

### Uso básico

#### Enviar mensaje cifrado a servidor remoto
```bash
sudo python3 ping.py "kdnwjb wxlqnb" 
```


### Detalles técnicos

**Payload ICMP (56 bytes):**

**Seguridad:** El paquete se ve como un ping legítimo, pero solo quien conoce `MAGIC=0xC0DE` sabrá que contiene datos ocultos.

---

## 3. `readv2.py` 
### Requisitos
```bash
scapy
```

### Instalación de dependencias
```bash
pip install scapy
```

### Uso básico

#### Analizar archivo PCAP/PCAPNG
```bash
sudo python3 readv2.py captura1.pcapng
```

#### Filtrar por IP origen específica
```bash
sudo python3 readv2.py captura1.pcapng
```

#### Mostrar valores hex de cada carácter
```bash
sudo python3 readv2.py captura1.pcapng
```


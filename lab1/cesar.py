import sys

def cesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            # Determinar si es mayúscula o minúscula
            start = ord('a') if char.islower() else ord('A')
            # Aplicar desplazamiento dentro del rango del alfabeto (26 letras)
            new_char = chr(start + (ord(char) - start + shift) % 26)
            result += new_char
        else:
            result += char
    return result

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python3 cesar.py <texto> <desplazamiento>")
        sys.exit(1)

    input_text = sys.argv[1]
    shift_value = int(sys.argv[2])
    
    encoded = cesar_cipher(input_text, shift_value)
    print(encoded)
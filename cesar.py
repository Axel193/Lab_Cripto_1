import sys

def cifrar_cesar(texto, corrimiento):
    resultado = ""

    for caracter in texto:
        if 'A' <= caracter <= 'Z':
            resultado += chr(
                (ord(caracter) - ord('A') + corrimiento) % 26
                + ord('A')
            )
        elif 'a' <= caracter <= 'z':
            resultado += chr(
                (ord(caracter) - ord('a') + corrimiento) % 26
                + ord('a')
            )
        else:
            resultado += caracter

    return resultado

if len(sys.argv) != 3:
    print("Uso: python3 cesar.py \"texto\" corrimiento")
    sys.exit(1)

texto = sys.argv[1]

try:
    corrimiento = int(sys.argv[2])
except ValueError:
    print("El corrimiento debe ser un número entero.")
    sys.exit(1)

resultado = cifrar_cesar(texto, corrimiento)

print(resultado)
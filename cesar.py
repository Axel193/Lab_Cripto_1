def cifrar_cesar(mensaje, saltos):
    resultado = ""

    for caracter in mensaje:
        if caracter.isupper():
            resultado += chr((ord(caracter) - ord('A') + saltos) % 26 + ord('A'))
        elif caracter.islower():
            resultado += chr((ord(caracter) - ord('a') + saltos) % 26 + ord('a'))
        else:
            resultado += caracter

    return resultado


print("=== CIFRADO DE CÉSAR ===")

mensaje = input("Ingrese el mensaje a cifrar: ")

while True:
    try:
        saltos = int(input("Ingrese la cantidad de saltos: "))
        break
    except ValueError:
        print("Por favor, ingrese un número entero.")

mensaje_cifrado = cifrar_cesar(mensaje, saltos)

print("\nMensaje original:", mensaje)
print("Cantidad de saltos:", saltos)
print("Mensaje cifrado:", mensaje_cifrado)
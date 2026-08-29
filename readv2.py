from scapy.all import rdpcap, ICMP, Raw
import sys

# Códigos de color ANSI
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Frecuencias relativas aproximadas de letras en español
FRECUENCIAS_ESP = {
    'a': 12.53, 'b': 1.42, 'c': 4.68, 'd': 5.86, 'e': 13.68,
    'f': 0.69, 'g': 1.01, 'h': 0.70, 'i': 6.25, 'j': 0.44,
    'k': 0.02, 'l': 4.97, 'm': 3.15, 'n': 6.71, 'o': 8.68,
    'p': 2.51, 'q': 0.88, 'r': 6.87, 's': 7.98, 't': 4.63,
    'u': 3.93, 'v': 0.90, 'w': 0.01, 'x': 0.22, 'y': 0.90, 'z': 0.52
}


def calcular_puntuacion_espanol(texto):
    """Calcula una puntuación según la frecuencia típica de letras en español."""
    puntuacion = 0.0
    for caracter in texto.lower():
        if caracter in FRECUENCIAS_ESP:
            puntuacion += FRECUENCIAS_ESP[caracter]
    return puntuacion


def cesar_decrypt(texto, desplazamiento):
    resultado = ""

    for c in texto:
        if 'A' <= c <= 'Z':
            resultado += chr(
                (ord(c) - ord('A') - desplazamiento) % 26 + ord('A')
            )

        elif 'a' <= c <= 'z':
            resultado += chr(
                (ord(c) - ord('a') - desplazamiento) % 26 + ord('a')
            )

        else:
            resultado += c

    return resultado


def extraer_mensaje(archivo):
    try:
        paquetes = rdpcap(archivo)
    except Exception as e:
        print(f"Error al abrir el archivo: {e}")
        sys.exit(1)

    mensaje = ""
    paquetes_icmp = 0

    for paquete in paquetes:
        if ICMP in paquete:
            if paquete[ICMP].type == 8:  # Echo Request
                paquetes_icmp += 1
                if Raw in paquete:
                    datos = bytes(paquete[Raw].load)
                    try:
                        texto = datos.decode("utf-8")
                        mensaje += texto
                    except UnicodeDecodeError:
                        try:
                            texto = datos.decode("ascii")
                            mensaje += texto
                        except UnicodeDecodeError:
                            pass

    print(f"Paquetes ICMP Echo Request encontrados: {paquetes_icmp}")
    return mensaje


def main():
    if len(sys.argv) == 2:
        archivo = sys.argv[1]
    else:
        archivo = "cesar.pcapng" 

    print(f"\nLeyendo archivo: {archivo}")
    print("-" * 60)

    mensaje = extraer_mensaje(archivo)

    if not mensaje:
        print("\nNo se encontraron datos en los paquetes ICMP.")
        print("Comprueba que el PCAP contiene paquetes ICMP Echo Request")
        print("con información dentro de su payload.")
        sys.exit(1)

    print(f"\nMensaje cifrado encontrado:")
    print(mensaje)

    print("\n" + "=" * 60)
    print("POSIBLES DESCIFRADOS")
    print("=" * 60)

    mejor_desplazamiento = 0
    mejor_puntuacion = -1.0
    mejor_texto = ""

    # Probar todos los desplazamientos
    for desplazamiento in range(26):

        descifrado = cesar_decrypt(mensaje, desplazamiento)
        puntuacion = calcular_puntuacion_espanol(descifrado)

        # Si esta opción tiene mayor probabilidad en español, se guarda como la mejor
        if puntuacion > mejor_puntuacion:
            mejor_puntuacion = puntuacion
            mejor_desplazamiento = desplazamiento
            mejor_texto = descifrado

        # Se imprimen todas en texto normal
        print(f"Desplazamiento {desplazamiento:2d}: {descifrado}")

    # Imprimir resumen final con el mensaje más probable destacado en verde
    print("\n" + "=" * 60)
    print("MENSAJE MÁS PROBABLE")
    print("=" * 60)
    print(
        f"Desplazamiento {mejor_desplazamiento:2d}: "
        f"{GREEN}{BOLD}{mejor_texto}{RESET}"
    )


if __name__ == "__main__":
    main()
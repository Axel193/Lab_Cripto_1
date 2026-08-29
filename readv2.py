#!/usr/bin/env python3

from scapy.all import rdpcap, IP, ICMP, Raw
import sys

VERDE = "\033[92m"
RESET = "\033[0m"

def descifrar_cesar(texto, corrimiento):
    resultado = ""
    for caracter in texto:
        if 'A' <= caracter <= 'Z':
            resultado += chr((ord(caracter) - ord('A') - corrimiento) % 26 + ord('A'))
        elif 'a' <= caracter <= 'z':
            resultado += chr((ord(caracter) - ord('a') - corrimiento) % 26 + ord('a'))
        else:
            resultado += caracter
    return resultado

def obtener_mensaje(archivo, ip_destino):
    paquetes = rdpcap(archivo)
    mensaje = ""
    for paquete in paquetes:
        if paquete.haslayer(IP) and paquete.haslayer(ICMP) and paquete.haslayer(Raw):
            if paquete[IP].dst == ip_destino and paquete[ICMP].type == 8:
                datos = paquete[Raw].load
                if len(datos) == 1:
                    try:
                        mensaje += datos.decode("utf-8")
                    except UnicodeDecodeError:
                        continue
    return mensaje

def puntuar_mensaje(texto):
    palabras = ["el", "la", "los", "las", "un", "una", "de", "del", "en", 
                "que", "es", "y", "para", "por", "con", "como", "hola", 
                "mensaje", "este", "esta", "tal"]
    return sum(1 for palabra in palabras if palabra in texto.lower().split())

if len(sys.argv) != 3:
    print('Uso: python3 readv2.py "captura.pcapng" "IP_DESTINO"')
    sys.exit(1)

try:
    mensaje_cifrado = obtener_mensaje(sys.argv[1], sys.argv[2])
except Exception as e:
    print(f"Error al leer el archivo: {e}")
    sys.exit(1)

if not mensaje_cifrado:
    print("No se encontraron paquetes ICMP Request válidos hacia esa IP.")
    sys.exit(1)

print(f"\nMensaje cifrado encontrado: {mensaje_cifrado}\n")
print("POSIBLES DESCIFRADOS")
print("-" * 40)

# Evaluar todas las posibilidades
posibilidades = [(puntuar_mensaje(descifrar_cesar(mensaje_cifrado, i)), i, descifrar_cesar(mensaje_cifrado, i)) for i in range(26)]
mejor_puntuacion = max(p[0] for p in posibilidades)

# Imprimir resultados
for puntuacion, corrimiento, mensaje in posibilidades:
    # Solo pintamos de verde si coincide con el mejor puntaje y tiene al menos una coincidencia real
    if puntuacion == mejor_puntuacion and mejor_puntuacion > 0:
        print(f"{VERDE}Desplazamiento {corrimiento:2d}: {mensaje}{RESET}")
    else:
        print(f"Desplazamiento {corrimiento:2d}: {mensaje}")
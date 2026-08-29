from scapy.all import rdpcap, ICMP
import sys


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


def main():

    if len(sys.argv) != 2:
        print("Uso: python3 readv2.py cesarCrip.pcapng")
        sys.exit(1)

    archivo = sys.argv[1]
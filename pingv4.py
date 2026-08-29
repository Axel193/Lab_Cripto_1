from scapy.all import IP, ICMP, Raw, send
import sys

if len(sys.argv) != 3:
    print('Uso: python3 pingv4.py "texto" IP_DESTINO')
    sys.exit(1)

texto = sys.argv[1]
ip_destino = sys.argv[2]

print("Enviando caracteres mediante ICMP...")
print(f"Destino: {ip_destino}")
print(f"Caracteres a enviar: {len(texto)}")

for caracter in texto:

    paquete = (
        IP(dst=ip_destino)
        / ICMP(type=8, code=0)
        / Raw(load=caracter.encode("utf-8"))
    )

    send(paquete, verbose=False)

    print(f"Enviado: {repr(caracter)}")

print("Transmisión finalizada.")
from scapy.all import IP, ICMP, send
import sys
import time

if len(sys.argv) != 3:
    print('Uso: python3 pingv4.py "texto" IP_DESTINO')
    sys.exit(1)

texto = sys.argv[1]
ip_destino = sys.argv[2]

# Relleno estándar exigido por la rúbrica (ej. patrón de 0x10 a 0x37 o ceros)
padding_base = bytes(range(0x10, 0x38)) # Simula el payload clásico de un ping

seq_num = 1
ip_id = 0x0001

for caracter in texto:
    # Construcción del payload combinando el carácter cifrado y el padding requerido
    payload_icmph = caracter.encode("utf-8") + padding_base[:40] 

    paquete = (
        IP(dst=ip_destino, id=ip_id)
        / ICMP(type=8, code=0, id=0x0001, seq=seq_num)
        / payload_icmph
    )
    
    send(paquete, verbose=False)
    print(f"Enviado carácter '{caracter}' con seq={seq_num}")
    
    seq_num += 1
    ip_id += 1
    time.sleep(1) # Mantiene la ejecución cada 1 segundo exacto
from scapy.all import IP, ICMP, Raw, send

print("=== ENVÍO DE CARACTERES MEDIANTE ICMP ===")

destino = input("Ingrese la IP de destino: ")
mensaje = input("Ingrese el mensaje descifrado: ")

print("\nEnviando caracteres...\n")

for caracter in mensaje:
    paquete = (
        IP(dst=destino) /
        ICMP() /
        Raw(load=caracter.encode("utf-8"))
    )

    send(paquete, verbose=False)

    print(f"Enviado: '{caracter}'")

print("\nTodos los caracteres fueron enviados.")
import socket

# Configurado para el puerto 8080
PUERTO = 4444

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Permitir reutilizar el puerto si cerramos y abrimos rápido el script
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind(('0.0.0.0', PUERTO)) 
server.listen(1)
print(f"🚀 Servidor escuchando en el puerto {PUERTO}...")
print("Esperando conexión desde el iPhone...")

try:
    conn, addr = server.accept()
    print(f"✅ ¡CONECTADO! Dispositivo detectado en: {addr}")
    conn.send(b"Hola desde la PC! Escribe un mensaje secreto:\n")

    while True:
        data = conn.recv(1024)
        if not data: 
            break
        # Mostramos lo que llega
        mensaje = data.decode('utf-8', errors='ignore')
        print(f"📩 Mensaje recibido: {mensaje.strip()}")
except KeyboardInterrupt:
    print("\nServidor detenido por el usuario.")
finally:
    server.close()
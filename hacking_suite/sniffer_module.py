import socket
import threading
from scapy.all import sniff, IP, Raw, wrpcap
import os

def iniciar_intercepcion(iface, puerto, tiempo, carpeta, callback):
    paquetes = []
    ruta_pcap = os.path.join(carpeta, "captura.pcap")

    def run_server():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(('0.0.0.0', puerto))
            server.listen(1)
            callback(f"🚀 Servidor escuchando en puerto {puerto}...")
            conn, addr = server.accept()
            callback(f"✅ iPhone conectado: {addr}")
            conn.send(b"Bienvenido al Servidor Seguro. Escribe tu mensaje:\n")
            while True:
                data = conn.recv(1024)
                if not data: break
                msg = data.decode('utf-8', errors='ignore').strip()
                callback(f"📩 Servidor recibió: {msg}")
        except Exception as e:
            callback(f"❌ Error Servidor: {e}")
        finally:
            server.close()

    def run_sniffer():
        def procesar(pkt):
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                if payload:
                    callback(f"🕵️‍♂️ [INTERCEPTADO]: {payload}")
                    paquetes.append(pkt)

        callback(f"📡 Sniffer activo en {iface}...")
        sniff(iface=iface, timeout=tiempo, filter=f"tcp port {puerto}", prn=procesar)
        if paquetes:
            wrpcap(ruta_pcap, paquetes)
            callback(f"💾 Guardado en {ruta_pcap}")

    threading.Thread(target=run_server, daemon=True).start()
    threading.Thread(target=run_sniffer, daemon=True).start()
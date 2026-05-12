import socket
import os
import re
from datetime import datetime

def obtener_ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def crear_carpeta_captura(nombre_base, directorio_base):
    if not os.path.exists(directorio_base):
        os.makedirs(directorio_base)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nombre_limpio = re.sub(r'[^\w\-_]', '_', nombre_base)
    ruta_carpeta = os.path.join(directorio_base, f"{timestamp}_{nombre_limpio}")
    os.makedirs(ruta_carpeta, exist_ok=True)
    return ruta_carpeta
#!/usr/bin/env python3
from scapy.all import sniff, wrpcap, IP
import sys
import time
import datetime

def formatear_hora(timestamp):
    """Convierte timestamp Unix a formato legible"""
    try:
        dt = datetime.datetime.fromtimestamp(timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    except:
        return str(timestamp)

if len(sys.argv) < 5:
    print("Uso: python3 sniffer_aux.py <interfaz> <tiempo> <archivo_pcap> <archivo_txt> [victim_ip]")
    sys.exit(1)

iface = sys.argv[1]
tiempo = int(sys.argv[2])
archivo_pcap = sys.argv[3]
archivo_txt = sys.argv[4]
victim_ip = sys.argv[5] if len(sys.argv) > 5 else ""

print(f"Capturando en {iface} durante {tiempo}s...")
if victim_ip:
    print(f"🎯 Modo ESPECÍFICO - Filtrando por IP: {victim_ip}")
else:
    print(f"📡 Modo GENERAL - Capturando todo el tráfico")
paquetes = []

def filtrar_paquete(pkt):
    if not victim_ip:
        return True
    if IP in pkt:
        ip = pkt[IP]
        return victim_ip in (ip.src, ip.dst)
    return False

def guardar_paquete(pkt):
    paquetes.append(pkt)

sniff(iface=iface, timeout=tiempo, prn=guardar_paquete, store=False, lfilter=filtrar_paquete)

wrpcap(archivo_pcap, paquetes)
print(f"Guardado {len(paquetes)} paquetes en {archivo_pcap}")

with open(archivo_txt, 'w', encoding='utf-8') as txt:
    txt.write(f"CAPTURA DE TRÁFICO - {time.ctime()}\n")
    txt.write(f"Interfaz: {iface}\n")
    txt.write(f"Duración: {tiempo} segundos\n")
    if victim_ip:
        txt.write(f"🎯 Modo ESPECÍFICO - Filtro por IP: {victim_ip}\n")
    else:
        txt.write(f"📡 Modo GENERAL - Todo el tráfico\n")
    txt.write(f"Total paquetes: {len(paquetes)}\n")
    txt.write("=" * 80 + "\n\n")
    
    for idx, pkt in enumerate(paquetes, 1):
        txt.write(f"Paquete #{idx}\n")
        txt.write(f"  Hora (Unix): {pkt.time}\n")
        txt.write(f"  Hora (local): {formatear_hora(pkt.time)}\n")
        txt.write(f"  Resumen: {pkt.summary()}\n")
        if pkt.haslayer('IP'):
            ip = pkt['IP']
            txt.write(f"  IP: {ip.src} -> {ip.dst}\n")
        if pkt.haslayer('TCP'):
            tcp = pkt['TCP']
            txt.write(f"  TCP: puerto {tcp.sport} -> {tcp.dport}\n")
        if pkt.haslayer('UDP'):
            udp = pkt['UDP']
            txt.write(f"  UDP: puerto {udp.sport} -> {udp.dport}\n")
        if pkt.haslayer('Raw'):
            raw = bytes(pkt['Raw'].load)
            txt.write(f"  Datos HEX: {raw[:100].hex()}\n")
            try:
                texto = raw.decode('utf-8', errors='replace')
                if texto.strip() and any(c.isprintable() for c in texto):
                    txt.write(f"  Datos TXT: {texto[:200]}...\n")
                else:
                    txt.write(f"  Datos TXT: (datos binarios o encriptados)\n")
            except:
                txt.write(f"  Datos TXT: (no se pudo decodificar)\n")
        txt.write("\n")

print(f"✅ Información detallada guardada en {archivo_txt}")

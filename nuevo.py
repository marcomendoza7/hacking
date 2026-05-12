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
from scapy.all import sniff, wrpcap, IP, TCP, Raw

# --- CONFIGURACIÓN DE DIRECTORIOS ---
CAPTURAS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "capturas_sniffer")
if not os.path.exists(CAPTURAS_DIR):
    os.makedirs(CAPTURAS_DIR)

# --- FUNCIONES DE APOYO ---
def obtener_ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def generar_contrasena(longitud):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(longitud))

def crear_carpeta_captura(nombre_base):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nombre_limpio = re.sub(r'[^\w\-_]', '_', nombre_base)
    ruta = os.path.join(CAPTURAS_DIR, f"{timestamp}_{nombre_limpio}")
    if not os.path.exists(ruta): os.makedirs(ruta)
    return ruta

# --- LÓGICA DEL SNIFFER INTEGRADO (REPORTE TXT + UN SOLO LOG) ---
def ejecutar_intercepcion_pro(iface, tiempo, nombre_base, output_text, progress_bar, root):
    carpeta = crear_carpeta_captura(nombre_base)
    ruta_pcap = os.path.join(carpeta, f"{nombre_base}.pcap")
    ruta_txt = os.path.join(carpeta, f"{nombre_base}_reporte.txt")
    puerto = 4444
    paquetes_raw = [] # Para el reporte TXT y el PCAP

    def log_pantalla(msg):
        output_text.insert(tk.END, f"{msg}\n")
        output_text.see(tk.END)

    def formatear_paquete_txt(pkt):
        """Formato idéntico al de tu prueba exitosa"""
        ahora = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        src = pkt[IP].src
        dst = pkt[IP].dst
        data = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
        return f"[{ahora}] {src} -> {dst}: {data}"

    def servidor_thread():
        """Servidor mudo: no escribe mensajes recibidos en pantalla para evitar duplicidad"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(('0.0.0.0', puerto))
            server.listen(1)
            root.after(0, lambda: log_pantalla(f"🚀 Servidor escuchando... (Esperando iPhone en puerto {puerto})"))
            conn, addr = server.accept()
            root.after(0, lambda: log_pantalla(f"✅ ¡IPHONE CONECTADO! Origen: {addr[0]}"))
            conn.send(b"Hola desde la PC! Escribe un mensaje secreto:\n")
            while True:
                data = conn.recv(1024)
                if not data: break
                # El servidor procesa pero NO hace log para no duplicar con el sniffer
            conn.close()
        except Exception as e:
            root.after(0, lambda: log_pantalla(f"❌ Error Servidor: {e}"))
        finally:
            server.close()

    def sniffer_thread():
        """El Sniffer es el único encargado de mostrar datos y generar el reporte"""
        root.after(0, lambda: log_pantalla(f"📡 Sniffer activo en {iface} (Filtrando puerto {puerto})..."))
        
        def procesar(pkt):
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                if payload:
                    # Log en pantalla (único texto visible)
                    root.after(0, lambda: log_pantalla(f"🕵️‍♂️ [INTERCEPTADO]: {payload}"))
                    paquetes_raw.append(pkt)

        # Captura paquetes durante el tiempo especificado
        sniff(iface=iface, timeout=tiempo, filter=f"tcp port {puerto}", prn=procesar, store=False)
        
        # Guardar archivos al finalizar
        if paquetes_raw:
            wrpcap(ruta_pcap, paquetes_raw) # Guardar PCAP
            
            with open(ruta_txt, 'w', encoding='utf-8') as f:
                f.write(f"--- REPORTE INTERCEPCIÓN PUERTO {puerto} ---\n")
                f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for p in paquetes_raw:
                    f.write(formatear_paquete_txt(p) + "\n")
            
            root.after(0, lambda: log_pantalla(f"\n✅ REPORTE TXT GUARDADO: {os.path.basename(ruta_txt)}"))
            root.after(0, lambda: log_pantalla(f"💾 PCAP GUARDADO: {os.path.basename(ruta_pcap)}"))
            root.after(0, lambda: log_pantalla(f"📁 Carpeta: {carpeta}"))
        else:
            root.after(0, lambda: log_pantalla("\n⚠️ No se capturaron datos con carga útil (Raw)."))
        
        root.after(0, lambda: log_pantalla("🏁 Captura finalizada."))

    # Lanzar hilos
    threading.Thread(target=servidor_thread, daemon=True).start()
    threading.Thread(target=sniffer_thread, daemon=True).start()

    # Hilo de la barra de progreso
    def update_progress():
        progress_bar['value'] = 0
        for i in range(tiempo):
            time.sleep(1)
            progress_bar['value'] = (i+1)/tiempo * 100
        progress_bar['value'] = 0

    threading.Thread(target=update_progress, daemon=True).start()

# --- CLASE PRINCIPAL ---
class HackingSuite:
    def __init__(self, root):
        self.root = root
        self.root.title("Hacking Ético Suite - Herramientas de Seguridad")
        self.root.geometry("900x800")
        self.root.configure(bg='#2c3e50')
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook.Tab', font=('Arial', 12, 'bold'))
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Pestañas
        self.tab_scan = ttk.Frame(self.notebook); self.notebook.add(self.tab_scan, text="🔍 Escaneo")
        self.tab_pass = ttk.Frame(self.notebook); self.notebook.add(self.tab_pass, text="🔐 Passwords")
        self.tab_sniff = ttk.Frame(self.notebook); self.notebook.add(self.tab_sniff, text="📡 Sniffer iPhone")
        self.tab_key = ttk.Frame(self.notebook); self.notebook.add(self.tab_key, text="⌨️ Keylogger")

        self.setup_scan_tab()
        self.setup_password_tab()
        self.setup_sniffer_tab()
        self.setup_keylogger_tab()

    def setup_scan_tab(self):
        frame = ttk.Frame(self.tab_scan, padding=10); frame.pack(fill=tk.BOTH)
        ttk.Label(frame, text="IP:").grid(row=0, column=0)
        self.scan_host = ttk.Entry(frame); self.scan_host.insert(0, "127.0.0.1"); self.scan_host.grid(row=0, column=1)
        ttk.Label(frame, text="Puertos:").grid(row=1, column=0)
        self.scan_ports = ttk.Entry(frame); self.scan_ports.insert(0, "22,80,443,4444"); self.scan_ports.grid(row=1, column=1)
        self.scan_output = scrolledtext.ScrolledText(frame, height=10, width=80); self.scan_output.grid(row=3, column=0, columnspan=2)
        ttk.Button(frame, text="Escanear", command=self.run_scan).grid(row=2, column=0, columnspan=2)

    def run_scan(self):
        h = self.scan_host.get(); r = self.scan_ports.get()
        threading.Thread(target=lambda: self.scan_logic(h, r), daemon=True).start()

    def scan_logic(self, host, rango):
        nm = nmap.PortScanner()
        try:
            self.scan_output.insert(tk.END, f"Escaneando {host}...\n")
            nm.scan(host, rango)
            for p in nm[host].all_protocols():
                for port in nm[host][p]:
                    state = nm[host][p][port]['state']
                    self.scan_output.insert(tk.END, f"Puerto {port}: {state}\n")
        except Exception as e: self.scan_output.insert(tk.END, f"Error: {e}\n")

    def setup_password_tab(self):
        frame = ttk.Frame(self.tab_pass, padding=10); frame.pack(fill=tk.BOTH)
        ttk.Label(frame, text="Longitud:").pack()
        self.pass_len = ttk.Entry(frame); self.pass_len.insert(0, "12"); self.pass_len.pack()
        self.pass_output = tk.Listbox(frame, height=10, width=60); self.pass_output.pack(pady=10)
        ttk.Button(frame, text="Generar", command=self.gen_pass).pack()

    def gen_pass(self):
        p = generar_contrasena(int(self.pass_len.get()))
        self.pass_output.insert(tk.END, f"Password: {p}")

    def setup_sniffer_tab(self):
        frame = ttk.Frame(self.tab_sniff, padding=10); frame.pack(fill=tk.BOTH)
        ttk.Label(frame, text="Interfaz de Red (ej: wlp2s0):").pack()
        self.sniff_iface = ttk.Entry(frame); self.sniff_iface.insert(0, "wlp2s0"); self.sniff_iface.pack()
        ttk.Label(frame, text="Tiempo de Captura (segundos):").pack()
        self.sniff_time = ttk.Entry(frame); self.sniff_time.insert(0, "60"); self.sniff_time.pack()
        self.sniff_progress = ttk.Progressbar(frame, length=400, mode='determinate'); self.sniff_progress.pack(pady=10)
        self.sniff_output = scrolledtext.ScrolledText(frame, height=20, width=90, bg="black", fg="lime")
        self.sniff_output.pack(pady=10)
        ttk.Button(frame, text="🚀 INICIAR INTERCEPCIÓN IPHONE", command=self.start_sniff_pro).pack()

    def start_sniff_pro(self):
        iface = self.sniff_iface.get()
        tiempo = int(self.sniff_time.get())
        self.sniff_output.delete(1.0, tk.END)
        ejecutar_intercepcion_pro(iface, tiempo, "ataque_iphone", self.sniff_output, self.sniff_progress, self.root)

    def setup_keylogger_tab(self):
        frame = ttk.Frame(self.tab_key, padding=10); frame.pack(fill=tk.BOTH)
        ttk.Label(frame, text="Keylogger Web (Node.js):").pack()
        self.key_output = scrolledtext.ScrolledText(frame, height=15); self.key_output.pack(pady=10)
        ttk.Button(frame, text="Abrir Localhost:3000", command=lambda: webbrowser.open("http://localhost:3000")).pack()

if __name__ == "__main__":
    root = tk.Tk()
    app = HackingSuite(root)
    root.mainloop()
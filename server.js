// server.js
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;
app.use(express.static('public'));

app.use(cors());
app.use(express.json());

const riderLocations = {};

// =========================================================
// API Endpoint'leri
// =========================================================

// POST /api/order endpoint'i: Android uygulamasından ve şimdi POS sisteminden de sipariş verilerini almak için
app.post('/api/order', (req, res) => {
    const orderData = req.body;
    
    // Gelen siparişin nereden geldiğini kontrol et (Android uygulaması veya POS)
    const platform = orderData.platform || 'Android App'; // Varsayılan olarak Android App

    console.log(`[${new Date().toLocaleTimeString()}] Yeni sipariş alındı - Platform: ${platform}, Masa/Sipariş No: ${orderData.tableName || orderData.orderId}, Toplam: ${orderData.totalAmount} TL`);

    // Sipariş verilerini bir veritabanına kaydedebilirsiniz.
    // Örneğin: saveOrderToDatabase(orderData);

    // Web arayüzüne (mutfak/kasa ekranı) gerçek zamanlı bildirim gönder
    // orderData'ya 'platform' bilgisini ekleyerek, web arayüzünde hangi platformdan geldiğini gösterebiliriz.
    io.emit('newOrder', { ...orderData, platform: platform });

    // Bildirim zili çalması için ayrı bir olay gönder
    io.emit('notificationSound', { play: true });

    res.status(200).json({ message: 'Sipariş başarıyla alındı ve web istemcilere iletildi.' });
});

// GET / endpoint'i: Sunucunun çalışıp çalışmadığını kontrol etmek ve index.html'i servis etmek için
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// =========================================================
// Socket.IO Olay Dinleyicileri
// =========================================================

io.on('connection', (socket) => {
    console.log(`[${new Date().toLocaleTimeString()}] Yeni bir istemci bağlandı: ${socket.id}`);

    socket.on('requestCurrentRiderLocations', () => {
        console.log(`[${new Date().toLocaleTimeString()}] Web istemcisi ${socket.id} mevcut motorcu konumlarını istedi.`);
        socket.emit('currentRiderLocations', riderLocations);
    });

    socket.on('riderLocationUpdate', (locationData) => {
        const { riderId, latitude, longitude, timestamp, speed, bearing, accuracy } = locationData;
        console.log(`[${new Date().toLocaleTimeString()}] Motorcu Konumu Güncellendi - ID: ${riderId}, Lat: ${latitude}, Lng: ${longitude}`);

        riderLocations[riderId] = {
            latitude,
            longitude,
            timestamp,
            speed,
            bearing,
            accuracy
        };

        io.emit('newRiderLocation', locationData);
    });

    socket.on('disconnect', () => {
        console.log(`[${new Date().toLocaleTimeString()}] Bir istemci bağlantısı kesildi: ${socket.id}`);
    });

    // İstemciden gelen "sipariş tamamlandı" olayını dinle (web arayüzündeki "Hazırlandı/Tamamlandı" butonu)
    socket.on('orderCompleted', (data) => {
        console.log(`[${new Date().toLocaleTimeString()}] Web istemcisi siparişi tamamladı: Platform: ${data.platform}, Sipariş No: ${data.orderId}, Toplam: ${data.totalAmount} TL`);
        // Burada siparişin durumunu veritabanında "tamamlandı" olarak işaretleyebilirsiniz.
        // Örneğin: updateOrderStatus(data.orderId, 'completed');
        // İlgili sipariş kartını kaldıran kısım zaten client tarafında çalışıyor.
    });

    // POS tarafından gönderilen yeni siparişleri dinle (eğer Socket.IO ile gönderilecekse)
    // Şu an için POS siparişleri '/api/order' üzerinden HTTP POST ile gönderilecek,
    // ancak ilerde Socket.IO üzerinden de göndermek isterseniz bu event kullanılabilir.
    socket.on('posOrder', (orderData) => {
        console.log(`[${new Date().toLocaleTimeString()}] POS üzerinden yeni sipariş alındı (Socket.IO) - Masa: ${orderData.tableName}, Toplam: ${orderData.totalAmount} TL`);
        io.emit('newOrder', { ...orderData, platform: 'POS' }); // Mutfak ekranına gönder
        io.emit('notificationSound', { play: true }); // Mutfak ekranında ses çal
    });
});

server.listen(PORT, () => {
    console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor`);
    console.log(`API endpoint: http://localhost:${PORT}/api/order`);
    console.log(`Web istemcileri ${PORT} portuna bağlanmalı.`);
});

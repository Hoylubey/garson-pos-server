// server.js
const express = require('express'); // Express framework'ünü dahil et
const http = require('http'); // Node.js'in dahili HTTP modülünü dahil et (Socket.IO için gerekli)
const { Server } = require("socket.io"); // Socket.IO sunucusunu dahil et
const cors = require('cors'); // CORS middleware'ini dahil et

// Express uygulamasını oluştur
const app = express();
// HTTP sunucusunu oluştur (Express uygulamasını kullanarak)
const server = http.createServer(app);

// Socket.IO sunucusunu HTTP sunucusu üzerine kur
const io = new Server(server, {
    cors: {
        origin: "*", // TÜM KÖKENLERDEN gelen isteklere izin ver (Geliştirme için iyi, Üretimde güvende olmak için belirli URL'lerle değiştirin!)
        methods: ["GET", "POST"] // İzin verilen HTTP metotları
    }
});

const PORT = process.env.PORT || 3000; // Sunucunun çalışacağı portu belirle (varsayılan 3000)
app.use(express.static('public'));
// Middleware'ler (istekleri işlemeden önce çalışan fonksiyonlar)
app.use(cors()); // CORS'u etkinleştir: Bu, farklı kaynaklardan (Android uygulamanız gibi) gelen isteklerin kabul edilmesini sağlar.
app.use(express.json()); // JSON body parsing'i etkinleştir: Bu, Android'den gelen JSON verisini req.body'ye dönüştürür.

// =========================================================
// API Endpoint'leri
// =========================================================

// POST /api/order endpoint'i: Android uygulamasından sipariş verilerini almak için
app.post('/api/order', (req, res) => {
    const orderData = req.body; // Gelen JSON verisi
    console.log(`[${new Date().toLocaleTimeString()}] Yeni sipariş alındı - Masa: ${orderData.tableName}, Toplam: ${orderData.totalAmount} TL`);

    // Bu noktada sipariş verilerini bir veritabanına kaydedebilirsiniz.
    // Örneğin: saveOrderToDatabase(orderData);

    // Web arayüzüne (mutfak/kasa ekranı) gerçek zamanlı bildirim gönder
    io.emit('newOrder', orderData); // 'newOrder' adında bir olay ve sipariş verilerini gönder

    // Bildirim zili çalması için ayrı bir olay da gönderebiliriz (web arayüzünde dinlenecek)
    io.emit('notificationSound', { play: true });

    // Android uygulamasına başarılı yanıt gönder
    res.status(200).json({ message: 'Sipariş başarıyla alındı ve web istemcilere iletildi.' });
});

// GET / endpoint'i: Sunucunun çalışıp çalışmadığını kontrol etmek için basit bir yanıt
app.get('/', (req, res) => {
    res.send('Garson POS Sunucusu Çalışıyor! API endpointi: /api/order');
});

// =========================================================
// Socket.IO Olay Dinleyicileri
// =========================================================

// Bir web istemcisi bağlandığında
io.on('connection', (socket) => {
    console.log(`[${new Date().toLocaleTimeString()}] Yeni bir web istemcisi bağlandı: ${socket.id}`);

    // Web istemcisi bağlantısı kesildiğinde
    socket.on('disconnect', () => {
        console.log(`[${new Date().toLocaleTimeString()}] Bir web istemcisi bağlantısı kesildi: ${socket.id}`);
    });

    // İstemciden gelebilecek diğer olayları burada dinleyebilirsiniz (örneğin sipariş onaylama)
    // socket.on('orderReceivedAck', (orderId) => {
    //     console.log(`Web istemcisi siparişi onayladı: ${orderId}`);
    // });
});

// Sunucuyu belirtilen portta dinlemeye başla
server.listen(PORT, () => {
    console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor`);
    console.log(`API endpoint: http://localhost:${PORT}/api/order`);
    console.log(`Web istemcileri ${PORT} portuna bağlanmalı.`);
});
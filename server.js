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
app.use(express.static('public')); // 'public' klasöründeki statik dosyaları servis et (index.html için)

// Middleware'ler (istekleri işlemeden önce çalışan fonksiyonlar)
app.use(cors()); // CORS'u etkinleştir: Bu, farklı kaynaklardan (Android uygulamanız gibi) gelen isteklerin kabul edilmesini sağlar.
app.use(express.json()); // JSON body parsing'i etkinleştir: Bu, Android'den gelen JSON verisini req.body'ye dönüştürür.

// Motorcu konumlarını saklamak için obje
// Anahtar: riderId, Değer: { latitude, longitude, timestamp, speed, bearing, accuracy }
const riderLocations = {};

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
    // index.html dosyasını direkt olarak public klasöründen servis etmek için
    res.sendFile(__dirname + '/public/index.html');
});

// =========================================================
// Socket.IO Olay Dinleyicileri
// =========================================================

// Bir istemci (web veya Android) bağlandığında
io.on('connection', (socket) => {
    console.log(`[${new Date().toLocaleTimeString()}] Yeni bir istemci bağlandı: ${socket.id}`);

    // Web istemcisi bağlandığında, mevcut tüm motorcu konumlarını gönder
    // Bu, tarayıcı yenilendiğinde veya ilk açıldığında motorcuları haritada gösterir
    socket.on('requestCurrentRiderLocations', () => {
        console.log(`[${new Date().toLocaleTimeString()}] Web istemcisi ${socket.id} mevcut motorcu konumlarını istedi.`);
        socket.emit('currentRiderLocations', riderLocations);
    });

    // Android uygulamasından gelen motorcu konum güncellemelerini dinle
    socket.on('riderLocationUpdate', (locationData) => {
        const { riderId, latitude, longitude, timestamp, speed, bearing, accuracy } = locationData;
        console.log(`[${new Date().toLocaleTimeString()}] Motorcu Konumu Güncellendi - ID: ${riderId}, Lat: ${latitude}, Lng: ${longitude}`);

        // Konum verisini bellekte sakla (veya bir veritabanına kaydedin)
        riderLocations[riderId] = {
            latitude,
            longitude,
            timestamp,
            speed,
            bearing,
            accuracy
        };

        // Tüm bağlı web istemcilerine yeni konumu yayınla
        io.emit('newRiderLocation', locationData);
    });

    // İstemci bağlantısı kesildiğinde
    socket.on('disconnect', () => {
        console.log(`[${new Date().toLocaleTimeString()}] Bir istemci bağlantısı kesildi: ${socket.id}`);
        // Eğer belirli bir riderId'ye sahip bir motorcu bağlantısı kesilirse,
        // ilgili marker'ı haritadan kaldırmak için istemcilere bir olay gönderebiliriz.
        // Ancak Android uygulamasının her zaman aktif olması bekleniyorsa bu şimdilik gerekli değil.
    });

    // İstemciden gelebilecek diğer olayları burada dinleyebilirsiniz (örneğin sipariş onaylama)
    socket.on('orderPaid', (data) => {
        console.log(`[${new Date().toLocaleTimeString()}] Web istemcisi siparişi ödendi olarak işaretledi: Masa ${data.tableName}, Toplam ${data.totalAmount} TL`);
        // İlgili siparişi veritabanında "ödendi" olarak işaretleyebiliriz.
        // Örneğin: updateOrderStatus(data.orderId, 'paid');
    });
});

// Sunucuyu belirtilen portta dinlemeye başla
server.listen(PORT, () => {
    console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor`);
    console.log(`API endpoint: http://localhost:${PORT}/api/order`);
    console.log(`Web istemcileri ${PORT} portuna bağlanmalı.`);
});

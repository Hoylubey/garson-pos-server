const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const admin = require('firebase-admin'); // Firebase Admin SDK
const path = require('path');
const Database = require('better-sqlite3'); // better-sqlite3 kütüphanesini import edin
const { v4: uuidv4 } = require('uuid'); // Benzersiz ID'ler için uuid kütüphanesi

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
app.use(express.json()); // Gelen JSON isteklerini ayrıştırmak için
app.use(express.static('public'));

// 🔥 Firebase Admin SDK Başlat
// Kendi 'serviceAccountKey.json' dosyanızın yolunu buraya girin.
// Bu dosyanın sunucu dosyanızla aynı dizinde olması önerilir.
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

// --- SQLite Veritabanı Entegrasyonu ---
const dbPath = path.join(__dirname, 'garson_pos.db'); // Veritabanı dosya yolu
const db = new Database(dbPath); // Veritabanı bağlantısı oluştur

// Ayarlar tablosunu oluştur (eğer yoksa)
db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
`);

// Orders tablosunu oluştur (eğer yoksa) - YENİ EKLENDİ
db.exec(`
    CREATE TABLE IF NOT EXISTS orders (
        orderId TEXT PRIMARY KEY,
        masaId TEXT NOT NULL,
        masaAdi TEXT NOT NULL,
        sepetItems TEXT NOT NULL, -- JSON string olarak saklayacağız
        toplamFiyat REAL NOT NULL,
        timestamp TEXT NOT NULL, -- ISO string olarak saklayacağız
        status TEXT NOT NULL DEFAULT 'pending' -- 'pending', 'paid', 'cancelled'
    )
`, (err) => { // better-sqlite3 ile callback kullanmak yerine try/catch bloğu daha yaygındır
    if (err) {
        console.error('Orders tablosu oluşturma hatası:', err.message);
    } else {
        console.log('Orders tablosu hazır.');
    }
});

// Başlangıçta sipariş alım durumunu veritabanından oku veya varsayılan değerle başlat
const initialStatus = db.prepare("SELECT value FROM settings WHERE key = 'isOrderTakingEnabled'").get();
if (!initialStatus) {
    db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").run('isOrderTakingEnabled', 'true');
    console.log("Sipariş alımı durumu veritabanına varsayılan olarak 'true' eklendi.");
}

// 🔐 Token Set'i (Şimdilik Set olarak kalacak, kalıcı depolama için veritabanına taşınabilir)
const fcmTokens = new Set();

// 🌍 Rider Lokasyonları
const riderLocations = {};
// YENİ EKLENEN: socket.id'den riderId'ye eşleme
const socketToRiderId = {}; 

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

// Sipariş durumu sorgulama endpoint'i
app.get('/api/order-status', (req, res) => {
    try {
        const result = db.prepare("SELECT value FROM settings WHERE key = 'isOrderTakingEnabled'").get();
        const enabled = result && result.value === 'true';
        res.json({ enabled: enabled });
    } catch (error) {
        console.error('Veritabanından sipariş durumu okunurken hata:', error);
        res.status(500).json({ error: 'Sipariş durumu sorgulanırken bir hata oluştu.' });
    }
});

// Sipariş durumunu değiştirme endpoint'i
app.post('/api/set-order-status', (req, res) => {
    const { enabled } = req.body;
    if (typeof enabled === 'boolean') {
        const statusValue = enabled ? 'true' : 'false';
        try {
            db.prepare("REPLACE INTO settings (key, value) VALUES (?, ?)").run('isOrderTakingEnabled', statusValue);
            console.log(`Sipariş alımı durumu veritabanında değiştirildi: ${enabled ? 'AÇIK' : 'KAPALI'}`);
            // Durum değiştiğinde tüm bağlı istemcilere bildir
            io.emit('orderTakingStatusChanged', { enabled: enabled }); // YENİ EKLENDİ
            res.json({ message: 'Sipariş durumu başarıyla güncellendi.', newStatus: enabled });
        } catch (error) {
            console.error('Veritabanına sipariş durumu yazılırken hata:', error);
            res.status(500).json({ error: 'Sipariş durumu güncellenirken bir hata oluştu.' });
        }
    } else {
        res.status(400).json({ error: 'Geçersiz parametre. "enabled" bir boolean olmalıdır.' });
    }
});

// 📦 SIPARIŞ AL (API Endpoint'i)
app.post('/api/order', async (req, res) => {
    try {
        // Sipariş alım durumunu veritabanından kontrol et
        const orderStatus = db.prepare("SELECT value FROM settings WHERE key = 'isOrderTakingEnabled'").get();
        const isOrderTakingEnabled = orderStatus && orderStatus.value === 'true';

        if (!isOrderTakingEnabled) {
            return res.status(403).json({ error: 'Sipariş alımı şu anda kapalıdır.' });
        }

        const orderData = req.body;

        // Uygulamadan gelen JSON anahtarları ile eşleşecek şekilde düzeltildi
        const masaId = orderData.masaId;
        const masaAdi = orderData.masaAdi;
        const toplamFiyat = orderData.toplamFiyat;
        const sepetItems = orderData.sepetItems; // Uygulamadan 'sepetItems' olarak geliyor

        // Gelen veriyi konsola yazdırma (hata ayıklama için çok önemli)
        console.log(`[${new Date().toLocaleTimeString()}] Gelen Sipariş Detayları:`);
        console.log(`Masa ID: ${masaId}`);
        console.log(`Masa Adı: ${masaAdi}`);
        console.log(`Toplam Fiyat: ${toplamFiyat} TL`);
        console.log('Sepet Ürünleri:', JSON.stringify(sepetItems, null, 2)); // Daha okunur format

        const orderId = uuidv4(); // Benzersiz bir sipariş ID'si oluştur
        const timestamp = new Date().toISOString(); // ISO formatında zaman damgası

        // Siparişi SQLite veritabanına kaydet
        // sepetItems objesini JSON stringe çevirerek sakla
        const sepetItemsJson = JSON.stringify(sepetItems);

        db.prepare(`INSERT INTO orders (orderId, masaId, masaAdi, sepetItems, toplamFiyat, timestamp, status) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
            orderId,
            masaId,
            masaAdi,
            sepetItemsJson,
            toplamFiyat,
            timestamp,
            'pending'
        );
        console.log(`Yeni sipariş SQLite'a kaydedildi. ID: ${orderId}`);

        // Web'e gönderilecek sipariş objesini oluştur (sepetItems parse edilmiş haliyle)
        const newOrderToSend = {
            orderId: orderId, // Artık orderId kullanıyoruz
            masaId: masaId,
            masaAdi: masaAdi,
            sepetItems: sepetItems, // Zaten obje olarak var
            toplamFiyat: toplamFiyat,
            timestamp: timestamp,
            status: 'pending'
        };

        // Mutfak/Kasa ekranlarına yeni siparişi gönder
        io.emit('newOrder', newOrderToSend);
        io.emit('notificationSound', { play: true });

        // 🔔 Firebase Bildirim
        const message = {
            data: {
                masaAdi: masaAdi,
                siparisDetay: JSON.stringify(sepetItems),
                siparisId: orderId, // Gerçek orderId'yi kullan
                toplamTutar: toplamFiyat.toString()
            },
            notification: { // notification alanı eklendi
                title: `Yeni Sipariş: ${masaAdi}`,
                body: `Toplam: ${toplamFiyat} TL`
            }
        };

        if (fcmTokens.size > 0) {
            const tokensArray = Array.from(fcmTokens);
            try {
                const messagesToSend = tokensArray.map(token => ({ ...message, token }));
                const firebaseResponse = await admin.messaging().sendEachForMulticast(messagesToSend);
                console.log('🔥 FCM gönderildi:', firebaseResponse);
            } catch (error) {
                console.error('❌ FCM gönderimi HATA:', error);
                if (error.errorInfo) {
                    console.error('Firebase Error Info:', error.errorInfo);
                }
            }
        } else {
            console.log('📭 Kayıtlı cihaz yok, FCM gönderilmedi.');
        }

        res.status(200).json({ message: 'Sipariş işlendi.' });
    } catch (error) {
        console.error('Sipariş işlenirken veya bildirim gönderilirken hata:', error);
        res.status(500).json({ error: 'Sipariş işlenirken bir hata oluştu.' });
    }
});


// 🌐 GET /
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// 📡 SOCKET.IO
io.on('connection', (socket) => {
    console.log(`[${new Date().toLocaleTimeString()}] Yeni bağlantı: ${socket.id}`);

    // Mutfak/Kasa Ekranı bağlandığında mevcut siparişleri SQLite'tan çek ve gönder
    try {
        const activeOrders = db.prepare(`SELECT * FROM orders WHERE status = 'pending' ORDER BY timestamp ASC`).all();
        // Veritabanından gelen sepetItems JSON string olduğu için parse etmeliyiz
        const parsedOrders = activeOrders.map(order => {
            return {
                ...order,
                sepetItems: JSON.parse(order.sepetItems) // JSON stringi objeye çevir
            };
        });
        socket.emit('currentActiveOrders', parsedOrders);
        console.log(`[${new Date().toLocaleTimeString()}] Socket ${socket.id} için ${parsedOrders.length} aktif sipariş gönderildi.`);
    } catch (error) {
        console.error('Mevcut siparişleri SQLite\'tan çekerken hata:', error.message);
    }

    socket.on('requestCurrentRiderLocations', () => {
        socket.emit('currentRiderLocations', riderLocations);
    });

    socket.on('riderLocationUpdate', (locationData) => {
        const { riderId, latitude, longitude, timestamp, speed, bearing, accuracy } = locationData;
        riderLocations[riderId] = { latitude, longitude, timestamp, speed, bearing, accuracy };
        socketToRiderId[socket.id] = riderId; // YENİ EKLENEN: Socket ID'si ile Rider ID'sini eşle
        io.emit('newRiderLocation', locationData);
    });

    socket.on('orderPaid', (data) => {
        const { orderId } = data; // İstemciden orderId bekliyoruz
        console.log(`[${new Date().toLocaleTimeString()}] Sipariş ödendi olarak işaretlendi: ${orderId}`);

        try {
            const info = db.prepare(`UPDATE orders SET status = 'paid' WHERE orderId = ? AND status = 'pending'`).run(orderId);
            if (info.changes > 0) {
                console.log(`Sipariş (ID: ${orderId}) SQLite'ta ödendi olarak güncellendi.`);
                io.emit('orderPaidConfirmation', { orderId: orderId }); // Opsiyonel: mobil uygulamaya bildirim
                io.emit('removeOrderFromDisplay', { orderId: orderId }); // Mutfak/Kasa ekranından kaldır
            } else {
                console.warn(`Ödendi olarak işaretlenen sipariş (ID: ${orderId}) bulunamadı veya zaten ödenmiş.`);
            }
        } catch (error) {
            console.error('Siparişin durumunu güncellerken hata:', error.message);
        }
    });

    socket.on('disconnect', () => {
        console.log(`[${new Date().toLocaleTimeString()}] Bağlantı koptu: ${socket.id}`);
        const disconnectedRiderId = socketToRiderId[socket.id]; // İlgili riderId'yi al

        if (disconnectedRiderId) {
            delete riderLocations[disconnectedRiderId]; // riderLocations objesinden sil
            delete socketToRiderId[socket.id];    // Eşlemeden de sil
            console.log(`Motorcu ${disconnectedRiderId} bağlantısı kesildi. Haritadan kaldırılıyor.`);
            // İstemcilere bu motorcunun ayrıldığını bildir
            io.emit('riderDisconnected', disconnectedRiderId); // YENİ EKLENEN: Web'e motorcu ayrıldığını bildir
        }
    });
});

// 🚀 SERVER AÇ
server.listen(PORT, () => {
    console.log(`🟢 Sunucu ayakta: http://localhost:${PORT}`);
});

// Uygulama kapanırken veritabanı bağlantısını kapat
process.on('exit', () => {
    db.close();
    console.log('SQLite veritabanı bağlantısı kapatıldı.');
});

// Sunucuya kapatma sinyalleri geldiğinde düzgün kapanmayı sağla
process.on('SIGHUP', () => process.exit(1));
process.on('SIGINT', () => process.exit(1));
process.on('SIGTERM', () => process.exit(1));

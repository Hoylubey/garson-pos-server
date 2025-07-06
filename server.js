rconst express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const admin = require('firebase-admin'); // Firebase Admin SDK
const path = require('path');
const Database = require('better-sqlite3'); // better-sqlite3 kütüphanesini import edin

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

// 🔥 Firebase Admin SDK Başlat
// Kendi 'garson-uygulamasi-fcm-key.json' dosyanızın yolunu buraya girin.
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

// Başlangıçta sipariş alım durumunu veritabanından oku veya varsayılan değerle başlat
// Eğer 'isOrderTakingEnabled' anahtarı yoksa, varsayılan olarak 'true' (açık) ayarla.
const initialStatus = db.prepare("SELECT value FROM settings WHERE key = 'isOrderTakingEnabled'").get();
if (!initialStatus) {
    db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").run('isOrderTakingEnabled', 'true');
    console.log("Sipariş alımı durumu veritabanına varsayılan olarak 'true' eklendi.");
}

// 🔐 Token Set'i (Şimdilik Set olarak kalacak, kalıcı depolama için veritabanına taşınabilir)
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
            res.json({ message: 'Sipariş durumu başarıyla güncellendi.', newStatus: enabled });
        } catch (error) {
            console.error('Veritabanına sipariş durumu yazılırken hata:', error);
            res.status(500).json({ error: 'Sipariş durumu güncellenirken bir hata oluştu.' });
        }
    } else {
        res.status(400).json({ error: 'Geçersiz parametre. "enabled" bir boolean olmalıdır.' });
    }
});

// 📦 SIPARIŞ AL
app.post('/api/order', async (req, res) => {
    try {
        // Sipariş alım durumunu veritabanından kontrol et
        const orderStatus = db.prepare("SELECT value FROM settings WHERE key = 'isOrderTakingEnabled'").get();
        const isOrderTakingEnabled = orderStatus && orderStatus.value === 'true';

        if (!isOrderTakingEnabled) {
            return res.status(403).json({ error: 'Sipariş alımı şu anda kapalıdır.' });
        }

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
            //      title: `Yeni Sipariş: ${orderData.tableName}`,
            //      body: `Toplam: ${orderData.totalAmount} TL`
            // }
        };

        if (fcmTokens.size > 0) {
            const tokensArray = Array.from(fcmTokens);
            try {
                const firebaseResponse = await admin.messaging().sendEachForMulticast(message); // sendEachForMulticast kullanıldı
                console.log('🔥 FCM gönderildi:', firebaseResponse);
            } catch (error) {
                console.error('❌ FCM gönderimi HATA:', error);
            }
        } else {
            console.log('📭 Kayıtlı cihaz yok, FCM gönderilmedi.');
        }

        res.status(200).json({ message: 'Sipariş işlendi.' });
    } catch (error) {
        console.error('Sipariş veya bildirim gönderilirken hata:', error);
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

// Uygulama kapanırken veritabanı bağlantısını kapat
process.on('exit', () => {
    db.close();
    console.log('SQLite veritabanı bağlantısı kapatıldı.');
});

// Sunucuya kapatma sinyalleri geldiğinde düzgün kapanmayı sağla
process.on('SIGHUP', () => process.exit(1));
process.on('SIGINT', () => process.exit(1));
process.on('SIGTERM', () => process.exit(1));

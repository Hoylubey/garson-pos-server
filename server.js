const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const admin = require('firebase-admin'); // Firebase Admin SDK
const path = require('path');
const Database = require('better-sqlite3'); // better-sqlite3 kütüphanesini import edin
const { v4: uuidv4 } = require('uuid'); // Benzersiz ID'ler için uuid kütüphanesi
const bcrypt = require('bcryptjs'); // Şifreleme için bcryptjs kütüphanesi
const jwt = require('jsonwebtoken'); // JWT için jsonwebtoken kütüphanesi

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*", // Güvenlik için belirli domain'lerle sınırlamak daha iyidir üretimde
        methods: ["GET", "POST", "PUT", "DELETE"]
    }
});

const PORT = process.env.PORT || 3000;
// JWT için gizli anahtar. Üretimde bunu bir ortam değişkeninden okuyun!
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key_here_please_change_this_in_production';

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
try {
    db.exec(`
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    `);
    console.log('Settings tablosu hazır.');
} catch (err) {
    console.error('Settings tablosu oluşturma hatası:', err.message);
}

// Orders tablosunu oluştur (eğer yoksa)
try {
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
    `);
    console.log('Orders tablosu hazır.');
} catch (err) {
    console.error('Orders tablosu oluşturma hatası:', err.message);
}

// USERS tablosunu oluştur (eğer yoksa)
try {
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT, -- Motorcular için isim veya çalışan adı
            role TEXT NOT NULL DEFAULT 'employee' -- 'employee', 'admin', 'rider', 'garson'
        )
    `);
    console.log('Users tablosu hazır.');
    // Yönetici hesabının varlığını kontrol et ve yoksa ekle
    const adminUser = db.prepare("SELECT * FROM users WHERE username = 'hoylubey' AND role = 'admin'").get();
    if (!adminUser) {
        bcrypt.hash('Goldmaster150.', 10).then(hashedPassword => {
            db.prepare("INSERT INTO users (username, password, full_name, role) VALUES (?, ?, ?, ?)").run('hoylubey', hashedPassword, 'Yönetici', 'admin');
            console.log('Varsayılan yönetici hesabı oluşturuldu.');
        }).catch(err => {
            console.error('Yönetici şifresi hashlenirken hata:', err);
        });
    }
} catch (err) {
    console.error('Users tablosu oluşturma veya yönetici ekleme hatası:', err.message);
}

// PRODUCTS tablosunu oluştur (eğer yoksa)
try {
    db.exec(`
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            price REAL NOT NULL,
            category TEXT,
            description TEXT
        )
    `);
    console.log('Products tablosu hazır.');
    // Örnek ürünler ekle (sadece tablo boşsa)
    const existingProducts = db.prepare("SELECT COUNT(*) FROM products").get();
    if (existingProducts['COUNT(*)'] === 0) {
        const insert = db.prepare("INSERT INTO products (name, price, category) VALUES (?, ?, ?)");
        insert.run('Kokoreç Yarım Ekmek', 120.00, 'Ana Yemek');
        insert.run('Kokoreç Çeyrek Ekmek', 90.00, 'Ana Yemek');
        insert.run('Ayran Büyük', 25.00, 'İçecek');
        insert.run('Ayran Küçük', 15.00, 'İçecek');
        insert.run('Su', 10.00, 'İçecek');
        console.log('Örnek ürünler veritabanına eklendi.');
    }
} catch (err) {
    console.error('Products tablosu oluşturma veya örnek ürün ekleme hatası:', err.message);
}

// FCM Tokens tablosunu oluştur (eğer yoksa)
try {
    db.exec(`
        CREATE TABLE IF NOT EXISTS fcm_tokens (
            token TEXT PRIMARY KEY,
            userId INTEGER NOT NULL,
            username TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
        )
    `);
    console.log('FCM Tokens tablosu hazır.');
} catch (err) {
    console.error('FCM Tokens tablosu oluşturma hatası:', err.message);
}


// Başlangıçta sipariş alım durumunu veritabanından oku veya varsayılan değerle başlat
const initialStatus = db.prepare("SELECT value FROM settings WHERE key = 'isOrderTakingEnabled'").get();
if (!initialStatus) {
    db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").run('isOrderTakingEnabled', 'true');
    console.log("Sipariş alımı durumu veritabanına varsayılan olarak 'true' eklendi.");
}

// 🌍 Rider Lokasyonları (şimdilik hafızada kalacak, ancak JWT ile daha güvenli hale getirilecek)
// { "username": { id, username, full_name, role, latitude, longitude, timestamp, speed, bearing, accuracy }, ... }
const riderLocations = {};
const socketToUsername = {}; // { "socket.id": "username" }

// Middleware: JWT Doğrulama
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.status(401).json({ message: 'Yetkilendirme tokenı gerekli.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT doğrulama hatası:', err.message);
            return res.status(403).json({ message: 'Geçersiz veya süresi dolmuş token.' });
        }
        req.user = user; // Çözümlenmiş kullanıcı bilgilerini isteğe ekle
        next();
    });
}

// Middleware: Yönetici yetkisini kontrol et (JWT doğrulamasından sonra çalışır)
function isAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ message: 'Yetkisiz erişim. Yönetici yetkisi gerekli.' });
    }
}

// --- KULLANICI VE YÖNETİCİ GİRİŞ / KAYIT ENDPOINT'LERİ ---

// Genel Giriş Endpoint'i (Mobil uygulama tarafından kullanılacak)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Kullanıcı adı ve parola gerekli.' });
    }

    try {
        const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

        if (!user) {
            return res.status(401).json({ message: 'Geçersiz kullanıcı adı veya parola.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Geçersiz kullanıcı adı veya parola.' });
        }

        // JWT oluştur
        const token = jwt.sign(
            { id: user.id, username: user.username, full_name: user.full_name, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' } // Token 24 saat geçerli olacak
        );

        res.status(200).json({
            message: 'Giriş başarılı!',
            token: token,
            role: user.role,
            user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role }
        });

    } catch (error) {
        console.error('Genel giriş hatası:', error);
        res.status(500).json({ message: 'Giriş sırasında bir hata oluştu.' });
    }
});


// Çalışan (Motorcu) Kayıt Endpoint'i (Sadece Yönetici tarafından kullanılmalı, bu yüzden isAdmin middleware'i eklendi)
app.post('/api/register-employee', authenticateToken, isAdmin, async (req, res) => {
    const { username, password, full_name, role } = req.body;

    if (!username || !password || !full_name || !role) {
        return res.status(400).json({ message: 'Kullanıcı adı, parola, tam ad ve rol gerekli.' });
    }

    const validRoles = ['employee', 'admin', 'rider', 'garson'];
    if (!validRoles.includes(role)) {
        return res.status(400).json({ message: 'Geçersiz rol belirtildi.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const stmt = db.prepare("INSERT INTO users (username, password, full_name, role) VALUES (?, ?, ?, ?)");
        const info = stmt.run(username, hashedPassword, full_name, role);
        const newUser = { id: info.lastInsertRowid, username, full_name, role: role };

        // Yeni çalışan için de JWT oluşturabiliriz, ancak bu endpoint yönetici tarafından kullanıldığı için
        // genellikle yeni çalışanın doğrudan giriş yapması beklenir.
        // Yine de, eğer bir token dönmesi gerekiyorsa:
        const token = jwt.sign(
            { id: newUser.id, username: newUser.username, full_name: newUser.full_name, role: newUser.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'Çalışan başarıyla oluşturuldu.',
            token: token, // Yeni oluşturulan çalışan için token
            role: newUser.role,
            user: newUser
        });
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed')) {
            return res.status(409).json({ message: 'Bu kullanıcı adı zaten mevcut.' });
        }
        console.error('Çalışan kayıt hatası:', error);
        res.status(500).json({ message: 'Kayıt sırasında bir hata oluştu.' });
    }
});

// Çalışan (Motorcu) Giriş Endpoint'i ve Yönetici Giriş Endpoint'i artık genel /api/login tarafından ele alınıyor.
// Bu endpoint'ler kaldırılabilir veya özel roller için özelleştirilebilir.
// Şimdilik yorum satırı olarak bırakıyorum, genel login endpoint'i yeterli.
/*
app.post('/api/login-employee', async (req, res) => { ... });
app.post('/api/login-admin', async (req, res) => { ... });
*/

// --- ÜRÜN YÖNETİMİ ENDPOINT'LERİ (Sadece Yönetici) ---
// Tüm ürünleri getir (kimlik doğrulaması gerektirmez, menü herkese açık olabilir)
app.get('/api/products', (req, res) => {
    try {
        const products = db.prepare("SELECT * FROM products ORDER BY name ASC").all();
        res.status(200).json(products);
    }
    catch (error) {
        console.error('Ürünleri çekerken hata:', error);
        res.status(500).json({ message: 'Ürünler alınırken bir hata oluştu.' });
    }
});

// Ürün Ekle (Sadece Yönetici) - authenticateToken ve isAdmin middleware'leri eklendi
app.post('/api/products/add', authenticateToken, isAdmin, (req, res) => {
    const { name, price, category, description } = req.body;
    if (!name || price === undefined) {
        return res.status(400).json({ message: 'Ürün adı ve fiyatı gerekli.' });
    }
    try {
        const stmt = db.prepare("INSERT INTO products (name, price, category, description) VALUES (?, ?, ?, ?)");
        stmt.run(name, price, category || null, description || null);
        io.emit('menuUpdated'); // Tüm istemcilere menünün güncellendiğini bildir
        res.status(201).json({ message: 'Ürün başarıyla eklendi.', product: { name, price, category, description } });
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed')) {
            return res.status(409).json({ message: 'Bu ürün adı zaten mevcut.' });
        }
        console.error('Ürün ekleme hatası:', error);
        res.status(500).json({ message: 'Ürün eklenirken bir hata oluştu.' });
    }
});

// Ürün Güncelle (Sadece Yönetici) - authenticateToken ve isAdmin middleware'leri eklendi
app.put('/api/products/update/:id', authenticateToken, isAdmin, (req, res) => {
    const { id } = req.params;
    const { name, price, category, description } = req.body;
    if (!name && price === undefined && !category && !description) {
        return res.status(400).json({ message: 'Güncellenecek en az bir alan gerekli.' });
    }
    try {
        let updateFields = [];
        let params = [];
        if (name !== undefined) { updateFields.push('name = ?'); params.push(name); }
        if (price !== undefined) { updateFields.push('price = ?'); params.push(price); }
        if (category !== undefined) { updateFields.push('category = ?'); params.push(category); }
        if (description !== undefined) { updateFields.push('description = ?'); params.push(description); }

        if (updateFields.length === 0) {
            return res.status(400).json({ message: 'Güncellenecek geçerli bir alan yok.' });
        }

        params.push(id);
        const stmt = db.prepare(`UPDATE products SET ${updateFields.join(', ')} WHERE id = ?`);
        const info = stmt.run(...params);

        if (info.changes > 0) {
            io.emit('menuUpdated'); // Tüm istemcilere menünün güncellendiğini bildir
            res.status(200).json({ message: 'Ürün başarıyla güncellendi.', id: id });
        } else {
            res.status(404).json({ message: 'Ürün bulunamadı veya değişiklik yapılmadı.' });
        }
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed')) {
            return res.status(409).json({ message: 'Bu ürün adı zaten mevcut.' });
        }
        console.error('Ürün güncelleme hatası:', error);
        res.status(500).json({ message: 'Ürün güncellenirken bir hata oluştu.' });
    }
});

// Ürün Sil (Sadece Yönetici) - authenticateToken ve isAdmin middleware'leri eklendi
app.delete('/api/products/delete/:id', authenticateToken, isAdmin, (req, res) => {
    const { id } = req.params;
    try {
        const stmt = db.prepare("DELETE FROM products WHERE id = ?");
        const info = stmt.run(id);
        if (info.changes > 0) {
            io.emit('menuUpdated'); // Tüm istemcilere menünün güncellendiğini bildir
            res.status(200).json({ message: 'Ürün başarıyla silindi.', id: id });
        } else {
            res.status(404).json({ message: 'Ürün bulunamadı.' });
        }
    } catch (error) {
        console.error('Ürün silme hatası:', error);
        res.status(500).json({ message: 'Ürün silinirken bir hata oluştu.' });
    }
});

// ✅ TOKEN KAYDI (JWT ile birlikte kullanıcı bilgisi de kaydedilecek)
app.post('/api/register-fcm-token', authenticateToken, async (req, res) => {
    const { token } = req.body;
    const userId = req.user.id; // JWT'den alınan kullanıcı ID'si
    const username = req.user.username; // JWT'den alınan kullanıcı adı

    if (!token) {
        return res.status(400).send({ message: 'Token sağlanmadı.' });
    }

    try {
        // Token'ı veritabanına kaydet veya güncelle
        const stmt = db.prepare("REPLACE INTO fcm_tokens (token, userId, username, timestamp) VALUES (?, ?, ?, ?)");
        stmt.run(token, userId, username, new Date().toISOString());
        console.log(`FCM Token kayıt edildi/güncellendi: ${token} (User: ${username})`);
        res.status(200).send({ message: 'Token başarıyla kayıt edildi.' });
    } catch (error) {
        console.error('FCM Token veritabanına kaydedilirken hata:', error);
        res.status(500).send({ message: 'Token kaydedilirken bir hata oluştu.' });
    }
});

// 🔍 Tokenları listele (debug için, sadece yöneticiye açık olabilir)
app.get('/api/fcm-tokens', authenticateToken, isAdmin, (req, res) => {
    try {
        const tokens = db.prepare("SELECT * FROM fcm_tokens").all();
        res.status(200).json(tokens);
    } catch (error) {
        console.error('FCM tokenları çekilirken hata:', error);
        res.status(500).json({ message: 'FCM tokenları alınırken bir hata oluştu.' });
    }
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

// Sipariş durumunu değiştirme endpoint'i (Sadece Yönetici)
app.post('/api/set-order-status', authenticateToken, isAdmin, (req, res) => {
    const { enabled } = req.body;
    if (typeof enabled === 'boolean') {
        const statusValue = enabled ? 'true' : 'false';
        try {
            db.prepare("REPLACE INTO settings (key, value) VALUES (?, ?)").run('isOrderTakingEnabled', statusValue);
            console.log(`Sipariş alımı durumu veritabanında değiştirildi: ${enabled ? 'AÇIK' : 'KAPALI'}`);
            // Durum değiştiğinde tüm bağlı istemcilere bildir
            io.emit('orderTakingStatusChanged', { enabled: enabled });
            res.json({ message: 'Sipariş durumu başarıyla güncellendi.', newStatus: enabled });
        } catch (error) {
            console.error('Veritabanına sipariş durumu yazılırken hata:', error);
            res.status(500).json({ error: 'Sipariş durumu güncellenirken bir hata oluştu.' });
        }
    } else {
        res.status(400).json({ error: 'Geçersiz parametre. "enabled" bir boolean olmalıdır.' });
    }
});

// 📦 SIPARIŞ AL (API Endpoint'i) - Artık kimlik doğrulaması gerektiriyor
app.post('/api/order', authenticateToken, async (req, res) => {
    try {
        // Sipariş alım durumunu veritabanından kontrol et
        const orderStatus = db.prepare("SELECT value FROM settings WHERE key = 'isOrderTakingEnabled'").get();
        const isOrderTakingEnabled = orderStatus && orderStatus.value === 'true';

        if (!isOrderTakingEnabled) {
            return res.status(403).json({ error: 'Sipariş alımı şu anda kapalıdır.' });
        }

        const orderData = req.body;

        const masaId = orderData.masaId;
        const masaAdi = orderData.masaAdi;
        const toplamFiyat = orderData.toplamFiyat;
        const sepetItems = orderData.sepetItems;

        console.log(`[${new Date().toLocaleTimeString()}] Gelen Sipariş Detayları:`);
        console.log(`Masa ID: ${masaId}`);
        console.log(`Masa Adı: ${masaAdi}`);
        console.log(`Toplam Fiyat: ${toplamFiyat} TL`);
        console.log('Sepet Ürünleri:', JSON.stringify(sepetItems, null, 2));

        const orderId = uuidv4();
        const timestamp = new Date().toISOString();

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

        const newOrderToSend = {
            orderId: orderId,
            masaId: masaId,
            masaAdi: masaAdi,
            sepetItems: sepetItems,
            toplamFiyat: toplamFiyat,
            timestamp: timestamp,
            status: 'pending'
        };

        io.emit('newOrder', newOrderToSend);
        io.emit('notificationSound', { play: true });

        // 🔔 Firebase Bildirim
        const message = {
            data: {
                masaAdi: masaAdi,
                siparisDetay: JSON.stringify(sepetItems),
                siparisId: orderId,
                toplamTutar: toplamFiyat.toString()
            },
            notification: {
                title: `Yeni Sipariş: ${masaAdi}`,
                body: `Toplam: ${toplamFiyat} TL`
            }
        };

        // FCM tokenlarını veritabanından çek
        const tokensFromDb = db.prepare("SELECT token FROM fcm_tokens").all();
        const tokensArray = tokensFromDb.map(row => row.token);

        if (tokensArray.length > 0) {
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
        const parsedOrders = activeOrders.map(order => {
            try {
                return {
                    ...order,
                    sepetItems: JSON.parse(order.sepetItems) // JSON stringi objeye çevir
                };
            } catch (e) {
                console.error(`Sipariş ID ${order.orderId} için sepetItems parse edilirken hata:`, e.message);
                return { ...order, sepetItems: [] }; // Hata durumunda boş dizi döndür
            }
        });
        socket.emit('currentActiveOrders', parsedOrders);
        console.log(`[${new Date().toLocaleTimeString()}] Socket ${socket.id} için ${parsedOrders.length} aktif sipariş gönderildi.`);
    } catch (error) {
        console.error('Mevcut siparişleri SQLite\'tan çekerken hata:', error.message);
    }

    // `requestCurrentRiderLocations` event'i artık JWT doğrulamasını beklemeli
    socket.on('requestCurrentRiderLocations', (token) => {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                console.warn(`Geçersiz token ile motorcu konum isteği: ${err.message}`);
                socket.emit('authError', { message: 'Yetkisiz erişim. Geçersiz token.' });
                return;
            }
            if (user.role !== 'admin' && user.role !== 'garson') { // Sadece admin ve garson rolleri görebilir
                socket.emit('authError', { message: 'Bu işlemi yapmaya yetkiniz yok.' });
                return;
            }

            const currentRidersWithNames = Object.values(riderLocations).map(rider => ({
                id: rider.id,
                name: rider.full_name,
                latitude: rider.latitude,
                longitude: rider.longitude,
                timestamp: rider.timestamp,
                speed: rider.speed,
                bearing: rider.bearing,
                accuracy: rider.accuracy
            }));
            socket.emit('currentRiderLocations', currentRidersWithNames);
        });
    });

    // riderLocationUpdate artık JWT ile kimlik doğrulaması yapacak
    socket.on('riderLocationUpdate', (data) => {
        const { token, locationData } = data; // Token ve konum verisi birlikte geliyor

        if (!token || !locationData) {
            console.warn('Rider konum güncellemesi için token veya konum verisi eksik.');
            return;
        }

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                console.warn(`Geçersiz token ile rider konum güncelleme denemesi: ${err.message}`);
                // İstemciye hata bildirimi gönderebiliriz
                socket.emit('authError', { message: 'Yetkisiz konum güncellemesi. Geçersiz token.' });
                return;
            }

            if (user.role !== 'rider') { // Sadece 'rider' rolündeki kullanıcılar konumunu güncelleyebilir
                console.warn(`Kullanıcı ${user.username} rolü 'rider' değil. Konum güncellenmiyor.`);
                socket.emit('authError', { message: 'Bu işlemi yapmaya yetkiniz yok.' });
                return;
            }

            const { latitude, longitude, timestamp, speed, bearing, accuracy } = locationData;

            riderLocations[user.username] = { // user.username'i anahtar olarak kullan
                id: user.id,
                username: user.username,
                full_name: user.full_name,
                role: user.role,
                latitude,
                longitude,
                timestamp,
                speed,
                bearing,
                accuracy
            };
            socketToUsername[socket.id] = user.username; // Socket ID'si ile Kullanıcı Adını eşle

            // Tüm istemcilere güncellenmiş konumu gönder (isim dahil)
            io.emit('newRiderLocation', {
                id: user.id,
                name: user.full_name,
                latitude,
                longitude,
                timestamp,
                speed,
                bearing,
                accuracy
            });
        });
    });

    socket.on('orderPaid', (data) => {
        const { orderId } = data;
        console.log(`[${new Date().toLocaleTimeString()}] Sipariş ödendi olarak işaretlendi: ${orderId}`);

        try {
            const info = db.prepare(`UPDATE orders SET status = 'paid' WHERE orderId = ? AND status = 'pending'`).run(orderId);
            if (info.changes > 0) {
                console.log(`Sipariş (ID: ${orderId}) SQLite'ta ödendi olarak güncellendi.`);
                io.emit('orderPaidConfirmation', { orderId: orderId });
                io.emit('removeOrderFromDisplay', { orderId: orderId });
            } else {
                console.warn(`Ödendi olarak işaretlenen sipariş (ID: ${orderId}) bulunamadı veya zaten ödenmiş.`);
            }
        } catch (error) {
            console.error('Siparişin durumunu güncellerken hata:', error.message);
        }
    });

    socket.on('disconnect', () => {
        console.log(`[${new Date().toLocaleTimeString()}] Bağlantı koptu: ${socket.id}`);
        const disconnectedUsername = socketToUsername[socket.id];

        if (disconnectedUsername) {
            delete riderLocations[disconnectedUsername];
            delete socketToUsername[socket.id];
            console.log(`Motorcu ${disconnectedUsername} bağlantısı kesildi. Haritadan kaldırılıyor.`);
            io.emit('riderDisconnected', disconnectedUsername);
        }
    });
});

// Yeni endpoint: Tüm motorcu konumlarını isimleriyle birlikte döndür (Sadece kimlik doğrulaması yapılmış kullanıcılar)
app.get('/api/riders-locations', authenticateToken, (req, res) => {
    // Sadece admin veya garson rolündeki kullanıcılar bu endpoint'e erişebilir
    if (req.user.role !== 'admin' && req.user.role !== 'garson') {
        return res.status(403).json({ message: 'Bu işlemi yapmaya yetkiniz yok.' });
    }

    try {
        const activeRiders = Object.values(riderLocations).map(rider => ({
            id: rider.id,
            name: rider.full_name,
            latitude: rider.latitude,
            longitude: rider.longitude,
            timestamp: rider.timestamp,
            speed: rider.speed,
            bearing: rider.bearing,
            accuracy: rider.accuracy
        }));
        res.json(activeRiders);
    } catch (error) {
        console.error('Motorcu konumları çekilirken hata:', error);
        res.status(500).json({ message: 'Motorcu konumları alınırken bir hata oluştu.' });
    }
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

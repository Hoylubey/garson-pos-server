const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const admin = require('firebase-admin');
const path = require('path');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST", "PUT", "DELETE"]
    }
});

const PORT = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// 🔥 Firebase Admin SDK Başlat
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

// --- SQLite Veritabanı Entegrasyonu ---
const dbPath = path.join(__dirname, 'garson_pos.db');
const db = new Database(dbPath);

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
            sepetItems TEXT NOT NULL,
            toplamFiyat REAL NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
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
            full_name TEXT,
            role TEXT NOT NULL DEFAULT 'employee'
        )
    `);
    console.log('Users tablosu hazır.');
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

// Başlangıçta sipariş alım durumunu veritabanından oku veya varsayılan değerle başlat
const initialStatus = db.prepare("SELECT value FROM settings WHERE key = 'isOrderTakingEnabled'").get();
if (!initialStatus) {
    db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").run('isOrderTakingEnabled', 'true');
    console.log("Sipariş alımı durumu veritabanına varsayılan olarak 'true' eklendi.");
}

// 🔐 Token Set'i
const fcmTokens = new Set();

// 🌍 Rider Lokasyonları
const riderLocations = {};
const socketToUsername = {};

// Middleware: Yönetici yetkisini kontrol et
function isAdmin(req, res, next) {
    if (req.headers['x-role'] === 'admin') {
        next();
    } else {
        res.status(403).json({ message: 'Yetkisiz erişim. Yönetici yetkisi gerekli.' });
    }
}

// --- KULLANICI VE YÖNETİCİ GİRİŞ / KAYIT ENDPOINT'LERİ ---

// Genel Giriş Endpoint'i
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
        const token = user.id + "-" + user.role + "-" + Date.now();
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

// Çalışan (Motorcu) Kayıt Endpoint'i
app.post('/api/register-employee', async (req, res) => {
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
        const token = newUser.id + "-" + newUser.role + "-" + Date.now();
        res.status(201).json({
            message: 'Çalışan başarıyla oluşturuldu.',
            token: token,
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

// Çalışan (Motorcu) Giriş Endpoint'i (Şu an kullanılmıyor, genel /api/login kullanılıyor)
app.post('/api/login-employee', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Kullanıcı adı ve parola gerekli.' });
    }
    try {
        const user = db.prepare("SELECT * FROM users WHERE username = ? AND role = 'employee'").get(username);
        if (!user) {
            return res.status(401).json({ message: 'Geçersiz kullanıcı adı veya parola.' });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Geçersiz kullanıcı adı veya parola.' });
        }
        const token = user.id + "-" + user.role + "-" + Date.now();
        res.status(200).json({
            message: 'Giriş başarılı!',
            token: token,
            role: user.role,
            user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role }
        });
    } catch (error) {
        console.error('Çalışan giriş hatası:', error);
        res.status(500).json({ message: 'Giriş sırasında bir hata oluştu.' });
    }
});

// Yönetici Giriş Endpoint'i (Şu an kullanılmıyor, genel /api/login kullanılıyor)
app.post('/api/login-admin', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Kullanıcı adı ve parola gerekli.' });
    }
    try {
        const user = db.prepare("SELECT * FROM users WHERE username = ? AND role = 'admin'").get(username);
        if (!user) {
            return res.status(401).json({ message: 'Geçersiz kullanıcı adı veya parola.' });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Geçersiz kullanıcı adı veya parola.' });
        }
        const token = user.id + "-" + user.role + "-" + Date.now();
        res.status(200).json({
            message: 'Yönetici girişi başarılı!',
            token: token,
            role: user.role,
            user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role }
        });
    } catch (error) {
        console.error('Yönetici giriş hatası:', error);
        res.status(500).json({ message: 'Giriş sırasında bir hata oluştu.' });
    }
});

// --- ÜRÜN YÖNETİMİ ENDPOINT'LERİ (Sadece Yönetici) ---

// Tüm ürünleri getir (Mobil uygulamanın beklediği formatta döndürüldü)
app.get('/api/products', (req, res) => {
    try {
        const products = db.prepare("SELECT id, name, price, category, description FROM products ORDER BY name ASC").all();
        // Mobil uygulamanın beklediği urunAdi ve fiyat anahtarlarına dönüştür
        const formattedProducts = products.map(product => ({
            id: product.id,
            urunAdi: product.name, // 'name' -> 'urunAdi'
            fiyat: product.price, // 'price' -> 'fiyat'
            kategori: product.category,
            aciklama: product.description
        }));
        res.status(200).json(formattedProducts);
    }
    catch (error) {
        console.error('Ürünleri çekerken hata:', error);
        res.status(500).json({ message: 'Ürünler alınırken bir hata oluştu.' });
    }
});

// Ürün Ekle (Sadece Yönetici)
app.post('/api/products', isAdmin, (req, res) => { // Endpoint ismi 'add' kaldırıldı, daha RESTful
    const { urunAdi, fiyat, kategori, aciklama } = req.body; // Mobil uygulamadan gelen anahtarlar
    if (!urunAdi || fiyat === undefined) {
        return res.status(400).json({ message: 'Ürün adı ve fiyatı gerekli.' });
    }
    try {
        const stmt = db.prepare("INSERT INTO products (name, price, category, description) VALUES (?, ?, ?, ?)");
        const info = stmt.run(urunAdi, fiyat, kategori || null, aciklama || null);
        const newProduct = {
            id: info.lastInsertRowid,
            urunAdi: urunAdi,
            fiyat: fiyat,
            kategori: kategori,
            aciklama: aciklama
        };
        io.emit('menuUpdated');
        res.status(201).json({ message: 'Ürün başarıyla eklendi.', product: newProduct });
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed')) {
            return res.status(409).json({ message: 'Bu ürün adı zaten mevcut.' });
        }
        console.error('Ürün ekleme hatası:', error);
        res.status(500).json({ message: 'Ürün eklenirken bir hata oluştu.' });
    }
});

// Ürün Güncelle (Sadece Yönetici)
app.put('/api/products/:id', isAdmin, (req, res) => { // Endpoint ismi 'update' kaldırıldı, daha RESTful
    const { id } = req.params;
    const { urunAdi, fiyat, kategori, aciklama } = req.body; // Mobil uygulamadan gelen anahtarlar
    if (!urunAdi && fiyat === undefined && !kategori && !aciklama) {
        return res.status(400).json({ message: 'Güncellenecek en az bir alan gerekli.' });
    }
    try {
        let updateFields = [];
        let params = [];
        if (urunAdi !== undefined) { updateFields.push('name = ?'); params.push(urunAdi); } // 'urunAdi' -> 'name'
        if (fiyat !== undefined) { updateFields.push('price = ?'); params.push(fiyat); } // 'fiyat' -> 'price'
        if (kategori !== undefined) { updateFields.push('category = ?'); params.push(kategori); }
        if (aciklama !== undefined) { updateFields.push('description = ?'); params.push(aciklama); }

        if (updateFields.length === 0) {
            return res.status(400).json({ message: 'Güncellenecek geçerli bir alan yok.' });
        }

        params.push(id);
        const stmt = db.prepare(`UPDATE products SET ${updateFields.join(', ')} WHERE id = ?`);
        const info = stmt.run(...params);

        if (info.changes > 0) {
            io.emit('menuUpdated');
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

// Ürün Sil (Sadece Yönetici)
app.delete('/api/products/:id', isAdmin, (req, res) => { // Endpoint ismi 'delete' kaldırıldı, daha RESTful
    const { id } = req.params;
    try {
        const stmt = db.prepare("DELETE FROM products WHERE id = ?");
        const info = stmt.run(id);
        if (info.changes > 0) {
            io.emit('menuUpdated');
            res.status(200).json({ message: 'Ürün başarıyla silindi.', id: id });
        } else {
            res.status(404).json({ message: 'Ürün bulunamadı.' });
        }
    } catch (error) {
        console.error('Ürün silme hatası:', error);
        res.status(500).json({ message: 'Ürün silinirken bir hata oluştu.' });
    }
});


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

// 📦 SIPARIŞ AL (API Endpoint'i)
app.post('/api/order', async (req, res) => {
    try {
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

    try {
        const activeOrders = db.prepare(`SELECT * FROM orders WHERE status = 'pending' ORDER BY timestamp ASC`).all();
        const parsedOrders = activeOrders.map(order => {
            return {
                ...order,
                sepetItems: JSON.parse(order.sepetItems)
            };
        });
        socket.emit('currentActiveOrders', parsedOrders);
        console.log(`[${new Date().toLocaleTimeString()}] Socket ${socket.id} için ${parsedOrders.length} aktif sipariş gönderildi.`);
    } catch (error) {
        console.error('Mevcut siparişleri SQLite\'tan çekerken hata:', error.message);
    }

    socket.on('requestCurrentRiderLocations', () => {
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

    socket.on('riderLocationUpdate', (locationData) => {
        const { username, latitude, longitude, timestamp, speed, bearing, accuracy } = locationData;

        if (!username) {
            console.warn('Rider konum güncellemesi için kullanıcı adı (username) bulunamadı.');
            return;
        }

        const user = db.prepare("SELECT id, full_name, role FROM users WHERE username = ?").get(username);

        if (!user || user.role !== 'rider') {
            console.warn(`Kullanıcı ${username} bulunamadı veya rolü 'rider' değil. Konum güncellenmiyor.`);
            return;
        }

        riderLocations[username] = {
            id: user.id,
            username: username,
            full_name: user.full_name,
            role: user.role,
            latitude,
            longitude,
            timestamp,
            speed,
            bearing,
            accuracy
        };
        socketToUsername[socket.id] = username;

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

// Yeni endpoint: Tüm motorcu konumlarını isimleriyle birlikte döndür
app.get('/api/riders-locations', (req, res) => {
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

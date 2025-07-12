const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const admin = require('firebase-admin'); // Firebase Admin SDK
const path = require('path');
const Database = require('better-sqlite3'); // better-sqlite3 kütüphanesini import edin
const { v4: uuidv4 } = require('uuid'); // Benzersiz ID'ler için uuid kütüphanesi
const bcrypt = require('bcryptjs'); // Şifreleme için bcryptjs kütüphanesi

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*", // Güvenlik için belirli domain'lerle sınırlamak daha iyidir üretimde
        methods: ["GET", "POST", "PUT", "DELETE"] // Yeni metotlar eklendi
    }
});

const PORT = process.env.PORT || 3000;
app.use(cors());
app.use(express.json()); // Gelen JSON isteklerini ayrıştırmak için
app.use(express.static('public'));

// 🔥 Firebase Admin SDK Başlat
// Ortam değişkeninden Firebase hizmet hesabı anahtarını oku
try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
    console.log('Firebase Admin SDK başlatıldı.');
} catch (error) {
    console.error('Firebase Admin SDK başlatılırken hata oluştu. Ortam değişkenini kontrol edin:', error.message);
    // Uygulamanın Firebase olmadan da çalışmaya devam etmesi için burada çıkış yapmıyoruz,
    // ancak bildirimler çalışmayacaktır.
}


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

    // Yeni sütunları ekle (IF NOT EXISTS ile mevcutsa eklemeyecek)
    db.exec(`
        ALTER TABLE orders ADD COLUMN riderUsername TEXT;
        ALTER TABLE orders ADD COLUMN deliveryAddress TEXT;
        ALTER TABLE orders ADD COLUMN paymentMethod TEXT;
        ALTER TABLE orders ADD COLUMN assignedTimestamp TEXT;
        ALTER TABLE orders ADD COLUMN deliveryStatus TEXT DEFAULT 'pending';
    `);
    console.log('Orders tablosuna yeni sütunlar eklendi (varsa).');

} catch (err) {
    // ALTER TABLE hata verirse, genellikle sütun zaten var demektir.
    // Ancak farklı bir hata ise loglayalım.
    if (!err.message.includes('duplicate column name')) {
        console.error('Orders tablosu oluşturma veya güncelleme hatası:', err.message);
    } else {
        console.log('Orders tablosu sütunları zaten mevcut.');
    }
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


// Başlangıçta sipariş alım durumunu veritabanından oku veya varsayılan değerle başlat
const initialStatus = db.prepare("SELECT value FROM settings WHERE key = 'isOrderTakingEnabled'").get();
if (!initialStatus) {
    db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").run('isOrderTakingEnabled', 'true');
    console.log("Sipariş alımı durumu veritabanına varsayılan olarak 'true' eklendi.");
}

// 🔐 FCM Token Depolama (username'e göre, rol bilgisiyle birlikte)
// { "username": { token: "fcm_token_string", role: "admin" }, ... }
const fcmTokens = {};

// 🌍 Rider Lokasyonları
// username'e göre saklayacağız, full_name'i de içerecek
// { "username": { id, username, full_name, role, latitude, longitude, timestamp, speed, bearing, accuracy }, ... }
const riderLocations = {};
const socketToUsername = {}; // { "socket.id": "username" }


// Middleware: Yönetici yetkisini kontrol et (Şimdilik basit bir örnek, token doğrulama daha güvenlidir)
function isAdmin(req, res, next) {
    // Gerçek bir uygulamada, JWT gibi bir token doğrulama mekanizması kullanmalısınız.
    // Bu basit kontrol sadece konsepti göstermek içindir.
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.warn('isAdmin: Yetkilendirme başlığı eksik veya hatalı formatta.');
        return res.status(401).json({ message: 'Yetkilendirme başlığı eksik veya hatalı formatta.' });
    }
    
    const token = authHeader.split(' ')[1]; // "Bearer TOKEN" kısmından sadece TOKEN'ı al

    // Basit token doğrulama: token'ı parse ederek kullanıcı ID'si ve rolü al
    const parts = token.split('-');
    if (parts.length === 3) { // Beklenen format: id-role-timestamp
        const userRole = parts[1];
        if (userRole === 'admin') {
            next(); // Yönetici ise devam et
            return;
        }
    }
    console.warn('isAdmin: Token geçersiz veya yönetici yetkisi yok.');
    res.status(403).json({ message: 'Yetkisiz erişim. Yönetici yetkisi gerekli.' });
}

// Middleware: Sadece admin veya garson yetkisi olanlar için
function isAdminOrGarson(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.warn('isAdminOrGarson: Yetkilendirme başlığı eksik veya hatalı formatta.');
        return res.status(401).json({ message: 'Yetkilendirme başlığı eksik veya hatalı formatta.' });
    }
    
    const token = authHeader.split(' ')[1];
    const parts = token.split('-');
    if (parts.length === 3) {
        const userRole = parts[1];
        if (userRole === 'admin' || userRole === 'garson') {
            next();
            return;
        }
    }
    console.warn('isAdminOrGarson: Token geçersiz veya yetkisiz erişim. Admin veya Garson yetkisi gerekli. Token parts:', parts); // Hata ayıklama için eklendi
    res.status(403).json({ message: 'Yetkisiz erişim. Admin veya Garson yetkisi gerekli.' });
}

// Middleware: Sadece admin veya rider yetkisi olanlar için
function isAdminOrRider(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.warn('isAdminOrRider: Yetkilendirme başlığı eksik veya hatalı formatta.');
        return res.status(401).json({ message: 'Yetkilendirme başlığı eksik veya hatalı formatta.' });
    }
    
    const token = authHeader.split(' ')[1];
    const parts = token.split('-');
    if (parts.length === 3) {
        const userRole = parts[1];
        if (userRole === 'admin' || userRole === 'rider') {
            next();
            return;
        }
    }
    console.warn('isAdminOrRider: Token geçersiz veya yetkisiz erişim. Admin veya Rider yetkisi gerekli.');
    res.status(403).json({ message: 'Yetkisiz erişim. Admin veya Rider yetkisi gerekli.' });
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
app.post('/api/register-employee', isAdmin, async (req, res) => { // isAdmin middleware eklendi
    const { username, password, full_name, role } = req.body; // 'role' de eklendi

    if (!username || !password || !full_name || !role) {
        return res.status(400).json({ message: 'Kullanıcı adı, parola, tam ad ve rol gerekli.' });
    }

    // Geçerli rollerin bir listesini tanımla
    const validRoles = ['employee', 'admin', 'rider', 'garson'];
    if (!validRoles.includes(role)) {
        return res.status(400).json({ message: 'Geçersiz rol belirtildi.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const stmt = db.prepare("INSERT INTO users (username, password, full_name, role) VALUES (?, ?, ?, ?)");
        const info = stmt.run(username, hashedPassword, full_name, role); // Rolü de kaydet
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

// Tüm ürünleri getir
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

// Ürün Ekle (Sadece Yönetici)
app.post('/api/products/add', isAdmin, (req, res) => {
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

// Ürün Güncelle (Sadece Yönetici)
app.put('/api/products/update/:id', isAdmin, (req, res) => {
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

// Ürün Sil (Sadece Yönetici)
app.delete('/api/products/delete/:id', isAdmin, (req, res) => {
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


// ✅ FCM TOKEN KAYDI (Kullanıcı adı ve rol bilgisiyle birlikte)
app.post('/api/register-fcm-token', (req, res) => {
    console.log(`[${new Date().toLocaleTimeString()}] /api/register-fcm-token endpoint'ine istek geldi. Body:`, req.body);
    const { token, username, role } = req.body; // username ve role de al
    if (!token || !username || !role) {
        console.error('FCM Token kayıt hatası: Token, username veya role eksik.', { token, username, role });
        return res.status(400).json({ message: 'Token, username ve role gereklidir.' });
    }
    // fcmTokens objesinde username'i anahtar olarak kullanarak token ve rolü sakla
    fcmTokens[username] = { token, role };
    console.log(`FCM Token kaydedildi: Kullanıcı: ${username}, Rol: ${role}`);
    res.status(200).send({ message: 'Token başarıyla kayıt edildi.' });
});

// 🔍 Tokenları listele (debug için)
app.get('/api/fcm-tokens', (req, res) => {
    console.log('FCM Tokenlar listeleniyor:', fcmTokens); // Konsola da yazdır
    res.status(200).json(fcmTokens); // Artık bir obje döndürüyoruz
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
app.post('/api/set-order-status', isAdmin, (req, res) => { // isAdmin middleware eklendi
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

// 📦 SIPARIŞ AL (API Endpoint'i)
app.post('/api/order', async (req, res) => {
    console.log(`[${new Date().toLocaleTimeString()}] /api/order endpoint'ine istek geldi.`);
    try {
        // Sipariş alım durumunu veritabanından kontrol et
        const orderStatus = db.prepare("SELECT value FROM settings WHERE key = 'isOrderTakingEnabled'").get();
        const isOrderTakingEnabled = orderStatus && orderStatus.value === 'true';

        console.log(`[${new Date().toLocaleTimeString()}] Sipariş alım durumu: ${isOrderTakingEnabled ? 'AÇIK' : 'KAPALI'}`);

        if (!isOrderTakingEnabled) {
            return res.status(403).json({ error: 'Sipariş alımı şu anda kapalıdır.' });
        }

        const orderData = req.body;

        // Gelen verinin varlığını ve yapısını kontrol et
        if (!orderData || !orderData.masaId || !orderData.masaAdi || orderData.toplamFiyat === undefined || !orderData.sepetItems) {
            console.error(`[${new Date().toLocaleTimeString()}] Eksik sipariş verisi:`, orderData);
            return res.status(400).json({ error: 'Eksik sipariş verisi. Masa ID, Masa Adı, Toplam Fiyat ve Sepet Ürünleri gereklidir.' });
        }

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

        try {
            db.prepare(`INSERT INTO orders (orderId, masaId, masaAdi, sepetItems, toplamFiyat, timestamp, status, deliveryStatus) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
                orderId,
                masaId,
                masaAdi,
                sepetItemsJson,
                toplamFiyat,
                timestamp,
                'pending', // 'status' hala 'pending'
                'pending' // Yeni 'deliveryStatus' varsayılan olarak 'pending'
            );
            console.log(`[${new Date().toLocaleTimeString()}] Yeni sipariş SQLite'a başarıyla kaydedildi. ID: ${orderId}`);
        } catch (dbError) {
            console.error(`[${new Date().toLocaleTimeString()}] SQLite'a sipariş kaydedilirken hata:`, dbError.message);
            return res.status(500).json({ error: 'Sipariş veritabanına kaydedilirken bir hata oluştu.' });
        }

        // Web'e gönderilecek sipariş objesini oluştur (sepetItems parse edilmiş haliyle)
        const newOrderToSend = {
            orderId: orderId, // Artık orderId kullanıyoruz
            masaId: masaId,
            masaAdi: masaAdi,
            sepetItems: sepetItems, // Zaten obje olarak var
            toplamFiyat: toplamFiyat,
            timestamp: timestamp,
            status: 'pending',
            deliveryStatus: 'pending'
        };

        // Mutfak/Kasa ekranlarına yeni siparişi gönder
        io.emit('newOrder', newOrderToSend);
        io.emit('notificationSound', { play: true });

        // 🔔 Firebase Bildirimlerini Adminlere Gönder
        // fcmTokens objesindeki tüm kayıtlı token'ları döngüye al
        console.log(`[${new Date().toLocaleTimeString()}] FCM Bildirimleri gönderilmeye başlanıyor. Kayıtlı token sayısı: ${Object.keys(fcmTokens).length}`);
        for (const username in fcmTokens) {
            const userData = fcmTokens[username];
            if (userData.role === 'admin') { // Sadece admin rolündeki kullanıcılara gönder
                console.log(`[${new Date().toLocaleTimeString()}] Admin rolündeki kullanıcı (${username}) için FCM bildirimi hazırlanıyor. Token: ${userData.token.substring(0, 10)}...`);
                const message = {
                    notification: {
                        title: 'Yeni Sipariş!',
                        body: `Masa ${masaAdi} için yeni bir siparişiniz var. Toplam: ${toplamFiyat.toFixed(2)} TL`,
                    },
                    data: { // Custom data payload
                        orderId: orderId.toString(),
                        masaAdi: masaAdi,
                        toplamFiyat: toplamFiyat.toFixed(2),
                        sepetItems: JSON.stringify(sepetItems), // Sipariş detaylarını string olarak gönder
                        type: 'new_order' // Bildirim tipini belirt
                    },
                    token: userData.token,
                };

                try {
                    const response = await admin.messaging().send(message); // await kullanıldı
                    console.log(`🔥 FCM bildirimi başarıyla gönderildi (${username}):`, response);
                } catch (error) {
                    console.error(`❌ FCM bildirimi gönderilirken hata oluştu (${username}):`, error);
                    // Geçersiz veya kayıtlı olmayan token'ları temizle
                    if (error.code === 'messaging/invalid-registration-token' ||
                        error.code === 'messaging/registration-token-not-registered') {
                        console.warn(`Geçersiz veya kayıtlı olmayan token temizleniyor: ${username}`);
                        delete fcmTokens[username]; // fcmTokens objesinden kaldır
                    }
                }
            } else {
                console.log(`[${new Date().toLocaleTimeString()}] Kullanıcı ${username} admin rolünde değil, bildirim gönderilmiyor. Rol: ${userData.role}`);
            }
        }

        res.status(200).json({ message: 'Sipariş işlendi.' });
    } catch (error) {
        console.error(`[${new Date().toLocaleTimeString()}] Sipariş işlenirken veya genel bir hata oluştu:`, error);
        res.status(500).json({ error: 'Sipariş işlenirken bir hata oluştu.' });
    }
});

// 🛵 YENİ ENDPOINT: SİPARİŞİ MOTORCUYA ATA
app.post('/api/assign-order', isAdmin, async (req, res) => {
    console.log(`[${new Date().toLocaleTimeString()}] /api/assign-order endpoint'ine istek geldi.`);
    const { orderId, riderUsername, deliveryAddress, paymentMethod } = req.body;

    if (!orderId || !riderUsername || !deliveryAddress || !paymentMethod) {
        console.error('Sipariş atama hatası: Eksik veri.', req.body);
        return res.status(400).json({ message: 'Sipariş ID, motorcu kullanıcı adı, teslimat adresi ve ödeme yöntemi gereklidir.' });
    }

    try {
        const assignedTimestamp = new Date().toISOString();

        // Siparişi veritabanında güncelle
        const stmt = db.prepare(`
            UPDATE orders
            SET riderUsername = ?, deliveryAddress = ?, paymentMethod = ?, assignedTimestamp = ?, deliveryStatus = 'assigned'
            WHERE orderId = ? AND deliveryStatus = 'pending'
        `);
        const info = stmt.run(riderUsername, deliveryAddress, paymentMethod, assignedTimestamp, orderId);

        if (info.changes === 0) {
            console.warn(`Sipariş (ID: ${orderId}) bulunamadı veya zaten atanmış/teslim edilmiş.`);
            return res.status(404).json({ message: 'Sipariş bulunamadı veya zaten atanmış/teslim edilmiş.' });
        }

        // Atanan siparişi veritabanından çek (güncel haliyle)
        const assignedOrder = db.prepare(`SELECT * FROM orders WHERE orderId = ?`).get(orderId);
        // sepetItems JSON string olduğu için parse et
        assignedOrder.sepetItems = JSON.parse(assignedOrder.sepetItems);

        console.log(`Sipariş ${orderId} motorcu ${riderUsername} adresine (${deliveryAddress}) atandı.`);
        io.emit('orderAssigned', assignedOrder); // Web admin ekranlarına bildir

        // 🔔 Motorcuya FCM Bildirimi Gönder
        const riderData = fcmTokens[riderUsername];
        if (riderData && riderData.token) {
            const message = {
                notification: {
                    title: 'Yeni Teslimat Siparişi!',
                    body: `Masa ${assignedOrder.masaAdi} için yeni bir siparişiniz var. Adres: ${deliveryAddress}`,
                },
                data: {
                    orderId: assignedOrder.orderId,
                    masaAdi: assignedOrder.masaAdi,
                    toplamFiyat: assignedOrder.toplamFiyat.toString(),
                    deliveryAddress: assignedOrder.deliveryAddress,
                    paymentMethod: assignedOrder.paymentMethod,
                    sepetItems: JSON.stringify(assignedOrder.sepetItems),
                    type: 'new_delivery_order' // Bildirim tipini belirt
                },
                token: riderData.token,
            };

            try {
                const response = await admin.messaging().send(message);
                console.log(`🔥 FCM bildirimi başarıyla motorcuya gönderildi (${riderUsername}):`, response);
            } catch (error) {
                console.error(`❌ FCM bildirimi motorcuya gönderilirken hata oluştu (${riderUsername}):`, error);
                if (error.code === 'messaging/invalid-registration-token' ||
                    error.code === 'messaging/registration-token-not-registered') {
                    console.warn(`Geçersiz veya kayıtlı olmayan motorcu token'ı temizleniyor: ${riderUsername}`);
                    delete fcmTokens[riderUsername];
                }
            }
        } else {
            console.warn(`Motorcu ${riderUsername} için FCM token bulunamadı veya geçersiz.`);
        }

        res.status(200).json({ message: 'Sipariş başarıyla atandı.', order: assignedOrder });

    } catch (error) {
        console.error('Sipariş atama hatası:', error);
        res.status(500).json({ message: 'Sipariş atanırken bir hata oluştu.' });
    }
});

// 🔄 YENİ ENDPOINT: SİPARİŞ TESLİMAT DURUMUNU GÜNCELLE
app.post('/api/update-order-delivery-status', isAdminOrRider, async (req, res) => {
    console.log(`[${new Date().toLocaleTimeString()}] /api/update-order-delivery-status endpoint'ine istek geldi.`);
    const { orderId, newDeliveryStatus } = req.body; // newDeliveryStatus: 'en_route', 'delivered'

    if (!orderId || !newDeliveryStatus) {
        return res.status(400).json({ message: 'Sipariş ID ve yeni teslimat durumu gereklidir.' });
    }

    const validStatuses = ['en_route', 'delivered', 'cancelled']; // 'pending' ve 'assigned' zaten var
    if (!validStatuses.includes(newDeliveryStatus)) {
        return res.status(400).json({ message: 'Geçersiz teslimat durumu belirtildi.' });
    }

    try {
        const stmt = db.prepare(`
            UPDATE orders
            SET deliveryStatus = ?
            WHERE orderId = ?
        `);
        const info = stmt.run(newDeliveryStatus, orderId);

        if (info.changes === 0) {
            return res.status(404).json({ message: 'Sipariş bulunamadı veya durumu zaten güncel.' });
        }

        console.log(`Sipariş ${orderId} teslimat durumu güncellendi: ${newDeliveryStatus}`);
        io.emit('orderDeliveryStatusUpdated', { orderId, newDeliveryStatus }); // Tüm istemcilere bildir

        // Eğer sipariş teslim edildiyse, adminlere bildirim gönder
        if (newDeliveryStatus === 'delivered') {
            const deliveredOrder = db.prepare(`SELECT * FROM orders WHERE orderId = ?`).get(orderId);
            for (const username in fcmTokens) {
                const userData = fcmTokens[username];
                if (userData.role === 'admin') {
                    const message = {
                        notification: {
                            title: 'Sipariş Teslim Edildi!',
                            body: `Masa ${deliveredOrder.masaAdi} için sipariş başarıyla teslim edildi.`,
                        },
                        data: {
                            orderId: deliveredOrder.orderId,
                            masaAdi: deliveredOrder.masaAdi,
                            type: 'order_delivered'
                        },
                        token: userData.token,
                    };
                    try {
                        await admin.messaging().send(message);
                        console.log(`🔥 FCM bildirimi adminlere gönderildi (teslimat):`, username);
                    } catch (error) {
                        console.error(`❌ FCM bildirimi adminlere gönderilirken hata (teslimat):`, error);
                    }
                }
            }
        }

        res.status(200).json({ message: 'Teslimat durumu başarıyla güncellendi.', orderId, newDeliveryStatus });

    } catch (error) {
        console.error('Teslimat durumu güncellenirken hata:', error);
        res.status(500).json({ message: 'Teslimat durumu güncellenirken bir hata oluştu.' });
    }
});

// 📜 YENİ ENDPOINT: MOTORCUYA ATANAN SİPARİŞLERİ GETİR
app.get('/api/rider/orders/:username', isAdminOrRider, (req, res) => { // Endpoint yolu düzeltildi
    console.log(`[${new Date().toLocaleTimeString()}] /api/rider/orders/:username endpoint'ine istek geldi.`);
    const { username } = req.params;

    try {
        const orders = db.prepare(`
            SELECT * FROM orders
            WHERE riderUsername = ? AND (deliveryStatus = 'assigned' OR deliveryStatus = 'en_route')
            ORDER BY assignedTimestamp DESC
        `).all(username);

        // sepetItems JSON string olduğu için parse et
        const parsedOrders = orders.map(order => ({
            ...order,
            sepetItems: JSON.parse(order.sepetItems)
        }));

        res.status(200).json(parsedOrders);
    } catch (error) {
        console.error('Motorcuya atanan siparişler çekilirken hata:', error);
        res.status(500).json({ message: 'Siparişler alınırken bir hata oluştu.' });
    }
});

// 🏁 YENİ ENDPOINT: MOTORCUNUN GÜNÜNÜ SONLANDIR
app.post('/api/rider/end-day', isAdminOrRider, async (req, res) => { // Endpoint yolu düzeltildi
    console.log(`[${new Date().toLocaleTimeString()}] /api/rider/end-day endpoint'ine istek geldi.`);
    const { username } = req.body; // Body'den username al

    if (!username) {
        return res.status(400).json({ message: 'Kullanıcı adı gerekli.' });
    }

    try {
        // Teslim edilmiş sipariş sayısını al
        const deliveredCount = db.prepare(`
            SELECT COUNT(*) AS count FROM orders
            WHERE riderUsername = ? AND deliveryStatus = 'delivered'
            AND assignedTimestamp >= ?
        `).get(username, new Date().toISOString().split('T')[0]); // Bugün teslim edilenler

        // Atanmış ve yolda olan tüm siparişleri 'cancelled' olarak işaretle (veya başka bir uygun durum)
        db.prepare(`
            UPDATE orders
            SET deliveryStatus = 'cancelled', riderUsername = NULL, deliveryAddress = NULL, paymentMethod = NULL, assignedTimestamp = NULL
            WHERE riderUsername = ? AND (deliveryStatus = 'assigned' OR deliveryStatus = 'en_route')
        `).run(username);

        io.emit('riderDayEnded', { username, deliveredCount: deliveredCount.count }); // Web admin ekranlarına bildir

        res.status(200).json({
            message: `Motorcu ${username} günü sonlandırdı.`,
            totalDeliveredPackagesToday: deliveredCount.count
        });

    } catch (error) {
        console.error('Motorcunun gününü sonlandırırken hata:', error);
        res.status(500).json({ message: 'Günü sonlandırırken bir hata oluştu.' });
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
        // sepetItems JSON string olduğu için parse etmeliyiz
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
        // Tüm mevcut motorcu konumlarını isimleriyle birlikte gönder
        const currentRidersWithNames = Object.values(riderLocations).map(rider => ({
            id: rider.id,
            username: rider.username, // Kullanıcı adını da ekle
            name: rider.full_name, // 'full_name' kullan
            fullName: rider.full_name, // Daha açık bir anahtar
            latitude: rider.latitude,
            longitude: rider.longitude,
            timestamp: rider.timestamp,
            speed: rider.speed,
            bearing: rider.bearing,
            accuracy: rider.accuracy
        }));
        socket.emit('currentRiderLocations', currentRidersWithNames);
    });

    // riderLocationUpdate artık 'username' bekliyor, 'riderId' değil
    socket.on('riderLocationUpdate', (locationData) => {
        const { username, latitude, longitude, timestamp, speed, bearing, accuracy } = locationData;

        if (!username) {
            console.warn('Rider konum güncellemesi için kullanıcı adı (username) bulunamadı.');
            return;
        }

        // Kullanıcının tam adını veritabanından al
        const user = db.prepare("SELECT id, full_name, role FROM users WHERE username = ?").get(username);

        if (!user || user.role !== 'rider') { // Sadece 'rider' rolündeki kullanıcıların konumunu takip et
            console.warn(`Kullanıcı ${username} bulunamadı veya rolü 'rider' değil. Konum güncellenmiyor.`);
            return;
        }

        riderLocations[username] = {
            id: user.id, // Kullanıcı ID'si
            username: username,
            full_name: user.full_name, // Tam adını kaydet
            role: user.role,
            latitude,
            longitude,
            timestamp,
            speed,
            bearing,
            accuracy
        };
        socketToUsername[socket.id] = username; // Socket ID'si ile Kullanıcı Adını eşle

        // Tüm istemcilere güncellenmiş konumu gönder (isim dahil)
        io.emit('newRiderLocation', {
            id: user.id,
            username: username, // Kullanıcı adını da ekle
            name: user.full_name, // Existing field for full_name
            fullName: user.full_name, // Explicitly add full_name under 'fullName'
            latitude,
            longitude,
            timestamp,
            speed,
            bearing,
            accuracy
        });
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
        const disconnectedUsername = socketToUsername[socket.id]; // İlgili kullanıcı adını al

        if (disconnectedUsername) {
            delete riderLocations[disconnectedUsername]; // riderLocations objesinden sil
            delete socketToUsername[socket.id];    // Eşlemeden de sil
            console.log(`Motorcu ${disconnectedUsername} bağlantısı kesildi. Haritadan kaldırılıyor.`);
            // İstemcilere bu motorcunun ayrıldığını bildir
            io.emit('riderDisconnected', disconnectedUsername);
        }
    });
});

// Yeni endpoint: Tüm motorcu konumlarını isimleriyle birlikte döndür
app.get('/api/riders-locations', (req, res) => {
    try {
        const activeRiders = Object.values(riderLocations).map(rider => ({
            id: rider.id,
            username: rider.username, // Kullanıcı adını da ekle
            name: rider.full_name, // 'full_name' kullan
            fullName: rider.full_name, // Daha açık bir anahtar
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

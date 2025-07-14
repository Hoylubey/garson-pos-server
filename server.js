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

try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
    console.log('Firebase Admin SDK başlatıldı.');
} catch (error) {
    console.error('Firebase Admin SDK başlatılırken hata:', error);
    console.error('FIREBASE_SERVICE_ACCOUNT_KEY ortam değişkeni doğru ayarlanmamış veya JSON formatı bozuk.');
    process.exit(1);
}

const dbPath = path.join(__dirname, 'garson_pos.db');
const db = new Database(dbPath, { verbose: console.log });

db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT,
        role TEXT NOT NULL DEFAULT 'employee'
    );

    CREATE TABLE IF NOT EXISTS riders (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        full_name TEXT,
        latitude REAL,
        longitude REAL,
        timestamp INTEGER,
        speed REAL,
        bearing REAL,
        accuracy REAL,
        delivered_count INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        price REAL NOT NULL,
        category TEXT,
        description TEXT
    );

    CREATE TABLE IF NOT EXISTS orders (
        orderId TEXT PRIMARY KEY,
        masaId TEXT NOT NULL,
        masaAdi TEXT NOT NULL,
        sepetItems TEXT NOT NULL,
        toplamFiyat REAL NOT NULL,
        timestamp TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        riderUsername TEXT,
        deliveryAddress TEXT,
        paymentMethod TEXT,
        assignedTimestamp TEXT,
        deliveryStatus TEXT DEFAULT 'pending',
        deliveredTimestamp TEXT
    );
`);
console.log('Temel tablolar oluşturuldu veya zaten mevcut.');

const checkAndAlterOrdersTable = () => {
    try {
        const columns = db.prepare("PRAGMA table_info(orders)").all();
        const columnNames = new Set(columns.map(c => c.name));

        if (!columnNames.has('riderUsername')) {
            db.exec("ALTER TABLE orders ADD COLUMN riderUsername TEXT;");
            console.log("orders tablosuna 'riderUsername' sütunu eklendi.");
        }
        if (!columnNames.has('deliveryAddress')) {
            db.exec("ALTER TABLE orders ADD COLUMN deliveryAddress TEXT;");
            console.log("orders tablosuna 'deliveryAddress' sütunu eklendi.");
        }
        if (!columnNames.has('paymentMethod')) {
            db.exec("ALTER TABLE orders ADD COLUMN paymentMethod TEXT;");
            console.log("orders tablosuna 'paymentMethod' sütunu eklendi.");
        }
        if (!columnNames.has('assignedTimestamp')) {
            db.exec("ALTER TABLE orders ADD COLUMN assignedTimestamp TEXT;");
            console.log("orders tablosuna 'assignedTimestamp' sütunu eklendi.");
        }
        if (!columnNames.has('deliveryStatus')) {
            db.exec("ALTER TABLE orders ADD COLUMN deliveryStatus TEXT DEFAULT 'pending';");
            console.log("orders tablosuna 'deliveryStatus' sütunu eklendi.");
        }
        if (!columnNames.has('deliveredTimestamp')) {
            db.exec("ALTER TABLE orders ADD COLUMN deliveredTimestamp TEXT;");
            console.log("orders tablosuna 'deliveredTimestamp' sütunu eklendi.");
        }
    } catch (error) {
        console.error("Orders tablosu şeması kontrol edilirken/güncellenirken hata:", error.message);
    }
};
checkAndAlterOrdersTable();

const setupDefaultUsersAndSettings = () => {
    try {
        const usersToCreate = [
            { username: 'hoylubey', password: 'Goldmaster150.', role: 'admin', fullName: 'Yönetici' },
            { username: 'admin', password: 'admin123', role: 'admin', fullName: 'Sistem Yöneticisi' },
            { username: 'garson', password: 'garson123', role: 'garson', fullName: 'Garson Personel' },
            { username: 'motorcu', password: 'motorcu123', role: 'rider', fullName: 'Motorcu Personel' }
        ];

        usersToCreate.forEach(user => {
            const existingUser = db.prepare("SELECT * FROM users WHERE username = ?").get(user.username);
            if (!existingUser) {
                const hashedPassword = bcrypt.hashSync(user.password, 10);
                const userId = uuidv4();
                db.prepare("INSERT INTO users (id, username, password, full_name, role) VALUES (?, ?, ?, ?, ?)").run(userId, user.username, hashedPassword, user.fullName, user.role);
                console.log(`Varsayılan kullanıcı oluşturuldu: ${user.username}/${user.password}`);

                if (user.role === 'rider') {
                    db.prepare("INSERT INTO riders (id, username, full_name, delivered_count) VALUES (?, ?, ?, ?)").run(userId, user.username, user.fullName, 0);
                    console.log(`Motorcu ${user.username} riders tablosuna eklendi.`);
                }
            } else {
                console.log(`Varsayılan kullanıcı ${user.username} zaten mevcut.`);
            }
        });

        const orderStatusSetting = db.prepare("SELECT value FROM settings WHERE key = 'isOrderTakingEnabled'").get();
        if (!orderStatusSetting) {
            db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").run('isOrderTakingEnabled', 'true');
            console.log("Sipariş alımı durumu veritabanına varsayılan olarak 'true' eklendi.");
        }

        const existingProductsCount = db.prepare("SELECT COUNT(*) AS count FROM products").get().count;
        if (existingProductsCount === 0) {
            const insert = db.prepare("INSERT INTO products (name, price, category) VALUES (?, ?, ?)");
            insert.run('Kokoreç Yarım Ekmek', 120.00, 'Ana Yemek');
            insert.run('Kokoreç Çeyrek Ekmek', 90.00, 'Ana Yemek');
            insert.run('Ayran Büyük', 25.00, 'İçecek');
            insert.run('Ayran Küçük', 15.00, 'İçecek');
            insert.run('Su', 10.00, 'İçecek');
            console.log('Örnek ürünler veritabanına eklendi.');
        } else {
            console.log('Ürünler tablosu zaten dolu, örnek ürünler eklenmedi.');
        }

    } catch (error) {
        console.error('Varsayılan kullanıcılar, ürünler veya ayarlar oluşturulurken hata:', error);
    }
};
setupDefaultUsersAndSettings();


const riderLocations = {};
const connectedClients = new Map();
const fcmTokens = {};

// Middleware: Token doğrulama ve rol kontrolü için yardımcı fonksiyonlar
const parseToken = (token) => {
    const parts = token.split('.'); // Nokta (.) ile ayır
    console.log(`[parseToken] Token ayrıştırma denemesi: ${token}, Parçalar: ${JSON.stringify(parts)}, Parça Sayısı: ${parts.length}`);

    if (parts.length === 3) {
        const userId = parts[0];
        const role = parts[1];
        const timestamp = parseInt(parts[2], 10);
        
        console.log(`[parseToken] Token başarıyla ayrıştırıldı: ID=${userId}, Rol=${role}, Timestamp=${timestamp}`);
        return {
            id: userId,
            role: role,
            timestamp: timestamp
        };
    }
    console.warn(`[parseToken] Hatalı token formatı: Beklenen 3 parça, alınan ${parts.length} parça. Token: ${token}`);
    return null;
};

// Middleware: Sadece Admin yetkisi olanlar için
function isAdminMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.warn('[isAdminMiddleware] Yetkilendirme başlığı eksik veya hatalı formatta.');
        return res.status(401).json({ message: 'Yetkilendirme başlığı eksik veya hatalı formatta.' });
    }
    
    const token = authHeader.split(' ')[1];
    const decodedToken = parseToken(token);

    if (decodedToken && decodedToken.role === 'admin') {
        req.user = { uid: decodedToken.id, role: decodedToken.role };
        console.log(`[isAdminMiddleware] Yetkili admin erişimi: Kullanıcı ID: ${req.user.uid}, Rol: ${req.user.role}`);
        next();
        return;
    }
    console.warn(`[isAdminMiddleware] Yetkisiz erişim. Token: ${token}, Ayrıştırılan Rol: ${decodedToken ? decodedToken.role : 'Yok'}. Yönetici yetkisi gerekli.`);
    res.status(403).json({ message: 'Yetkisiz erişim. Yönetici yetkisi gerekli.' });
}

// Middleware: Admin, Garson veya Motorcu yetkisi olanlar için
function isAdminOrGarsonOrRiderMiddleware(req, res, next) { 
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.warn('[isAdminOrGarsonOrRiderMiddleware] Yetkilendirme başlığı eksik veya hatalı formatta.');
        return res.status(401).json({ message: 'Yetkilendirme başlığı eksik veya hatalı formatta.' });
    }
    
    const token = authHeader.split(' ')[1];
    const decodedToken = parseToken(token);

    if (decodedToken && (decodedToken.role === 'admin' || decodedToken.role === 'garson' || decodedToken.role === 'rider')) { 
        req.user = { uid: decodedToken.id, role: decodedToken.role };
        console.log(`[isAdminOrGarsonOrRiderMiddleware] Yetkili admin/garson/rider erişimi: Kullanıcı ID: ${req.user.uid}, Rol: ${req.user.role}`);
        next();
        return;
    }
    console.warn(`[isAdminOrGarsonOrRiderMiddleware] Yetkisiz erişim. Token: ${token}, Ayrıştırılan Rol: ${decodedToken ? decodedToken.role : 'Yok'}. Admin, Garson veya Rider yetkisi gerekli.`);
    res.status(403).json({ message: 'Yetkisiz erişim. Admin, Garson veya Rider yetkisi gerekli.' });
}

// Middleware: Admin veya Motorcu yetkisi olanlar için
function isAdminOrRiderMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.warn('[isAdminOrRiderMiddleware] Yetkilendirme başlığı eksik veya hatalı formatta.');
        return res.status(401).json({ message: 'Yetkilendirme başlığı eksik veya hatalı formatta.' });
    }
    
    const token = authHeader.split(' ')[1];
    const decodedToken = parseToken(token);

    if (decodedToken && (decodedToken.role === 'admin' || decodedToken.role === 'rider')) {
        req.user = { uid: decodedToken.id, role: decodedToken.role };
        console.log(`[isAdminOrRiderMiddleware] Yetkili admin/rider erişimi: Kullanıcı ID: ${req.user.uid}, Rol: ${req.user.role}`);
        next();
        return;
    }
    console.warn(`[isAdminOrRiderMiddleware] Yetkisiz erişim. Token: ${token}, Ayrıştırılan Rol: ${decodedToken ? decodedToken.role : 'Yok'}. Admin veya Rider yetkisi gerekli.`);
    res.status(403).json({ message: 'Yetkisiz erişim. Admin veya Rider yetkisi gerekli.' });
}


// 🔐 AUTHENTICATION ENDPOINTS
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Kullanıcı adı ve parola gerekli.' });
    }

    try {
        const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

        if (!user) {
            console.log(`[Login] Kullanıcı bulunamadı: ${username}`);
            return res.status(401).json({ message: 'Geçersiz kullanıcı adı veya parola.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            console.log(`[Login] Yanlış parola for kullanıcı: ${username}`);
            return res.status(401).json({ message: 'Geçersiz kullanıcı adı veya parola.' });
        }

        const token = `${user.id}.${user.role}.${Date.now()}`; 
        console.log(`[Login] Başarılı giriş: ${username}, Rol: ${user.role}, Token: ${token.substring(0, 20)}...`);

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

// Yeni çalışan kaydı (Admin yetkisi gerektirir)
app.post('/api/register-employee', isAdminMiddleware, async (req, res) => {
    const { username, password, full_name, role } = req.body;

    if (!username || !password || !full_name || !role) {
        return res.status(400).json({ message: 'Kullanıcı adı, parola, tam ad ve rol gerekli.' });
    }

    const validRoles = ['employee', 'admin', 'rider', 'garson'];
    if (!validRoles.includes(role)) {
        return res.status(400).json({ message: 'Geçersiz rol belirtildi.' });
    }

    try {
        const existingUser = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
        if (existingUser) {
            return res.status(409).json({ message: 'Bu kullanıcı adı zaten mevcut.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = uuidv4();
        const stmt = db.prepare("INSERT INTO users (id, username, password, full_name, role) VALUES (?, ?, ?, ?, ?)");
        stmt.run(userId, username, hashedPassword, full_name, role);
        
        if (role === 'rider') {
            db.prepare("INSERT INTO riders (id, username, full_name, delivered_count) VALUES (?, ?, ?, ?)").run(userId, username, full_name, 0);
        }

        res.status(201).json({
            message: 'Çalışan başarıyla oluşturuldu.',
            user: { id: userId, username, full_name, role: role }
        });
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed')) {
            return res.status(409).json({ message: 'Bu kullanıcı adı zaten mevcut.' });
        }
        console.error('Çalışan kayıt hatası:', error);
        res.status(500).json({ message: 'Kayıt sırasında bir hata oluştu.' });
    }
});

// Çalışan girişi (Employee rolü için) - Bu endpoint'i kullanmıyorsanız kaldırabilirsiniz
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

        const token = `${user.id}.${user.role}.${Date.now()}`;
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

// Admin girişi (Admin rolü için) - Bu endpoint'i kullanmıyorsanız kaldırabilirsiniz
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

        const token = `${user.id}.${user.role}.${Date.now()}`;
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

// ⚙️ APP SETTINGS ENDPOINTS (Admin/Garson/Rider yetkisi gerektirir)
app.get('/api/order-status', isAdminOrGarsonOrRiderMiddleware, (req, res) => { 
    try {
        const result = db.prepare("SELECT value FROM settings WHERE key = 'isOrderTakingEnabled'").get();
        const enabled = result && result.value === 'true';
        res.json({ enabled: enabled });
    } catch (error) {
        console.error('Veritabanından sipariş durumu okunurken hata:', error);
        res.status(500).json({ error: 'Sipariş durumu sorgulanırken bir hata oluştu.' });
    }
});

app.post('/api/set-order-status', isAdminMiddleware, (req, res) => {
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

// 📊 PRODUCT ENDPOINTS (Admin/Garson/Rider yetkisi gerektirir)
app.get('/api/products', isAdminOrGarsonOrRiderMiddleware, (req, res) => { 
    try {
        const products = db.prepare("SELECT * FROM products ORDER BY name ASC").all();
        res.status(200).json(products);
    }
    catch (error) {
        console.error('Ürünleri çekerken hata:', error);
        res.status(500).json({ message: 'Ürünler alınırken bir hata oluştu.' });
    }
});

app.post('/api/products/add', isAdminMiddleware, (req, res) => {
    const { name, price, category, description } = req.body;
    if (!name || price === undefined) {
        return res.status(400).json({ message: 'Ürün adı ve fiyatı gerekli.' });
    }
    try {
        const stmt = db.prepare("INSERT INTO products (name, price, category, description) VALUES (?, ?, ?, ?)");
        stmt.run(name, price, category || null, description || null);
        io.emit('menuUpdated');
        res.status(201).json({ message: 'Ürün başarıyla eklendi.', product: { name, price, category, description } });
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed')) {
            return res.status(409).json({ message: 'Bu ürün adı zaten mevcut.' });
        }
        console.error('Ürün ekleme hatası:', error);
        res.status(500).json({ message: 'Ürün eklenirken bir hata oluştu.' });
    }
});

app.put('/api/products/update/:id', isAdminMiddleware, (req, res) => {
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

app.delete('/api/products/delete/:id', isAdminMiddleware, (req, res) => {
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

// FCM Token kayıt endpoint'i
app.post('/api/register-fcm-token', (req, res) => {
    console.log(`[${new Date().toLocaleTimeString()}] /api/register-fcm-token endpoint'ine istek geldi. Body:`, req.body);
    const { token, username, role } = req.body;
    if (!token || !username || !role) {
        console.error('FCM Token kayıt hatası: Token, username veya role eksik.', { token, username, role });
        return res.status(400).json({ message: 'Token, username ve role gereklidir.' });
    }
    fcmTokens[username] = { token, role };
    console.log(`FCM Token kaydedildi: Kullanıcı: ${username}, Rol: ${role}`);
    res.status(200).send({ message: 'Token başarıyla kayıt edildi.' });
});

// FCM Tokenları listeleme endpoint'i (Admin yetkisi gerektirir)
app.get('/api/fcm-tokens', isAdminMiddleware, (req, res) => {
    console.log('FCM Tokenlar listeleniyor:', fcmTokens);
    res.status(200).json(fcmTokens);
});

// 📦 ORDER ENDPOINTS
app.post('/api/order', async (req, res) => {
    console.log(`[${new Date().toLocaleTimeString()}] /api/order endpoint'ine istek geldi.`);
    try {
        const orderStatus = db.prepare("SELECT value FROM settings WHERE key = 'isOrderTakingEnabled'").get();
        const isOrderTakingEnabled = orderStatus && orderStatus.value === 'true';

        console.log(`[${new Date().toLocaleTimeString()}] Sipariş alım durumu: ${isOrderTakingEnabled ? 'AÇIK' : 'KAPALI'}`);

        if (!isOrderTakingEnabled) {
            return res.status(403).json({ error: 'Sipariş alımı şu anda kapalıdır.' });
        }

        const orderData = req.body;

        if (!orderData || !orderData.masaId || !orderData.masaAdi || orderData.toplamFiyat === undefined || !orderData.sepetItems) {
            console.error(`[${new Date().toLocaleTimeString()}] Eksik sipariş verisi:`, orderData);
            return res.status(400).json({ error: 'Eksik sipariş verisi. Masa ID, Masa Adı, Toplam Fiyat ve Sepet Ürünleri gereklidir.' });
        }

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

        try {
            db.prepare(`INSERT INTO orders (orderId, masaId, masaAdi, sepetItems, toplamFiyat, timestamp, status, deliveryStatus) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
                orderId,
                masaId,
                masaAdi,
                sepetItemsJson,
                toplamFiyat,
                timestamp,
                'pending',
                'pending'
            );
            console.log(`[${new Date().toLocaleTimeString()}] Yeni sipariş SQLite'a başarıyla kaydedildi. ID: ${orderId}`);
        } catch (dbError) {
            console.error(`[${new Date().toLocaleTimeString()}] SQLite'a sipariş kaydedilirken hata:`, dbError.message);
            return res.status(500).json({ error: 'Sipariş veritabanına kaydedilirken bir hata oluştu.' });
        }

        const newOrderToSend = {
            orderId: orderId,
            masaId: masaId,
            masaAdi: masaAdi,
            sepetItems: sepetItems,
            toplamFiyat: toplamFiyat,
            timestamp: timestamp,
            status: 'pending',
            deliveryStatus: 'pending'
        };

        console.log(`[${new Date().toLocaleTimeString()}] Socket.IO üzerinden 'newOrder' olayını tetikliyor.`);
        let emittedToClients = 0;
        connectedClients.forEach((clientSocketId, clientInfo) => {
            if (clientInfo.role === 'admin' || clientInfo.role === 'garson') {
                io.to(clientSocketId).emit('newOrder', newOrderToSend);
                console.log(`[${new Date().toLocaleTimeString()}] 'newOrder' olayı ${clientInfo.username} (${clientInfo.role}) kullanıcısına gönderildi.`);
                emittedToClients++;
            }
        });
        if (emittedToClients === 0) {
            console.warn(`[${new Date().toLocaleTimeString()}] 'newOrder' olayı hiçbir admin/garson istemcisine gönderilemedi. Hiçbiri bağlı olmayabilir.`);
        }
        io.emit('notificationSound', { play: true });

        console.log(`[${new Date().toLocaleTimeString()}] FCM Bildirimleri gönderilmeye başlanıyor. Kayıtlı token sayısı: ${Object.keys(fcmTokens).length}`);
        for (const username in fcmTokens) {
            const userData = fcmTokens[username];
            if (userData.role === 'admin') {
                console.log(`[${new Date().toLocaleTimeString()}] Admin rolündeki kullanıcı (${username}) için FCM bildirimi hazırlanıyor. Token: ${userData.token.substring(0, 10)}...`);
                const message = {
                    notification: {
                        title: 'Yeni Sipariş!',
                        body: `Masa ${masaAdi} için yeni bir siparişiniz var. Toplam: ${toplamFiyat.toFixed(2)} TL`,
                    },
                    data: {
                        orderId: orderId.toString(),
                        masaAdi: masaAdi,
                        toplamFiyat: toplamFiyat.toFixed(2),
                        sepetItems: JSON.stringify(sepetItems),
                        type: 'new_order'
                    },
                    token: userData.token,
                };

                try {
                    const response = await admin.messaging().send(message);
                    console.log(`🔥 FCM bildirimi başarıyla gönderildi (${username}):`, response);
                } catch (error) {
                    console.error(`❌ FCM bildirimi gönderilirken hata oluştu (${username}):`, error);
                    if (error.code === 'messaging/invalid-registration-token' ||
                        error.code === 'messaging/registration-token-not-registered') {
                        console.warn(`Geçersiz veya kayıtlı olmayan token temizleniyor: ${username}`);
                        delete fcmTokens[username];
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

app.get('/api/orders/active', isAdminOrGarsonOrRiderMiddleware, (req, res) => { 
    try {
        const activeOrders = db.prepare(`SELECT * FROM orders WHERE status != 'paid' AND status != 'cancelled' ORDER BY timestamp DESC`).all();
        const parsedOrders = activeOrders.map(order => ({
            ...order,
            sepetItems: JSON.parse(order.sepetItems)
        }));
        console.log(`[${new Date().toLocaleTimeString()}] /api/orders/active endpoint'inden ${parsedOrders.length} aktif sipariş döndürüldü.`);
        res.status(200).json(parsedOrders);
    } catch (error) {
        console.error('Aktif siparişler çekilirken hata:', error);
        res.status(500).json({ message: 'Aktif siparişler alınırken bir hata oluştu.' });
    }
});

app.post('/api/assign-order', isAdminMiddleware, async (req, res) => {
    console.log(`[${new Date().toLocaleTimeString()}] /api/assign-order endpoint'ine istek geldi.`);
    const { orderId, riderUsername, deliveryAddress, paymentMethod } = req.body;

    if (!orderId || !riderUsername || !deliveryAddress || !paymentMethod) {
        console.error('Sipariş atama hatası: Eksik veri.', req.body);
        return res.status(400).json({ message: 'Sipariş ID, motorcu kullanıcı adı, teslimat adresi ve ödeme yöntemi gereklidir.' });
    }

    try {
        const assignedTimestamp = new Date().toISOString();

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

        const assignedOrder = db.prepare(`SELECT * FROM orders WHERE orderId = ?`).get(orderId);
        assignedOrder.sepetItems = JSON.parse(assignedOrder.sepetItems);

        console.log(`Sipariş ${orderId} motorcu ${riderUsername} adresine (${deliveryAddress}) atandı. Delivery Status: ${assignedOrder.deliveryStatus}`);
        
        connectedClients.forEach((clientSocketId, clientInfo) => {
            if (clientInfo.role === 'rider' && clientInfo.username === riderUsername) {
                io.to(clientSocketId).emit('orderAssignedToRider', assignedOrder);
            } else if (clientInfo.role === 'admin' || clientInfo.role === 'garson') {
                io.to(clientSocketId).emit('orderAssigned', assignedOrder);
            }
        });

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
                    type: 'new_delivery_order'
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

// 👥 USER MANAGEMENT ENDPOINTS (Admin yetkisi gerektirir)
app.get('/api/users', isAdminMiddleware, (req, res) => {
    try {
        const users = db.prepare("SELECT id, username, full_name, role FROM users").all();
        res.json(users);
    } catch (error) {
        console.error('Kullanıcılar çekilirken hata:', error);
        res.status(500).json({ message: 'Kullanıcılar alınırken bir hata oluştu.' });
    }
});

// Yeni çalışan ekleme endpoint'i (önceki register-employee ile aynı işlevi görür, ancak daha genel bir isim)
app.post('/api/users', isAdminMiddleware, async (req, res) => {
    const { username, password, full_name, role } = req.body;

    if (!username || !password || !full_name || !role) {
        return res.status(400).json({ message: 'Kullanıcı adı, parola, tam ad ve rol gerekli.' });
    }

    const validRoles = ['employee', 'admin', 'rider', 'garson'];
    if (!validRoles.includes(role)) {
        return res.status(400).json({ message: 'Geçersiz rol belirtildi.' });
    }

    try {
        const existingUser = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
        if (existingUser) {
            return res.status(409).json({ message: 'Bu kullanıcı adı zaten mevcut.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = uuidv4();
        const stmt = db.prepare("INSERT INTO users (id, username, password, full_name, role) VALUES (?, ?, ?, ?, ?)");
        stmt.run(userId, username, hashedPassword, full_name, role);
        
        if (role === 'rider') {
            db.prepare("INSERT INTO riders (id, username, full_name, delivered_count) VALUES (?, ?, ?, ?)").run(userId, username, full_name, 0);
        }

        res.status(201).json({
            message: 'Çalışan başarıyla oluşturuldu.',
            user: { id: userId, username, full_name, role: role }
        });
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed')) {
            return res.status(409).json({ message: 'Bu kullanıcı adı zaten mevcut.' });
        }
        console.error('Çalışan ekleme hatası:', error);
        res.status(500).json({ message: 'Çalışan eklenirken bir hata oluştu.' });
    }
});


app.delete('/api/users/:id', isAdminMiddleware, (req, res) => {
    const { id } = req.params;
    try {
        const user = db.prepare("SELECT username, role FROM users WHERE id = ?").get(id);
        if (!user) {
            return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
        }
        if (req.user.uid === id) {
             return res.status(403).json({ message: 'Kendi hesabınızı silemezsiniz.' });
        }

        db.prepare("DELETE FROM users WHERE id = ?").run(id);

        if (user.role === 'rider') {
            db.prepare("DELETE FROM riders WHERE username = ?").run(user.username);
            if (riderLocations[user.username]) {
                delete riderLocations[user.username];
                connectedClients.forEach((clientSocketId, clientInfo) => {
                    if (clientInfo.role === 'admin' || clientInfo.role === 'garson') {
                        io.to(clientSocketId).emit('riderDisconnected', user.username);
                    }
                });
            }
        }

        res.status(200).json({ message: 'Kullanıcı başarıyla silindi.' });
    } catch (error) {
        console.error('Kullanıcı silinirken hata:', error);
        res.status(500).json({ message: 'Kullanıcı silinirken bir hata oluştu.' });
    }
});

// Yeni endpoint: Tüm motorcu kullanıcılarını döndürür
app.get('/api/riders', isAdminOrGarsonOrRiderMiddleware, (req, res) => {
    console.log(`[${new Date().toLocaleTimeString()}] /api/riders endpoint'ine istek geldi.`);
    try {
        const riders = db.prepare("SELECT id, username, full_name FROM users WHERE role = 'rider'").all();
        console.log(`[${new Date().toLocaleTimeString()}] /api/riders endpoint'inden ${riders.length} motorcu döndürüldü.`);
        res.status(200).json(riders);
    } catch (error) {
        console.error('Motorcu kullanıcıları çekilirken hata:', error);
        res.status(500).json({ message: 'Motorcu kullanıcıları alınırken bir hata oluştu.' });
    }
});


// 🛵 RIDER ENDPOINTS
app.post('/api/update-order-delivery-status', isAdminOrRiderMiddleware, async (req, res) => {
    console.log(`[${new Date().toLocaleTimeString()}] /api/update-order-delivery-status endpoint'ine istek geldi.`);
    const { orderId, newDeliveryStatus, username } = req.body;

    if (!orderId || !newDeliveryStatus || !username) {
        return res.status(400).json({ message: 'Sipariş ID, yeni teslimat durumu ve kullanıcı adı gereklidir.' });
    }

    const validStatuses = ['en_route', 'delivered', 'cancelled'];
    if (!validStatuses.includes(newDeliveryStatus)) {
        return res.status(400).json({ message: 'Geçersiz teslimat durumu belirtildi.' });
    }

    try {
        let updateQuery = `UPDATE orders SET deliveryStatus = ?`;
        const params = [newDeliveryStatus];
        
        if (newDeliveryStatus === 'delivered') {
            const deliveredTimestamp = new Date().toISOString();
            updateQuery += `, deliveredTimestamp = ?, status = 'paid'`;
            params.push(deliveredTimestamp);
            console.log(`[${new Date().toLocaleTimeString()}] Sipariş ${orderId} 'delivered' olarak işaretlendi. deliveredTimestamp: ${deliveredTimestamp}`);

            const rider = db.prepare("SELECT * FROM riders WHERE username = ?").get(username);
            if (rider) {
                const updatedCount = (rider.delivered_count || 0) + 1;
                db.prepare("UPDATE riders SET delivered_count = ? WHERE username = ?").run(updatedCount, username);
                console.log(`[${new Date().toLocaleTimeString()}] Motorcu ${username} için teslimat sayısı artırıldı: ${updatedCount}`);
            }
        } else if (newDeliveryStatus === 'cancelled') {
            updateQuery += `, riderUsername = NULL, deliveryAddress = NULL, paymentMethod = NULL, assignedTimestamp = NULL, deliveredTimestamp = NULL, status = 'cancelled'`;
            console.log(`[${new Date().toLocaleTimeString()}] Sipariş ${orderId} durumu '${newDeliveryStatus}' olarak değiştirildi ve motorcu bilgileri temizlendi.`);
        } else {
            updateQuery += `, deliveredTimestamp = NULL`;
            console.log(`[${new Date().toLocaleTimeString()}] Sipariş ${orderId} durumu '${newDeliveryStatus}' olarak değiştirildi. deliveredTimestamp temizlendi.`);
        }

        updateQuery += ` WHERE orderId = ?`;
        params.push(orderId);

        const stmt = db.prepare(updateQuery);
        const info = stmt.run(...params);

        if (info.changes === 0) {
            console.warn(`[${new Date().toLocaleTimeString()}] Sipariş (ID: ${orderId}) bulunamadı veya durumu zaten güncel. Değişiklik yapılmadı.`);
            return res.status(404).json({ message: 'Sipariş bulunamadı veya durumu zaten güncel.' });
        }

        console.log(`[${new Date().toLocaleTimeString()}] Sipariş ${orderId} teslimat durumu güncellendi: ${newDeliveryStatus}`);
        
        connectedClients.forEach((clientSocketId, clientInfo) => {
            if (clientInfo.role === 'admin' || clientInfo.role === 'garson') {
                io.to(clientSocketId).emit('orderDeliveryStatusUpdated', { orderId, newDeliveryStatus });
                if (newDeliveryStatus === 'delivered' || newDeliveryStatus === 'cancelled') {
                     io.to(clientSocketId).emit('removeOrderFromDisplay', { orderId: orderId });
                }
            }
        });

        if (newDeliveryStatus === 'delivered') {
            const deliveredOrder = db.prepare(`SELECT * FROM orders WHERE orderId = ?`).get(orderId);
            for (const userToken in fcmTokens) {
                const userData = fcmTokens[userToken];
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
                        console.log(`🔥 FCM bildirimi adminlere gönderildi (teslimat):`, userToken);
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

app.get('/api/rider/delivered-count/:username', isAdminOrRiderMiddleware, (req, res) => {
    const { username } = req.params;
    const today = new Date().toISOString().split('T')[0]; 

    try {
        console.log(`[${new Date().toLocaleTimeString()}] /api/rider/delivered-count/${username} isteği alındı. Bugünün tarihi (UTC): ${today}`);
        const deliveredCount = db.prepare(`
            SELECT COUNT(*) AS count FROM orders
            WHERE riderUsername = ? 
            AND deliveryStatus = 'delivered' 
            AND substr(deliveredTimestamp, 1, 10) = ?
        `).get(username, today);
        
        console.log(`[${new Date().toLocaleTimeString()}] Motorcu ${username} için bugün teslim edilen paket sayısı: ${deliveredCount.count}`);
        res.status(200).json({ deliveredCount: deliveredCount.count });
    } catch (error) {
        console.error(`[${new Date().toLocaleTimeString()}] Motorcu ${username} için teslim edilen paket sayısı çekilirken hata:`, error);
        res.status(500).json({ message: 'Teslim edilen paket sayısı alınırken bir hata oluştu.' });
    }
});

app.get('/api/rider/orders/:username', isAdminOrRiderMiddleware, (req, res) => {
    const { username } = req.params;
    console.log(`[${new Date().toLocaleTimeString()}] /api/rider/orders/${username} isteği alındı.`);
    try {
        const orders = db.prepare(`
            SELECT * FROM orders
            WHERE riderUsername = ? AND (deliveryStatus = 'assigned' OR deliveryStatus = 'en_route')
            ORDER BY assignedTimestamp DESC
        `).all(username);

        const parsedOrders = orders.map(order => ({
            ...order,
            sepetItems: JSON.parse(order.sepetItems)
        }));
        console.log(`[${new Date().toLocaleTimeString()}] Motorcu ${username} için ${parsedOrders.length} atanmış sipariş döndürüldü.`);
        res.status(200).json(parsedOrders);
    } catch (error) {
        console.error(`[${new Date().toLocaleTimeString()}] Motorcu ${username} için atanmış siparişler çekilirken hata:`, error);
        res.status(500).json({ message: 'Atanmış siparişler alınırken bir hata oluştu.' });
    }
});

app.post('/api/rider/end-day', isAdminOrRiderMiddleware, async (req, res) => {
    console.log(`[${new Date().toLocaleTimeString()}] /api/rider/end-day endpoint'ine istek geldi.`);
    const { username } = req.body;

    if (!username) {
        console.error(`[${new Date().toLocaleTimeString()}] /api/rider/end-day: Kullanıcı adı eksik.`);
        return res.status(400).json({ message: 'Kullanıcı adı gerekli.' });
    }

    try {
        const today = new Date().toISOString().split('T')[0];
        console.log(`[${new Date().toLocaleTimeString()}] Günü sonlandırılıyor. Bugünün tarihi (UTC) teslimat sayımı için: ${today}`);

        const deliveredCountResult = db.prepare(`
            SELECT COUNT(*) AS count FROM orders
            WHERE riderUsername = ? AND deliveryStatus = 'delivered' AND substr(deliveredTimestamp, 1, 10) = ?
        `).get(username, today);
        const deliveredCount = deliveredCountResult ? deliveredCountResult.count : 0;
        console.log(`[${new Date().toLocaleTimeString()}] Günü sonlandırma öncesi hesaplanan teslimat sayısı: ${deliveredCount}`);

        db.prepare(`
            UPDATE orders
            SET deliveryStatus = 'cancelled', riderUsername = NULL, deliveryAddress = NULL, paymentMethod = NULL, assignedTimestamp = NULL, deliveredTimestamp = NULL
            WHERE riderUsername = ? AND (deliveryStatus = 'assigned' OR deliveryStatus = 'en_route')
        `).run(username);
        console.log(`[${new Date().toLocaleTimeString()}] Motorcu ${username} için teslim edilmeyen siparişler iptal edildi.`);

        db.prepare("UPDATE riders SET delivered_count = 0 WHERE username = ?").run(username);
        console.log(`[${new Date().toLocaleTimeString()}] Motorcu ${username} için teslimat sayacı veritabanında sıfırlandı.`);

        connectedClients.forEach((clientSocketId, clientInfo) => {
            if (clientInfo.role === 'admin' || clientInfo.role === 'garson') {
                io.to(clientSocketId).emit('riderDayEnded', { username, deliveredCount: deliveredCount });
                io.to(clientSocketId).emit('riderDisconnected', username);
            }
        });
        
        res.status(200).json({
            message: `Motorcu ${username} günü sonlandırdı.`,
            totalDeliveredPackagesToday: deliveredCount
        });

    } catch (error) {
        console.error(`[${new Date().toLocaleTimeString()}] Motorcunun gününü sonlandırırken hata oluştu:`, error);
        res.status(500).json({ message: 'Günü sonlandırırken bir hata oluştu.' });
    }
});

app.get('/api/riders-locations', isAdminOrGarsonOrRiderMiddleware, (req, res) => { 
    try {
        const activeRiders = Object.values(riderLocations).map(rider => ({
            id: rider.id,
            username: rider.username,
            name: rider.full_name,
            fullName: rider.full_name,
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


app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});


io.on('connection', (socket) => {
    console.log(`[${new Date().toLocaleTimeString()}] Yeni bağlantı: ${socket.id}`);

    socket.on('registerClient', (clientInfo) => {
        const { username, role, userId } = clientInfo;
        connectedClients.set(socket.id, { username, role, userId });
        console.log(`[Socket.IO] Client registered: ${socket.id} -> ${username} (${role}), User ID: ${userId}`);

        if (role === 'admin' || role === 'garson') { 
            const activeOrders = db.prepare("SELECT * FROM orders WHERE status != 'paid' AND status != 'cancelled' ORDER BY timestamp DESC").all();
            const parsedOrders = activeOrders.map(order => ({ ...order, sepetItems: JSON.parse(order.sepetItems) }));
            io.to(socket.id).emit('currentActiveOrders', parsedOrders);
            console.log(`[Socket.IO] ${username} (${role}) için ${parsedOrders.length} aktif sipariş gönderildi.`);

            io.to(socket.id).emit('currentRiderLocations', Object.values(riderLocations));
            console.log(`[Socket.IO] ${username} (${role}) için ${Object.values(riderLocations).length} motorcu konumu gönderildi.`);
        }
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
            accuracy,
            socketId: socket.id
        };

        connectedClients.forEach((clientSocketId, clientInfo) => {
            if (clientInfo.role === 'admin' || clientInfo.role === 'garson') { 
                io.to(clientSocketId).emit('newRiderLocation', riderLocations[username]);
            }
        });
        console.log(`Motorcu ${username} konum güncelledi: ${latitude}, ${longitude}`);
    });

    socket.on('orderPaid', (data) => {
        const { orderId } = data;
        console.log(`[${new Date().toLocaleTimeString()}] Sipariş ödendi olarak işaretlendi (Socket.IO): ${orderId}`);

        try {
            const info = db.prepare(`UPDATE orders SET status = 'paid' WHERE orderId = ? AND status = 'pending'`).run(orderId);
            if (info.changes > 0) {
                console.log(`Sipariş (ID: ${orderId}) SQLite'ta ödendi olarak güncellendi.`);
                connectedClients.forEach((clientSocketId, clientInfo) => {
                    if (clientInfo.role === 'admin' || clientInfo.role === 'garson') { 
                        io.to(clientSocketId).emit('orderPaidConfirmation', { orderId: orderId });
                        io.to(clientSocketId).emit('removeOrderFromDisplay', { orderId: orderId });
                    }
                });
            } else {
                console.warn(`Ödendi olarak işaretlenen sipariş (ID: ${orderId}) bulunamadı veya zaten ödenmiş.`);
            }
        } catch (error) {
            console.error('Siparişin durumunu güncellerken hata:', error.message);
        }
    });

    socket.on('disconnect', () => {
        console.log(`[${new Date().toLocaleTimeString()}] Bağlantı koptu: ${socket.id}`);
        const clientInfo = connectedClients.get(socket.id);
        if (clientInfo) {
            connectedClients.delete(socket.id);
            console.log(`Client disconnected: ${clientInfo.username} (${clientInfo.role})`);
            if (clientInfo.role === 'rider' && riderLocations[clientInfo.username] && riderLocations[clientInfo.username].socketId === socket.id) {
                delete riderLocations[clientInfo.username];
                connectedClients.forEach((clientSocketId, clientInfo) => {
                    if (clientInfo.role === 'admin' || clientInfo.role === 'garson') { 
                        io.to(clientSocketId).emit('riderDisconnected', clientInfo.username);
                    }
                });
            }
        }
    });
});


server.listen(PORT, () => {
    console.log(`🟢 Sunucu ayakta: http://localhost:${PORT}`);
});

process.on('exit', () => {
    db.close();
    console.log('SQLite veritabanı bağlantısı kapatıldı.');
});

process.on('SIGHUP', () => process.exit(1));
process.on('SIGINT', () => process.exit(1));
process.on('SIGTERM', () => process.exit(1));

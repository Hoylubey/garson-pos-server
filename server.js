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
    console.error('Firebase Admin SDK başlatılırken hata oluştu. Ortam değişkenini kontrol edin:', error.message);
}

const dbPath = path.join(__dirname, 'garson_pos.db');
const db = new Database(dbPath);

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

    // Yeni sütunları ekle, zaten varsa hata vermez
    db.exec(`
        ALTER TABLE orders ADD COLUMN riderUsername TEXT;
        ALTER TABLE orders ADD COLUMN deliveryAddress TEXT;
        ALTER TABLE orders ADD COLUMN paymentMethod TEXT;
        ALTER TABLE orders ADD COLUMN assignedTimestamp TEXT;
        ALTER TABLE orders ADD COLUMN deliveryStatus TEXT DEFAULT 'pending';
        ALTER TABLE orders ADD COLUMN deliveredTimestamp TEXT;
    `);
    console.log('Orders tablosuna yeni sütunlar eklendi (varsa).');

} catch (err) {
    if (!err.message.includes('duplicate column name')) {
        console.error('Orders tablosu oluşturma veya güncelleme hatası:', err.message);
    } else {
        console.log('Orders tablosu sütunları zaten mevcut.');
    }
}

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

const initialStatus = db.prepare("SELECT value FROM settings WHERE key = 'isOrderTakingEnabled'").get();
if (!initialStatus) {
    db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").run('isOrderTakingEnabled', 'true');
    console.log("Sipariş alımı durumu veritabanına varsayılan olarak 'true' eklendi.");
}

const fcmTokens = {};
const riderLocations = {};
const socketToUsername = {};

function isAdmin(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.warn('isAdmin: Yetkilendirme başlığı eksik veya hatalı formatta.');
        return res.status(401).json({ message: 'Yetkilendirme başlığı eksik veya hatalı formatta.' });
    }
    
    const token = authHeader.split(' ')[1];
    const parts = token.split('-');
    if (parts.length === 3) {
        const userRole = parts[1];
        if (userRole === 'admin') {
            next();
            return;
        }
    }
    console.warn('isAdmin: Token geçersiz veya yönetici yetkisi yok.');
    res.status(403).json({ message: 'Yetkisiz erişim. Yönetici yetkisi gerekli.' });
}

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
    console.warn('isAdminOrGarson: Token geçersiz veya yetkisiz erişim. Admin veya Garson yetkisi gerekli. Token parts:', parts);
    res.status(403).json({ message: 'Yetkisiz erişim. Admin veya Garson yetkisi gerekli.' });
}

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

app.post('/api/register-employee', isAdmin, async (req, res) => {
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

app.post('/api/products/add', isAdmin, (req, res) => {
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

app.delete('/api/products/delete/:id', isAdmin, (req, res) => {
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

app.get('/api/fcm-tokens', (req, res) => {
    console.log('FCM Tokenlar listeleniyor:', fcmTokens);
    res.status(200).json(fcmTokens);
});

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

app.post('/api/set-order-status', isAdmin, (req, res) => {
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

        console.log(`[${new Date().toLocaleTimeString()}] Socket.IO üzerinden 'newOrder' olayını tetikliyor: ${newOrderToSend.orderId}`);
        io.emit('newOrder', newOrderToSend);
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

app.get('/api/orders/active', isAdminOrGarson, (req, res) => {
    try {
        const activeOrders = db.prepare(`SELECT * FROM orders WHERE status = 'pending' ORDER BY timestamp DESC`).all();
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

app.post('/api/assign-order', isAdmin, async (req, res) => {
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

        console.log(`Sipariş ${orderId} motorcu ${riderUsername} adresine (${deliveryAddress}) atandı.`);
        io.emit('orderAssigned', assignedOrder);

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

app.post('/api/update-order-delivery-status', isAdminOrRider, async (req, res) => {
    console.log(`[${new Date().toLocaleTimeString()}] /api/update-order-delivery-status endpoint'ine istek geldi.`);
    const { orderId, newDeliveryStatus } = req.body;

    if (!orderId || !newDeliveryStatus) {
        return res.status(400).json({ message: 'Sipariş ID ve yeni teslimat durumu gereklidir.' });
    }

    const validStatuses = ['en_route', 'delivered', 'cancelled'];
    if (!validStatuses.includes(newDeliveryStatus)) {
        return res.status(400).json({ message: 'Geçersiz teslimat durumu belirtildi.' });
    }

    try {
        let updateQuery = `UPDATE orders SET deliveryStatus = ?`;
        const params = [newDeliveryStatus];
        let currentDeliveredTimestamp = null; // Log için tanımlandı

        if (newDeliveryStatus === 'delivered') {
            currentDeliveredTimestamp = new Date().toISOString(); // Yakalanan zaman damgası
            updateQuery += `, deliveredTimestamp = ?`;
            params.push(currentDeliveredTimestamp);
            console.log(`[${new Date().toLocaleTimeString()}] Sipariş ${orderId} 'delivered' olarak işaretlendi. deliveredTimestamp: ${currentDeliveredTimestamp}`);
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
        io.emit('orderDeliveryStatusUpdated', { orderId, newDeliveryStatus });

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

// YENİ ENDPOINT: Motorcunun bugün teslim ettiği paket sayısını getir
app.get('/api/rider/delivered-count/:username', isAdminOrRider, (req, res) => {
    const { username } = req.params;
    const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD formatı (UTC)

    try {
        console.log(`[${new Date().toLocaleTimeString()}] /api/rider/delivered-count/${username} isteği alındı. Bugünün tarihi (UTC): ${today}`);
        const deliveredCount = db.prepare(`
            SELECT COUNT(*) AS count FROM orders
            WHERE riderUsername = ? AND deliveryStatus = 'delivered' AND substr(deliveredTimestamp, 1, 10) = ?
        `).get(username, today);
        
        console.log(`[${new Date().toLocaleTimeString()}] Motorcu ${username} için bugün teslim edilen paket sayısı: ${deliveredCount.count}`);
        res.status(200).json({ deliveredCount: deliveredCount.count });
    } catch (error) {
        console.error(`[${new Date().toLocaleTimeString()}] Motorcu ${username} için teslim edilen paket sayısı çekilirken hata:`, error);
        res.status(500).json({ message: 'Teslim edilen paket sayısı alınırken bir hata oluştu.' });
    }
});


app.post('/api/rider/end-day', isAdminOrRider, async (req, res) => {
    console.log(`[${new Date().toLocaleTimeString()}] /api/rider/end-day endpoint'ine istek geldi.`);
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ message: 'Kullanıcı adı gerekli.' });
    }

    try {
        // Günü sonlandırmadan önce bugünün teslim edilen paket sayısını al
        const today = new Date().toISOString().split('T')[0];
        console.log(`[${new Date().toLocaleTimeString()}] Günü sonlandırılıyor. Bugünün tarihi (UTC) teslimat sayımı için: ${today}`);
        const deliveredCountResult = db.prepare(`
            SELECT COUNT(*) AS count FROM orders
            WHERE riderUsername = ? AND deliveryStatus = 'delivered' AND substr(deliveredTimestamp, 1, 10) = ?
        `).get(username, today);
        const deliveredCount = deliveredCountResult.count;

        // Teslim edilmeyen siparişleri iptal et
        db.prepare(`
            UPDATE orders
            SET deliveryStatus = 'cancelled', riderUsername = NULL, deliveryAddress = NULL, paymentMethod = NULL, assignedTimestamp = NULL, deliveredTimestamp = NULL
            WHERE riderUsername = ? AND (deliveryStatus = 'assigned' OR deliveryStatus = 'en_route')
        `).run(username);
        console.log(`[${new Date().toLocaleTimeString()}] Motorcu ${username} için teslim edilmeyen siparişler iptal edildi.`);

        io.emit('riderDayEnded', { username, deliveredCount: deliveredCount });

        res.status(200).json({
            message: `Motorcu ${username} günü sonlandırdı.`,
            totalDeliveredPackagesToday: deliveredCount // Frontend'in beklediği anahtar adı
        });

    } catch (error) {
        console.error('Motorcunun gününü sonlandırırken hata:', error);
        res.status(500).json({ message: 'Günü sonlandırırken bir hata oluştu.' });
    }
});

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

io.on('connection', (socket) => {
    console.log(`[${new Date().toLocaleTimeString()}] Yeni bağlantı: ${socket.id}`);

    socket.on('requestCurrentRiderLocations', () => {
        const currentRidersWithNames = Object.values(riderLocations).map(rider => ({
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
            username: username,
            name: user.full_name,
            fullName: user.full_name,
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

app.get('/api/riders-locations', (req, res) => {
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

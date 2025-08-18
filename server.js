const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const admin = require('firebase-admin');

// Firebase Admin SDK'sını başlat
const serviceAccount = require('./firebase-adminsdk.json');
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST", "PUT"]
    }
});

const PORT = 3000;
const db = new Database('./restoran_otomasyon.db');

app.use(express.json());
app.use(cors());

// Veritabanı tablolarını oluşturma
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS menu (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        urunAdi TEXT NOT NULL,
        fiyat REAL NOT NULL,
        kategori TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS orders (
        orderId TEXT PRIMARY KEY,
        masaId TEXT NOT NULL,
        masaAdi TEXT NOT NULL,
        sepetItems TEXT NOT NULL,
        toplamFiyat REAL NOT NULL,
        timestamp TEXT NOT NULL,
        status TEXT NOT NULL,
        riderUsername TEXT,
        deliveryStatus TEXT
    );

    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS riders (
        riderId TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL
    );
`);

// Örnek kullanıcı ekleme (yalnızca ilk çalıştırmada)
db.prepare("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)").run('admin', 'admin123', 'admin');
db.prepare("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)").run('garson1', 'garson123', 'garson');
db.prepare("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)").run('motorcu1', 'motorcu123', 'motorcu');

// Örnek ayar ekleme
db.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)").run('isOrderTakingEnabled', 'true');

// Middleware'ler
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (authHeader) {
        req.user = { role: authHeader.split(' ')[1], username: req.headers['username'] };
        next();
    } else {
        res.sendStatus(403);
    }
};

const isAdminMiddleware = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.sendStatus(403);
    }
};

const isGarsonMiddleware = (req, res, next) => {
    if (req.user && req.user.role === 'garson') {
        next();
    } else {
        res.sendStatus(403);
    }
};

const isAdminOrGarsonOrRiderMiddleware = (req, res, next) => {
    if (req.user && (req.user.role === 'admin' || req.user.role === 'garson' || req.user.role === 'motorcu')) {
        next();
    } else {
        res.sendStatus(403);
    }
};

// Bağlı istemcileri ve rol bilgilerini saklamak için Map
const connectedClients = new Map();
const fcmTokens = {};

// API Rotaları
app.get('/', (req, res) => {
    res.send('Restoran Otomasyon Sistemi API Çalışıyor.');
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE username = ? AND password = ?").get(username, password);

    if (user) {
        res.json({ token: `Bearer ${user.role}`, role: user.role, username: user.username, message: 'Giriş başarılı.' });
    } else {
        res.status(401).json({ message: 'Kullanıcı adı veya şifre hatalı.' });
    }
});

app.get('/api/users', isAdminMiddleware, (req, res) => {
    const users = db.prepare("SELECT * FROM users").all();
    res.json(users);
});

app.put('/api/users/role', isAdminMiddleware, (req, res) => {
    const { username, role } = req.body;
    db.prepare("UPDATE users SET role = ? WHERE username = ?").run(role, username);
    res.json({ message: 'Kullanıcı rolü güncellendi.' });
});

app.get('/api/menu', authenticateToken, (req, res) => {
    const menuItems = db.prepare("SELECT * FROM menu").all();
    res.json(menuItems);
});

app.post('/api/menu', isAdminMiddleware, (req, res) => {
    const { urunAdi, fiyat, kategori } = req.body;
    db.prepare("INSERT INTO menu (urunAdi, fiyat, kategori) VALUES (?, ?, ?)").run(urunAdi, fiyat, kategori);
    res.status(201).json({ message: 'Menü öğesi başarıyla eklendi.' });
});

app.put('/api/menu/:id', isAdminMiddleware, (req, res) => {
    const { id } = req.params;
    const { urunAdi, fiyat, kategori } = req.body;
    db.prepare("UPDATE menu SET urunAdi = ?, fiyat = ?, kategori = ? WHERE id = ?").run(urunAdi, fiyat, kategori, id);
    res.json({ message: 'Menü öğesi güncellendi.' });
});

app.delete('/api/menu/:id', isAdminMiddleware, (req, res) => {
    const { id } = req.params;
    db.prepare("DELETE FROM menu WHERE id = ?").run(id);
    res.json({ message: 'Menü öğesi silindi.' });
});

app.get('/api/orders', authenticateToken, (req, res) => {
    const { status, riderUsername } = req.query;
    let query = "SELECT * FROM orders";
    const params = [];
    const conditions = [];

    if (status) {
        conditions.push("status = ?");
        params.push(status);
    }
    if (riderUsername) {
        conditions.push("riderUsername = ?");
        params.push(riderUsername);
    }

    if (conditions.length > 0) {
        query += " WHERE " + conditions.join(" AND ");
    }
    query += " ORDER BY timestamp DESC";

    const orders = db.prepare(query).all(params);
    const ordersWithParsedItems = orders.map(order => ({
        ...order,
        sepetItems: JSON.parse(order.sepetItems)
    }));
    res.json(ordersWithParsedItems);
});

app.post('/api/order', authenticateToken, async (req, res) => {
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

        // Bu kısım, tüm bağlı istemcilere anında bildirim göndermek için güncellendi.
        console.log(`[${new Date().toLocaleTimeString()}] Socket.IO üzerinden 'newOrder' olayını tüm bağlı client'lara yayınlıyor.`);
        io.emit('newOrder', newOrderToSend);
        io.emit('notificationSound', { play: true });

        console.log(`[${new Date().toLocaleTimeString()}] FCM Bildirimleri gönderilmeye başlanıyor.`);
        for (const username in fcmTokens) {
            const userData = fcmTokens[username];
            if (userData.role === 'admin') {
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
                    await admin.messaging().send(message);
                    console.log(`🔥 FCM bildirimi başarıyla gönderildi (${username}).`);
                } catch (error) {
                    console.error(`❌ FCM bildirimi gönderilirken hata oluştu (${username}):`, error);
                    if (error.code === 'messaging/invalid-registration-token' ||
                        error.code === 'messaging/registration-token-not-registered') {
                        console.warn(`Geçersiz veya kayıtlı olmayan token temizleniyor: ${username}`);
                        delete fcmTokens[username];
                    }
                }
            }
        }

        res.status(200).json({ message: 'Sipariş işlendi.' });
    } catch (error) {
        console.error(`[${new Date().toLocaleTimeString()}] Sipariş işlenirken veya genel bir hata oluştu:`, error);
        res.status(500).json({ error: 'Sipariş işlenirken bir hata oluştu.' });
    }
});

// Yeni Eklenen Rota: Sipariş Durumu Güncelleme
app.put('/api/order-status-update', isAdminOrGarsonOrRiderMiddleware, (req, res) => {
    const { orderId, newStatus } = req.body;

    if (!orderId || !newStatus) {
        return res.status(400).json({ error: 'Sipariş ID veya yeni durum eksik.' });
    }

    try {
        const stmt = db.prepare("UPDATE orders SET status = ? WHERE orderId = ?");
        const info = stmt.run(newStatus, orderId);

        if (info.changes === 0) {
            return res.status(404).json({ error: 'Sipariş bulunamadı.' });
        }

        console.log(`[${new Date().toLocaleTimeString()}] Sipariş ID ${orderId} durumu ${newStatus} olarak güncellendi.`);
        
        // Durum değişikliğini tüm bağlı istemcilere anında yayınlıyoruz.
        io.emit('orderStatusUpdated', { orderId, newStatus });

        res.status(200).json({ message: 'Sipariş durumu başarıyla güncellendi.', orderId, newStatus });
    } catch (error) {
        console.error(`[${new Date().toLocaleTimeString()}] Sipariş durumu güncellenirken hata:`, error.message);
        res.status(500).json({ error: 'Sipariş durumu güncellenirken bir hata oluştu.' });
    }
});

// Ayarları Güncelleme
app.put('/api/settings', isAdminMiddleware, (req, res) => {
    const { key, value } = req.body;
    db.prepare("UPDATE settings SET value = ? WHERE key = ?").run(value, key);
    res.json({ message: 'Ayar güncellendi.' });
});

// Socket.IO bağlantıları
io.on('connection', (socket) => {
    console.log(`Bir kullanıcı bağlandı: ${socket.id}`);
    const clientRole = socket.handshake.query.role;
    const clientUsername = socket.handshake.query.username;
    if (clientRole && clientUsername) {
        connectedClients.set(socket.id, { role: clientRole, username: clientUsername });
        console.log(`- Rol: ${clientRole}, Kullanıcı: ${clientUsername}`);
    } else {
        console.log(`- Rol veya kullanıcı adı bilgisi eksik.`);
    }

    socket.on('disconnect', () => {
        console.log(`Bir kullanıcı ayrıldı: ${socket.id}`);
        connectedClients.delete(socket.id);
    });

    socket.on('registerToken', (token, username) => {
        if (token && username) {
            fcmTokens[username] = { token, role: clientRole };
            console.log(`FCM token kaydedildi: ${username}`);
        }
    });

    socket.on('removeToken', (token, username) => {
        if (fcmTokens[username]) {
            delete fcmTokens[username];
            console.log(`FCM token silindi: ${username}`);
        }
    });
});

server.listen(PORT, () => {
    console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor.`);
});

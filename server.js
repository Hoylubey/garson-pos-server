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
    console.error('Firebase Admin SDK başlatılırken hata:', error);
    console.error('FIREBASE_SERVICE_ACCOUNT_KEY ortam değişkeni doğru ayarlanmamış veya JSON formatı bozuk.');
    process.exit(1); // Uygulamayı sonlandır
}

// SQLite Veritabanı Bağlantısı
const db = new Database('garson_pos.db', { verbose: console.log }); // verbose ile logları görebilirsiniz

// Veritabanı tablolarını oluştur (Eğer yoksa)
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT
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

    CREATE TABLE IF NOT EXISTS orders (
        orderId TEXT PRIMARY KEY,
        masaId INTEGER NOT NULL,
        masaAdi TEXT NOT NULL,
        sepetItems TEXT NOT NULL, -- JSON string olarak saklanacak
        toplamFiyat REAL NOT NULL,
        timestamp INTEGER NOT NULL,
        status TEXT NOT NULL, -- 'pending', 'paid', 'cancelled'
        riderUsername TEXT,
        deliveryAddress TEXT,
        paymentMethod TEXT,
        deliveryStatus TEXT, -- 'pending', 'assigned', 'en_route', 'delivered', 'cancelled'
        assignedTimestamp TEXT, -- Siparişin motorcuya atandığı zaman (ISO string)
        deliveredTimestamp TEXT -- Siparişin teslim edildiği zaman (ISO string)
    );

    CREATE TABLE IF NOT EXISTS app_settings (
        setting_key TEXT PRIMARY KEY,
        setting_value TEXT
    );
`);

// Veritabanı şemasını kontrol et ve gerekirse sütunları ekle (Migration-like)
const checkAndAlterTables = () => {
    try {
        // orders tablosunda assignedTimestamp sütunu var mı kontrol et
        const assignedTimestampExists = db.prepare("PRAGMA table_info(orders)").all().some(column => column.name === 'assignedTimestamp');
        if (!assignedTimestampExists) {
            db.exec("ALTER TABLE orders ADD COLUMN assignedTimestamp TEXT;");
            console.log("orders tablosuna 'assignedTimestamp' sütunu eklendi.");
        }

        // orders tablosunda deliveredTimestamp sütunu var mı kontrol et
        const deliveredTimestampExists = db.prepare("PRAGMA table_info(orders)").all().some(column => column.name === 'deliveredTimestamp');
        if (!deliveredTimestampExists) {
            db.exec("ALTER TABLE orders ADD COLUMN deliveredTimestamp TEXT;");
            console.log("orders tablosuna 'deliveredTimestamp' sütunu eklendi.");
        }
    } catch (error) {
        console.error("Veritabanı şeması kontrol edilirken/güncellenirken hata:", error);
    }
};
checkAndAlterTables(); // Uygulama başladığında şema kontrolünü çalıştır

// Varsayılan yönetici kullanıcısını ekle (sadece uygulama ilk çalıştığında)
const setupDefaultAdmin = () => {
    try {
        const users = [
            { username: 'admin', password: 'admin123', role: 'admin', fullName: 'Sistem Yöneticisi' },
            { username: 'garson', password: 'garson123', role: 'garson', fullName: 'Garson Personel' },
            { username: 'motorcu', password: 'motorcu123', role: 'rider', fullName: 'Motorcu Personel' }
        ];

        users.forEach(user => {
            const existingUser = db.prepare("SELECT * FROM users WHERE username = ?").get(user.username);
            if (!existingUser) {
                const hashedPassword = bcrypt.hashSync(user.password, 10);
                db.prepare("INSERT INTO users (id, username, password, role, full_name) VALUES (?, ?, ?, ?, ?)").run(uuidv4(), user.username, hashedPassword, user.role, user.fullName);
                console.log(`Varsayılan kullanıcı oluşturuldu: ${user.username}/${user.password}`);
            } else {
                console.log(`Varsayılan kullanıcı ${user.username} zaten mevcut.`);
            }
        });

        // Varsayılan sipariş alım durumunu ayarla (eğer yoksa)
        const orderStatusSetting = db.prepare("SELECT setting_value FROM app_settings WHERE setting_key = 'order_reception_enabled'").get();
        if (!orderStatusSetting) {
            db.prepare("INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?)").run('order_reception_enabled', 'true');
            console.log('Varsayılan sipariş alım durumu ayarlandı: AÇIK');
        }

    } catch (error) {
        console.error('Varsayılan kullanıcılar veya ayarlar oluşturulurken hata:', error);
    }
};
setupDefaultAdmin();


// Aktif motorcu konumlarını saklamak için geçici bellek (veritabanı yerine)
// Gerçek bir uygulamada bu veritabanında veya Redis gibi bir cache sisteminde tutulmalıdır.
const riderLocations = {}; // { username: { id, username, full_name, latitude, longitude, timestamp, speed, bearing, accuracy, socketId } }

// Bağlı istemcileri rol ve kullanıcı adıyla takip etmek için Map
const connectedClients = new Map(); // Map<socketId, { userId, username, role }>

// 🔐 AUTHENTICATION ENDPOINTS
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

        if (!user) {
            return res.status(401).json({ message: 'Kullanıcı adı veya parola yanlış.' });
        }

        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Kullanıcı adı veya parola yanlış.' });
        }

        // Firebase Custom Token oluştur
        const customToken = await admin.auth().createCustomToken(user.id, { role: user.role, username: user.username, full_name: user.full_name });

        res.json({ message: 'Giriş başarılı!', token: customToken, role: user.role, user: { id: user.id, username: user.username, full_name: user.full_name } });

    } catch (error) {
        console.error('Giriş hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

// Middleware for token verification
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: 'Yetkilendirme tokenı bulunamadı.' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Yetkilendirme tokenı hatalı formatta.' });
    }

    try {
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.user = decodedToken; // Attach user info to request
        next();
    } catch (error) {
        console.error('Token doğrulama hatası:', error);
        return res.status(403).json({ message: 'Geçersiz veya süresi dolmuş token.' });
    }
};

// Middleware for admin role check
const isAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ message: 'Bu işlemi yapmaya yetkiniz yok. Yönetici yetkisi gereklidir.' });
    }
};

// Middleware for admin or garson role check
const isAdminOrGarson = (req, res, next) => {
    if (req.user && (req.user.role === 'admin' || req.user.role === 'garson')) {
        next();
    } else {
        res.status(403).json({ message: 'Bu işlemi yapmaya yetkiniz yok.' });
    }
};

// Middleware for admin or rider role check
const isAdminOrRider = (req, res, next) => {
    if (req.user && (req.user.role === 'admin' || req.user.role === 'rider')) {
        next();
    } else {
        res.status(403).json({ message: 'Bu işlemi yapmaya yetkiniz yok.' });
    }
};

// ⚙️ APP SETTINGS ENDPOINTS (Admin/Garson yetkisi gerektirir)
app.get('/api/order-status', verifyToken, isAdminOrGarson, (req, res) => {
    try {
        const setting = db.prepare("SELECT setting_value FROM app_settings WHERE setting_key = 'order_reception_enabled'").get();
        const enabled = setting ? setting.setting_value === 'true' : false;
        res.json({ enabled });
    } catch (error) {
        console.error('Sipariş alım durumu çekilirken hata:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

app.post('/api/set-order-status', verifyToken, isAdminOrGarson, (req, res) => {
    const { enabled } = req.body;
    try {
        db.prepare("REPLACE INTO app_settings (setting_key, setting_value) VALUES (?, ?)").run('order_reception_enabled', enabled.toString());
        io.emit('orderTakingStatusChanged', { enabled: enabled }); // Tüm bağlı istemcilere durumu bildir
        res.json({ message: 'Sipariş alım durumu güncellendi.', newStatus: enabled });
    } catch (error) {
        console.error('Sipariş alım durumu güncellenirken hata:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

// 📦 ORDER ENDPOINTS (Admin/Garson yetkisi gerektirir)
app.get('/api/orders/active', verifyToken, isAdminOrGarson, (req, res) => {
    try {
        // 'paid' veya 'cancelled' olmayan siparişleri getir
        const activeOrders = db.prepare("SELECT * FROM orders WHERE status != 'paid' AND status != 'cancelled' ORDER BY timestamp DESC").all();
        // sepetItems'ı JSON'dan parse et
        const parsedOrders = activeOrders.map(order => ({
            ...order,
            sepetItems: JSON.parse(order.sepetItems)
        }));
        res.json(parsedOrders);
    } catch (error) {
        console.error('Aktif siparişler çekilirken hata:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

app.post('/api/assign-order', verifyToken, isAdminOrGarson, (req, res) => {
    const { orderId, riderUsername, deliveryAddress, paymentMethod } = req.body;

    if (!orderId || !riderUsername || !deliveryAddress || !paymentMethod) {
        return res.status(400).json({ message: 'Eksik bilgi: orderId, riderUsername, deliveryAddress ve paymentMethod gereklidir.' });
    }

    try {
        const order = db.prepare("SELECT * FROM orders WHERE orderId = ?").get(orderId);
        if (!order) {
            return res.status(404).json({ message: 'Sipariş bulunamadı.' });
        }

        // Siparişi güncelle, assignedTimestamp'ı da kaydet
        db.prepare("UPDATE orders SET riderUsername = ?, deliveryAddress = ?, paymentMethod = ?, deliveryStatus = ?, assignedTimestamp = ? WHERE orderId = ?").run(riderUsername, deliveryAddress, paymentMethod, 'assigned', new Date().toISOString(), orderId);

        const updatedOrder = db.prepare("SELECT * FROM orders WHERE orderId = ?").get(orderId);
        updatedOrder.sepetItems = JSON.parse(updatedOrder.sepetItems); // JSON string'i parse et

        io.emit('orderAssigned', updatedOrder); // Motorcu uygulamasına ve diğer panellere bildir
        res.json({ message: 'Sipariş başarıyla atandı!', order: updatedOrder });

    } catch (error) {
        console.error('Sipariş atanırken hata:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

// 👥 USER MANAGEMENT ENDPOINTS (Admin yetkisi gerektirir)
app.get('/api/users', verifyToken, isAdmin, (req, res) => {
    try {
        const users = db.prepare("SELECT id, username, role, full_name FROM users").all();
        res.json(users);
    } catch (error) {
        console.error('Kullanıcılar çekilirken hata:', error);
        res.status(500).json({ message: 'Kullanıcılar alınırken bir hata oluştu.' });
    }
});

app.post('/api/users', verifyToken, isAdmin, async (req, res) => {
    const { username, password, role, full_name } = req.body;
    if (!username || !password || !role || !full_name) {
        return res.status(400).json({ message: 'Kullanıcı adı, parola, rol ve tam ad gerekli.' });
    }
    try {
        const existingUser = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
        if (existingUser) {
            return res.status(409).json({ message: 'Bu kullanıcı adı zaten mevcut.' });
        }
        const hashedPassword = bcrypt.hashSync(password, 10);
        const userId = uuidv4();
        db.prepare("INSERT INTO users (id, username, password, role, full_name) VALUES (?, ?, ?, ?, ?)").run(userId, username, hashedPassword, role, full_name);

        // Eğer yeni kullanıcı bir motorcu ise, riders tablosuna da ekle
        if (role === 'rider') {
            db.prepare("INSERT INTO riders (id, username, full_name, delivered_count) VALUES (?, ?, ?, ?)").run(userId, username, full_name, 0);
        }

        res.status(201).json({ message: 'Kullanıcı başarıyla eklendi.', user: { id: userId, username, role, full_name } });
    } catch (error) {
        console.error('Kullanıcı eklenirken hata:', error);
        res.status(500).json({ message: 'Kullanıcı eklenirken bir hata oluştu.' });
    }
});

app.delete('/api/users/:id', verifyToken, isAdmin, (req, res) => {
    const { id } = req.params;
    try {
        const user = db.prepare("SELECT username, role FROM users WHERE id = ?").get(id);
        if (!user) {
            return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
        }
        // Kendi kendini silmeyi engelle
        if (req.user.uid === id) {
             return res.status(403).json({ message: 'Kendi hesabınızı silemezsiniz.' });
        }

        db.prepare("DELETE FROM users WHERE id = ?").run(id);

        // Eğer silinen kullanıcı bir motorcu ise, riders tablosundan da sil
        if (user.role === 'rider') {
            db.prepare("DELETE FROM riders WHERE username = ?").run(user.username);
            // Eğer motorcu aktifse, konumunu da temizle ve diğer istemcilere bildir
            if (riderLocations[user.username]) {
                delete riderLocations[user.username];
                io.emit('riderDisconnected', user.username);
            }
        }

        res.status(200).json({ message: 'Kullanıcı başarıyla silindi.' });
    } catch (error) {
        console.error('Kullanıcı silinirken hata:', error);
        res.status(500).json({ message: 'Kullanıcı silinirken bir hata oluştu.' });
    }
});


// 🛵 RIDER ENDPOINTS (Rider yetkisi gerektirir)
app.post('/api/rider/end-day', isAdminOrRider, async (req, res) => {
    console.log(`[${new Date().toLocaleTimeString()}] /api/rider/end-day endpoint'ine istek geldi.`);
    const { username } = req.body;

    if (!username) {
        console.error(`[${new Date().toLocaleTimeString()}] /api/rider/end-day: Kullanıcı adı eksik.`);
        return res.status(400).json({ message: 'Kullanıcı adı gerekli.' });
    }

    try {
        // Bugünün tarihini ISO formatında al, sadece YYYY-MM-DD kısmı
        const today = new Date().toISOString().split('T')[0];
        console.log(`[${new Date().toLocaleTimeString()}] Günü sonlandırılıyor. Bugünün tarihi (UTC) teslimat sayımı için: ${today}`);

        // Motorcunun bugünkü teslimat sayısını hesapla
        const deliveredCountResult = db.prepare(`
            SELECT COUNT(*) AS count FROM orders
            WHERE riderUsername = ? AND deliveryStatus = 'delivered' AND substr(deliveredTimestamp, 1, 10) = ?
        `).get(username, today);
        const deliveredCount = deliveredCountResult ? deliveredCountResult.count : 0;
        console.log(`[${new Date().toLocaleTimeString()}] Günü sonlandırma öncesi hesaplanan teslimat sayısı: ${deliveredCount}`);

        // Motorcuya atanmış ve teslim edilmemiş siparişleri iptal et
        db.prepare(`
            UPDATE orders
            SET deliveryStatus = 'cancelled', riderUsername = NULL, deliveryAddress = NULL, paymentMethod = NULL, assignedTimestamp = NULL, deliveredTimestamp = NULL
            WHERE riderUsername = ? AND (deliveryStatus = 'assigned' OR deliveryStatus = 'en_route')
        `).run(username);
        console.log(`[${new Date().toLocaleTimeString()}] Motorcu ${username} için teslim edilmeyen siparişler iptal edildi.`);

        // Motorcunun delivered_count'unu veritabanında sıfırla
        db.prepare("UPDATE riders SET delivered_count = 0 WHERE username = ?").run(username);
        console.log(`[${new Date().toLocaleTimeString()}] Motorcu ${username} için teslimat sayacı veritabanında sıfırlandı.`);

        // Web paneline ve diğer ilgili istemcilere motorcunun gününü sonlandırdığını bildir
        io.emit('riderDayEnded', { username, deliveredCount: deliveredCount });
        io.emit('riderDisconnected', username); // Haritadan kaldırılması için

        res.status(200).json({
            message: `Motorcu ${username} günü sonlandırdı.`,
            totalDeliveredPackagesToday: deliveredCount
        });

    } catch (error) {
        console.error(`[${new Date().toLocaleTimeString()}] Motorcunun gününü sonlandırırken hata oluştu:`, error);
        res.status(500).json({ message: 'Günü sonlandırırken bir hata oluştu.' });
    }
});


// 🌐 SOCKET.IO CONNECTIONS
io.on('connection', (socket) => {
    console.log('⚡️ Bir kullanıcı bağlandı:', socket.id);

    // İstemcinin rolünü ve kullanıcı adını kaydet
    socket.on('registerClient', (clientInfo) => {
        const { username, role } = clientInfo;
        connectedClients.set(socket.id, { username, role });
        console.log(`Client registered: ${socket.id} -> ${username} (${role})`);

        // Yeni bağlanan admin/garson paneline mevcut aktif siparişleri ve motorcu konumlarını gönder
        if (role === 'admin' || role === 'garson') {
            // Aktif siparişleri çek ve gönder
            const activeOrders = db.prepare("SELECT * FROM orders WHERE status != 'paid' AND status != 'cancelled' ORDER BY timestamp DESC").all();
            const parsedOrders = activeOrders.map(order => ({ ...order, sepetItems: JSON.parse(order.sepetItems) }));
            socket.emit('currentActiveOrders', parsedOrders);

            // Motorcu konumlarını çek ve gönder
            socket.emit('currentRiderLocations', Object.values(riderLocations));
        }
    });

    // Yeni sipariş dinle
    socket.on('newOrder', async (orderData) => {
        const orderReceptionEnabledSetting = db.prepare("SELECT setting_value FROM app_settings WHERE setting_key = 'order_reception_enabled'").get();
        const orderReceptionEnabled = orderReceptionEnabledSetting ? orderReceptionEnabledSetting.setting_value === 'true' : false;

        if (!orderReceptionEnabled) {
            console.log('Sipariş alımı kapalı. Yeni sipariş reddedildi.');
            socket.emit('orderRejected', { message: 'Sipariş alımı şu anda kapalıdır.' });
            return;
        }

        // Order ID zaten varsa, bu bir güncellemedir, yeni bir sipariş değildir.
        const existingOrder = db.prepare("SELECT * FROM orders WHERE orderId = ?").get(orderData.orderId);

        if (existingOrder) {
            console.log(`Mevcut sipariş güncelleniyor: ${orderData.orderId}`);
            try {
                db.prepare("UPDATE orders SET sepetItems = ?, toplamFiyat = ?, timestamp = ?, status = ?, masaId = ?, masaAdi = ? WHERE orderId = ?").run(
                    JSON.stringify(orderData.sepetItems),
                    orderData.toplamFiyat,
                    orderData.timestamp,
                    orderData.status,
                    orderData.masaId,
                    orderData.masaAdi,
                    orderData.orderId
                );
                const updatedOrder = db.prepare("SELECT * FROM orders WHERE orderId = ?").get(orderData.orderId);
                updatedOrder.sepetItems = JSON.parse(updatedOrder.sepetItems);
                // Sadece ilgili istemcilere (admin/garson) güncelleme gönder
                connectedClients.forEach((client, clientId) => {
                    if (client.role === 'admin' || client.role === 'garson') {
                        io.to(clientId).emit('orderUpdated', updatedOrder);
                    }
                });
            } catch (error) {
                console.error('Sipariş güncellenirken hata:', error);
            }
        } else {
            // Yeni sipariş ekle
            try {
                const newOrder = {
                    orderId: orderData.orderId,
                    masaId: orderData.masaId,
                    masaAdi: orderData.masaAdi,
                    sepetItems: JSON.stringify(orderData.sepetItems), // JSON string olarak kaydet
                    toplamFiyat: orderData.toplamFiyat,
                    timestamp: orderData.timestamp,
                    status: 'pending', // Yeni sipariş varsayılan olarak 'pending'
                    riderUsername: null,
                    deliveryAddress: null,
                    paymentMethod: null,
                    deliveryStatus: 'pending', // Teslimat durumu da 'pending'
                    assignedTimestamp: null,
                    deliveredTimestamp: null
                };
                db.prepare("INSERT INTO orders (orderId, masaId, masaAdi, sepetItems, toplamFiyat, timestamp, status, riderUsername, deliveryAddress, paymentMethod, deliveryStatus, assignedTimestamp, deliveredTimestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(
                    newOrder.orderId,
                    newOrder.masaId,
                    newOrder.masaAdi,
                    newOrder.sepetItems,
                    newOrder.toplamFiyat,
                    newOrder.timestamp,
                    newOrder.status,
                    newOrder.riderUsername,
                    newOrder.deliveryAddress,
                    newOrder.paymentMethod,
                    newOrder.deliveryStatus,
                    newOrder.assignedTimestamp,
                    newOrder.deliveredTimestamp
                );
                // Yeni siparişi sadece admin/garson panellerine yayınla
                newOrder.sepetItems = orderData.sepetItems; // Objeyi göndermeden önce parse et
                connectedClients.forEach((client, clientId) => {
                    if (client.role === 'admin' || client.role === 'garson') {
                        io.to(clientId).emit('newOrder', newOrder);
                    }
                });
                console.log('Yeni sipariş veritabanına kaydedildi ve admin/garson panellerine yayınlandı:', newOrder.orderId);
            } catch (error) {
                console.error('Yeni sipariş kaydedilirken hata:', error);
            }
        }
    });

    // Sipariş ödendi olarak işaretlendiğinde
    socket.on('orderPaid', (data) => {
        const { orderId } = data;
        try {
            db.prepare("UPDATE orders SET status = ? WHERE orderId = ?").run('paid', orderId);
            // Sadece admin/garson panellerine bildirim gönder
            connectedClients.forEach((client, clientId) => {
                if (client.role === 'admin' || client.role === 'garson') {
                    io.to(clientId).emit('orderPaidConfirmation', { orderId: orderId });
                    io.to(clientId).emit('removeOrderFromDisplay', { orderId: orderId });
                }
            });
            console.log(`Sipariş ${orderId} ödendi olarak işaretlendi.`);
        } catch (error) {
            console.error('Sipariş ödendi olarak işaretlenirken hata:', error);
        }
    });

    // Motorcu konum güncellemelerini dinle
    socket.on('riderLocationUpdate', (locationData) => {
        const { username, full_name, latitude, longitude, timestamp, speed, bearing, accuracy } = locationData;
        riderLocations[username] = { id: uuidv4(), username, full_name, latitude, longitude, timestamp, speed, bearing, accuracy, socketId: socket.id }; // socketId'yi kaydet
        // Sadece admin/garson panellerine yeni konumu yayınla
        connectedClients.forEach((client, clientId) => {
            if (client.role === 'admin' || client.role === 'garson') {
                io.to(clientId).emit('newRiderLocation', riderLocations[username]);
            }
        });
        console.log(`Motorcu ${username} konum güncelledi: ${latitude}, ${longitude}`);
    });

    // Motorcu sipariş durumunu güncellediğinde
    socket.on('updateOrderStatus', async (data) => {
        const { orderId, newDeliveryStatus, username } = data; // username eklendi
        console.log(`Motorcudan sipariş durumu güncellemesi: ${orderId}, Yeni Durum: ${newDeliveryStatus}`);
        try {
            let updateQuery = "UPDATE orders SET deliveryStatus = ? WHERE orderId = ?";
            const params = [newDeliveryStatus, orderId];

            if (newDeliveryStatus === 'delivered') {
                // Eğer sipariş teslim edildiyse, siparişi "paid" olarak işaretle ve deliveredTimestamp'ı kaydet
                updateQuery = "UPDATE orders SET deliveryStatus = ?, status = 'paid', deliveredTimestamp = ? WHERE orderId = ?";
                params.unshift(new Date().toISOString()); // deliveredTimestamp'ı ekle
                
                // Motorcunun günlük teslimat sayacını artır
                if (username) {
                    const rider = db.prepare("SELECT * FROM riders WHERE username = ?").get(username);
                    if (rider) {
                        const updatedCount = (rider.delivered_count || 0) + 1;
                        db.prepare("UPDATE riders SET delivered_count = ? WHERE username = ?").run(updatedCount, username);
                        console.log(`Motorcu ${username} için teslimat sayısı artırıldı: ${updatedCount}`);
                    }
                }
            }
            
            db.prepare(updateQuery).run(...params);


            if (newDeliveryStatus === 'delivered') {
                // Sadece admin/garson panellerine kaldırılma bildirimi gönder
                connectedClients.forEach((client, clientId) => {
                    if (client.role === 'admin' || client.role === 'garson') {
                        io.to(clientId).emit('removeOrderFromDisplay', { orderId: orderId });
                    }
                });
                console.log(`Sipariş ${orderId} teslim edildi ve panelden kaldırıldı.`);
            }

            // Sadece admin/garson panellerine durum güncellemesi bildir
            connectedClients.forEach((client, clientId) => {
                if (client.role === 'admin' || client.role === 'garson') {
                    io.to(clientId).emit('orderDeliveryStatusUpdated', { orderId, newDeliveryStatus });
                }
            });
        } catch (error) {
            console.error('Sipariş durumu güncellenirken hata:', error);
        }
    });

    // Motorcu günü sonlandırdığında (Socket.IO olayı)
    socket.on('riderDayEnded', (data) => {
        const { username } = data;
        console.log(`Motorcu ${username} gününü sonlandırdı (Socket.IO olayı).`);
        // Bu olay, HTTP endpoint'i tarafından da tetiklenebilir.
        // deliveredCount'u burada sıfırlamıyoruz, çünkü HTTP endpoint'i zaten sıfırlıyor.
        
        // riderLocations'tan kaldır
        delete riderLocations[username];
        // Sadece admin/garson panellerine bildir
        connectedClients.forEach((client, clientId) => {
            if (client.role === 'admin' || client.role === 'garson') {
                io.to(clientId).emit('riderDisconnected', username);
                io.to(clientId).emit('riderDayEnded', { username, deliveredCount: data.deliveredCount });
            }
        });
    });

    socket.on('disconnect', () => {
        console.log('🔌 Bir kullanıcı bağlantısı kesildi:', socket.id);
        const clientInfo = connectedClients.get(socket.id);
        if (clientInfo) {
            connectedClients.delete(socket.id);
            console.log(`Client disconnected: ${clientInfo.username} (${clientInfo.role})`);
            // Eğer bağlantısı kesilen bir motorcu ise, haritadan kaldırılması için diğer istemcilere bildir
            if (clientInfo.role === 'rider' && riderLocations[clientInfo.username]) {
                delete riderLocations[clientInfo.username];
                io.emit('riderDisconnected', clientInfo.username); // Tüm panellere bildir
            }
        }
    });
});

// Yeni endpoint: Tüm motorcu konumlarını isimleriyle birlikte döndür
app.get('/api/riders-locations', verifyToken, isAdminOrGarson, (req, res) => {
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


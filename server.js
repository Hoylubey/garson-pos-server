// server.js (Düzeltilmiş hali - Kayıt ve olay gönderme mantığı güçlendirildi)
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
const connectedClients = new Map(); // socket.id -> { username, role }
const fcmTokens = {}; // username -> { token, role }

// Middleware: Token doğrulama ve rol kontrolü için yardımcı fonksiyonlar
const parseToken = (token) => {
const parts = token.split('.'); 
if (parts.length === 3) {
const username = parts[0];
const role = parts[1];
const timestamp = parseInt(parts[2], 10);

console.log(`[parseToken] Token başarıyla ayrıştırıldı: Username=${username}, Rol=${role}, Timestamp=${timestamp}`);
return {
username: username,
role: role,
timestamp: timestamp
};
}
console.warn(`[parseToken] Hatalı token formatı: Beklenen 3 parça, alınan ${parts.length} parça. Token: ${token}`);
return null;
};

function isAdminMiddleware(req, res, next) {
const authHeader = req.headers['authorization'];
if (!authHeader || !authHeader.startsWith('Bearer ')) {
console.warn('[isAdminMiddleware] Yetkilendirme başlığı eksik veya hatalı formatta.');
return res.status(401).json({ message: 'Yetkilendirme başlığı eksik veya hatalı formatta.' });
}

const token = authHeader.split(' ')[1];
const decodedToken = parseToken(token);

if (decodedToken && decodedToken.role === 'admin') {
req.user = { username: decodedToken.username, role: decodedToken.role };
console.log(`[isAdminMiddleware] Yetkili admin erişimi: Kullanıcı: ${req.user.username}, Rol: ${req.user.role}`);
next();
return;
}
console.warn(`[isAdminMiddleware] Yetkisiz erişim. Token: ${token}, Ayrıştırılan Rol: ${decodedToken ? decodedToken.role : 'Yok'}. Yönetici yetkisi gerekli.`);
res.status(403).json({ message: 'Yetkisiz erişim. Yönetici yetkisi gerekli.' });
}

function isAdminOrGarsonOrRiderMiddleware(req, res, next) { 
const authHeader = req.headers['authorization'];
if (!authHeader || !authHeader.startsWith('Bearer ')) {
console.warn('[isAdminOrGarsonOrRiderMiddleware] Yetkilendirme başlığı eksik veya hatalı formatta.');
return res.status(401).json({ message: 'Yetkilendirme başlığı eksik veya hatalı formatta.' });
}

const token = authHeader.split(' ')[1];
const decodedToken = parseToken(token);

if (decodedToken && (decodedToken.role === 'admin' || decodedToken.role === 'garson' || decodedToken.role === 'rider')) { 
req.user = { username: decodedToken.username, role: decodedToken.role };
console.log(`[isAdminOrGarsonOrRiderMiddleware] Yetkili admin/garson/rider erişimi: Kullanıcı: ${req.user.username}, Rol: ${req.user.role}`);
next();
return;
}
console.warn(`[isAdminOrGarsonOrRiderMiddleware] Yetkisiz erişim. Token: ${token}, Ayrıştırılan Rol: ${decodedToken ? decodedToken.role : 'Yok'}. Admin, Garson veya Rider yetkisi gerekli.`);
res.status(403).json({ message: 'Yetkisiz erişim. Admin, Garson veya Rider yetkisi gerekli.' });
}

function isAdminOrRiderMiddleware(req, res, next) {
const authHeader = req.headers['authorization'];
if (!authHeader || !authHeader.startsWith('Bearer ')) {
consol...(truncated 33831 characters)...name: rider.username,
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

// Yeni endpoint: Atanmış siparişleri çekmek için (motorcu için)
app.get('/api/assigned-orders', isAdminOrRiderMiddleware, (req, res) => {
  const riderUsername = req.query.riderUsername;
  if (!riderUsername) {
    return res.status(400).json({ message: 'riderUsername parametresi eksik.' });
  }

  if (req.user.role === 'rider' && req.user.username !== riderUsername) {
    return res.status(403).json({ message: 'Yetkisiz erişim. Sadece kendi siparişlerinizi görüntüleyebilirsiniz.' });
  }

  try {
    const riderOrders = db.prepare(`
      SELECT * FROM orders
      WHERE riderUsername = ? AND deliveryStatus IN ('assigned', 'en_route')
      ORDER BY assignedTimestamp DESC
    `).all(riderUsername);

    const parsedOrders = riderOrders.map(order => ({ ...order, sepetItems: JSON.parse(order.sepetItems) }));
    res.json(parsedOrders);
  } catch (error) {
    console.error('Atanmış siparişler çekilirken hata:', error);
    res.status(500).json({ message: 'Siparişler alınırken bir hata oluştu.' });
  }
});

app.get('/', (req, res) => {
res.sendFile(__dirname + '/public/index.html');
});

io.on('connection', (socket) => {
console.log(`[${new Date().toLocaleTimeString()}] Yeni bağlantı: ${socket.id}`);

socket.on('registerClient', (clientInfo) => {
const { username, role } = clientInfo;

if (!username || !role) {
console.warn(`[Socket.IO] registerClient: Eksik bilgi. Gelen: ${JSON.stringify(clientInfo)}. Client kaydedilemedi.`);
return;
}

let existingSocketId = null;
for (let [sId, info] of connectedClients.entries()) {
if (info.username === username && info.role === role) {
existingSocketId = sId;
break;
}
}
if (existingSocketId && existingSocketId !== socket.id) {
console.log(`[Socket.IO] Mevcut client ${username} (${role}) için eski bağlantı (${existingSocketId}) kesiliyor. Yeni bağlantı: ${socket.id}`);
io.sockets.sockets.get(existingSocketId)?.disconnect(true);
connectedClients.delete(existingSocketId);
}

connectedClients.set(socket.id, { username, role });
console.log(`[Socket.IO] Client kaydedildi: Socket ID: ${socket.id} -> Kullanıcı: ${username} (${role}). Toplam bağlı client: ${connectedClients.size}`);

if (role === 'admin' || role === 'garson') {
const activeOrders = db.prepare("SELECT * FROM orders WHERE status != 'paid' AND status != 'cancelled' ORDER BY timestamp DESC").all();
const parsedOrders = activeOrders.map(order => ({ ...order, sepetItems: JSON.parse(order.sepetItems) }));
io.to(socket.id).emit('currentActiveOrders', parsedOrders);
console.log(`[Socket.IO] ${username} (${role}) kullanıcısına (${socket.id}) ${parsedOrders.length} aktif sipariş gönderildi.`);

io.to(socket.id).emit('currentRiderLocations', Object.values(riderLocations));
console.log(`[Socket.IO] ${username} (${role}) kullanıcısına (${socket.id}) ${Object.values(riderLocations).length} motorcu konumu gönderildi.`);
} else if (role === 'rider') {
const riderOrders = db.prepare(`
               SELECT * FROM orders
               WHERE riderUsername = ? AND (deliveryStatus = 'assigned' OR deliveryStatus = 'en_route')
               ORDER BY assignedTimestamp DESC
           `).all(username);
const parsedRiderOrders = riderOrders.map(order => ({ ...order, sepetItems: JSON.parse(order.sepetItems) }));
io.to(socket.id).emit('currentRiderOrders', parsedRiderOrders);
console.log(`[Socket.IO] Motorcu ${username} (${socket.id}) için ${parsedRiderOrders.length} atanmış sipariş gönderildi.`);
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

connectedClients.forEach((clientInfo, clientSocketId) => {
if (clientInfo.role === 'admin' || clientInfo.role === 'garson') {
io.to(clientSocketId).emit('newRiderLocation', riderLocations[username]);
}
});
console.log(`Motorcu ${username} konum güncelledi: ${latitude}, ${longitude}`);
});

socket.on('orderPaid', (data) => {
const { orderId } = data;
console.log(`[${new Date().toLocaleTimeString()}] Web panelinden 'orderPaid' olayı alındı. Sipariş ID: ${orderId}`);

try {
const currentOrder = db.prepare(`SELECT status, deliveryStatus FROM orders WHERE orderId = ?`).get(orderId);
if (!currentOrder) {
console.warn(`[orderPaid] Sipariş (ID: ${orderId}) bulunamadı.`);
return;
}

if (currentOrder.status === 'paid' || currentOrder.status === 'cancelled') {
console.warn(`[orderPaid] Sipariş (ID: ${orderId}) zaten ${currentOrder.status} durumunda. Güncelleme yapılmadı.`);
connectedClients.forEach((clientInfo, clientSocketId) => {
if (clientInfo.role === 'admin' || clientInfo.role === 'garson') {
io.to(clientSocketId).emit('removeOrderFromDisplay', { orderId: orderId });
}
});
return;
}

const info = db.prepare(`UPDATE orders SET status = 'paid' WHERE orderId = ?`).run(orderId);

if (info.changes > 0) {
console.log(`Sipariş (ID: ${orderId}) SQLite'ta başarıyla 'paid' olarak güncellendi.`);
connectedClients.forEach((clientInfo, clientSocketId) => {
if (clientInfo.role === 'admin' || clientInfo.role === 'garson') {
io.to(clientSocketId).emit('orderPaidConfirmation', { orderId: orderId });
io.to(clientSocketId).emit('removeOrderFromDisplay', { orderId: orderId });
console.log(`'orderPaidConfirmation' ve 'removeOrderFromDisplay' olayları web panellerine gönderildi.`);
}
});
} else {
console.warn(`Sipariş (ID: ${orderId}) bulunamadı veya 'paid' olarak güncellenemedi. info.changes: ${info.changes}`);
}
} catch (error) {
console.error(`[orderPaid] Siparişin durumunu güncellerken hata (ID: ${orderId}):`, error.message);
}
});

    // Eklenecek Kod Başlangıcı
socket.on('assignOrderToRider', async (data) => {
const { orderId, riderId, riderUsername } = data;
console.log(`[${new Date().toLocaleTimeString()}] 'assignOrderToRider' olayı alındı. Sipariş ID: ${orderId}, Motorcu ID: ${riderId}`);
        console.log(`[TEST] 'assignOrderToRider' olayı alındı, data:`, data);
try {
const assignedTimestamp = new Date().toISOString();
const updateStmt = db.prepare('UPDATE orders SET riderId = ?, riderUsername = ?, deliveryStatus = ?, assignedTimestamp = ? WHERE orderId = ?');
updateStmt.run(riderId, riderUsername, 'assigned', assignedTimestamp, orderId);

const updatedOrder = db.prepare('SELECT * FROM orders WHERE orderId = ?').get(orderId);
if (updatedOrder) {
updatedOrder.sepetItems = JSON.parse(updatedOrder.sepetItems);

// Admin ve Garson istemcilerine siparişin atandığını bildir
connectedClients.forEach((clientInfo, clientId) => {
if (clientInfo.role === 'admin' || clientInfo.role === 'garson') {
io.to(clientId).emit('orderAssigned', updatedOrder);
}
});

// Atanan motorcuya siparişi gönder
const riderSocketId = Array.from(connectedClients.keys()).find(key => connectedClients.get(key).userId === riderId);
if (riderSocketId) {
io.to(riderSocketId).emit('orderAssigned', updatedOrder);
console.log(`[${new Date().toLocaleTimeString()}] Sipariş ${orderId} motorcu ${riderUsername} 'a başarıyla atandı ve olay gönderildi.`);
} else {
console.error(`[${new Date().toLocaleTimeString()}] Motorcu ${riderUsername} (${riderId}) çevrimiçi değil, sipariş Socket.IO ile gönderilemedi.`);
}
} else {
console.error(`[${new Date().toLocaleTimeString()}] Sipariş ${orderId} veritabanında bulunamadı.`);
}
} catch (error) {
console.error(`[${new Date().toLocaleTimeString()}] Sipariş atama hatası (ID: ${orderId}):`, error.message);
}
});

socket.on('updateDeliveryStatus', async (data) => {
const { orderId, deliveryStatus } = data;
console.log(`[${new Date().toLocaleTimeString()}] 'updateDeliveryStatus' olayı alındı. Sipariş ID: ${orderId}, Yeni Durum: ${deliveryStatus}`);
try {
const updateStmt = db.prepare('UPDATE orders SET deliveryStatus = ? WHERE orderId = ?');
updateStmt.run(deliveryStatus, orderId);

io.emit('orderDeliveryStatusUpdated', { orderId, newDeliveryStatus: deliveryStatus });
console.log(`[${new Date().toLocaleTimeString()}] Sipariş ${orderId} için teslimat durumu başarıyla güncellendi ve tüm client'lara bildirildi.`);
} catch (error) {
console.error(`[${new Date().toLocaleTimeString()}] Sipariş durumu güncelleme hatası (ID: ${orderId}):`, error.message);
}
});
    // Eklenecek Kod Sonu

socket.on('disconnect', () => {
console.log(`[${new Date().toLocaleTimeString()}] Bağlantı koptu: ${socket.id}`);
const clientInfo = connectedClients.get(socket.id);
if (clientInfo) {
connectedClients.delete(socket.id);
console.log(`Client disconnected: ${clientInfo.username} (${clientInfo.role}). Kalan bağlı client: ${connectedClients.size}`);
if (clientInfo.role === 'rider' && riderLocations[clientInfo.username] && riderLocations[clientInfo.username].socketId === socket.id) {
delete riderLocations[clientInfo.username];
connectedClients.forEach((clientInfo, clientSocketId) => {
if (clientInfo.role === 'admin' || clientInfo.role === 'garson') {
io.to(clientSocketId).emit('riderDisconnected', clientInfo.username);
}
});
console.log(`Motorcu ${clientInfo.username} haritadan kaldırıldı.`);
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

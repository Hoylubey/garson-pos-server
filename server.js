// server.js dosyasının içeriği

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose(); // SQLite3 modülünü dahil et

const app = express();
const server = http.createServer(app);

// CORS ayarları: Frontend'in farklı bir adreste olabileceğini varsayıyoruz.
// Eğer frontend aynı sunucu üzerinden sunulacaksa bu kısım daha basit olabilir.
// Şimdilik herhangi bir kaynaktan gelen isteklere izin veriyoruz.
app.use(cors({
    origin: '*', // Tüm kaynaklardan gelen isteklere izin ver (Geliştirme için ideal, üretimde kısıtlanmalı)
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
}));

app.use(express.json()); // JSON body parsing için middleware

// Statik dosyaları sunmak için (index.html, CSS, JS)
app.use(express.static('public'));

// =========================================================
// SQLite Veritabanı Bağlantısı ve Modeller
// =========================================================
const DB_PATH = './garson_pos.db'; // Veritabanı dosyasının yolu
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('Veritabanına bağlanırken hata oluştu:', err.message);
    } else {
        console.log('SQLite veritabanına başarıyla bağlandı.');
        // Tabloları oluşturma veya doğrulamak için çağrı
        createTables();
    }
});

function createTables() {
    // Kategoriler tablosu
    db.run(`CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )`, (err) => {
        if (err) {
            console.error('Kategoriler tablosu oluşturulurken hata:', err.message);
        } else {
            console.log('Kategoriler tablosu hazır.');
            // Ürünler tablosu (kategoriye bağlı)
            db.run(`CREATE TABLE IF NOT EXISTS products (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                category_id INTEGER,
                FOREIGN KEY (category_id) REFERENCES categories(id)
            )`, (err) => {
                if (err) {
                    console.error('Ürünler tablosu oluşturulurken hata:', err.message);
                } else {
                    console.log('Ürünler tablosu hazır.');
                    // Örnek verileri ekle
                    seedData();
                }
            });
        }
    });

    // Siparişler tablosu
    db.run(`CREATE TABLE IF NOT EXISTS orders (
        orderId TEXT PRIMARY KEY,
        tableName TEXT NOT NULL,
        totalAmount REAL NOT NULL,
        timestamp TEXT NOT NULL,
        platform TEXT NOT NULL,
        status TEXT NOT NULL, -- Beklemede, Hazırlanıyor, Yolda, Tamamlandı
        paymentMethod TEXT -- Nakit, Kredi Kartı (null olabilir)
    )`, (err) => {
        if (err) {
            console.error('Siparişler tablosu oluşturulurken hata:', err.message);
        } else {
            console.log('Siparişler tablosu hazır.');
        }
    });

    // Sipariş kalemleri tablosu (ilişkisel)
    db.run(`CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id TEXT NOT NULL,
        product_id TEXT NOT NULL,
        product_name TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        unit_price REAL NOT NULL,
        total_price REAL NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders(orderId)
    )`, (err) => {
        if (err) {
            console.error('Sipariş kalemleri tablosu oluşturulurken hata:', err.message);
        } else {
            console.log('Sipariş kalemleri tablosu hazır.');
        }
    });
}

function seedData() {
    const categories = ['İçecekler', 'Kokoreç', 'Yan Ürünler', 'Tatlılar'];
    const productsToAdd = [
        { name: "Kola", price: 25.00, categoryName: "İçecekler" },
        { name: "Fanta", price: 22.00, categoryName: "İçecekler" },
        { name: "Ayran", price: 15.00, categoryName: "İçecekler" },
        { name: "Su", price: 10.00, categoryName: "İçecekler" },
        { name: "Yarım Ekmek Kokoreç", price: 120.00, categoryName: "Kokoreç" },
        { name: "Tam Ekmek Kokoreç", price: 200.00, categoryName: "Kokoreç" },
        { name: "Porsiyon Kokoreç", price: 150.00, categoryName: "Kokoreç" },
        { name: "Patates Cips", price: 40.00, categoryName: "Yan Ürünler" },
        { name: "Turşu", price: 10.00, categoryName: "Yan Ürünler" },
        { name: "Sütlaç", price: 35.00, categoryName: "Tatlılar" },
        { name: "Künefe", price: 60.00, categoryName: "Tatlılar" }
    ];

    db.serialize(() => {
        categories.forEach(categoryName => {
            // Kategori yoksa ekle
            db.run(`INSERT OR IGNORE INTO categories (name) VALUES (?)`, [categoryName], function(err) {
                if (err) {
                    console.error(`Kategori eklenirken hata (${categoryName}):`, err.message);
                } else if (this.changes > 0) {
                    console.log(`Kategori eklendi: ${categoryName}`);
                }
            });
        });

        // Ürünleri ekle (kategoriye göre)
        productsToAdd.forEach(product => {
            db.get(`SELECT id FROM categories WHERE name = ?`, [product.categoryName], (err, row) => {
                if (err) {
                    console.error(`Kategori ID alınırken hata (${product.categoryName}):`, err.message);
                    return;
                }
                if (row) {
                    const categoryId = row.id;
                    const productId = product.name.toLowerCase().replace(/\s/g, '_').replace(/ç/g, 'c').replace(/ş/g, 's').replace(/ı/g, 'i').replace(/ö/g, 'o').replace(/ü/g, 'u').replace(/ğ/g, 'g'); // Basit ID oluşturma
                    db.run(`INSERT OR IGNORE INTO products (id, name, price, category_id) VALUES (?, ?, ?, ?)`,
                        [productId, product.name, product.price, categoryId], function(err) {
                            if (err) {
                                console.error(`Ürün eklenirken hata (${product.name}):`, err.message);
                            } else if (this.changes > 0) {
                                console.log(`Ürün eklendi: ${product.name}`);
                            }
                        }
                    );
                } else {
                    console.warn(`Ürün için kategori bulunamadı: ${product.name} (Kategori: ${product.categoryName})`);
                }
            });
        });
    });
}


// =========================================================
// Socket.IO Sunucu Ayarları ve Olayları
// =========================================================
const io = socketIo(server, {
    cors: {
        origin: '*', // Tüm kaynaklardan gelen bağlantılara izin ver (Geliştirme için)
        methods: ['GET', 'POST']
    }
});

// Siparişleri bellekte tutmak yerine veritabanından çekeceğiz.
// Ancak aktif siparişleri takip etmek için yine de geçici bir bellek yapısı kullanabiliriz.
// Şimdilik sadece yeni gelen siparişleri tutacak bir dizi kullanalım,
// gerçekte veritabanından çekilen tüm siparişler listelenecek.
let activeOrders = {}; // orderId'ye göre siparişleri tutacak

// Mevcut aktif siparişleri veritabanından yükleme fonksiyonu
function loadCurrentOrdersFromDb() {
    db.all(`SELECT * FROM orders WHERE status NOT IN ('Tamamlandı', 'İptal Edildi') ORDER BY timestamp DESC`, (err, rows) => {
        if (err) {
            console.error('Mevcut siparişler veritabanından çekilirken hata:', err.message);
            return;
        }
        rows.forEach(orderRow => {
            // Her sipariş için kalemlerini çek
            db.all(`SELECT product_id as id, product_name as name, quantity, unit_price as unitPrice, total_price as totalPrice FROM order_items WHERE order_id = ?`, [orderRow.orderId], (err, items) => {
                if (err) {
                    console.error(`Sipariş kalemleri çekilirken hata (Order ID: ${orderRow.orderId}):`, err.message);
                    return;
                }
                const order = {
                    orderId: orderRow.orderId,
                    tableName: orderRow.tableName,
                    items: items,
                    totalAmount: orderRow.totalAmount,
                    timestamp: orderRow.timestamp,
                    platform: orderRow.platform,
                    status: orderRow.status,
                    paymentMethod: orderRow.paymentMethod
                };
                activeOrders[order.orderId] = order; // Belleğe ekle
                // Bağlı olan tüm client'lara gönder (sayfa yenilendiğinde vs.)
                io.emit('newOrder', order); // 'newOrder' olarak gönderiyoruz çünkü client tarafında addOrderToDisplay zaten var.
            });
        });
        console.log('Mevcut aktif siparişler yüklendi ve client\'lara gönderildi.');
    });
}


// Client bağlandığında
io.on('connection', (socket) => {
    console.log('Yeni bir istemci bağlandı:', socket.id);

    // Bağlanan client'a mevcut aktif siparişleri gönder
    socket.on('requestCurrentOrders', () => {
        const currentOrdersArray = Object.values(activeOrders);
        // Bu kısım, client bağlandığında sadece o client'a gönderilir.
        socket.emit('currentOrders', currentOrdersArray);
        console.log(`Client ${socket.id} için mevcut siparişler gönderildi.`);
    });

    // Bağlanan client'a mevcut motorcu konumlarını gönder (şimdilik bu kısım değişmiyor)
    socket.on('requestCurrentRiderLocations', () => {
        // Bu kısım henüz veritabanına entegre değil, mevcut mantıkla devam ediyor.
        // TODO: Motorcu konumlarını da veritabanına kaydetmek istenirse burası değişmeli.
        socket.emit('currentRiderLocations', Object.values(riderLocations));
    });

    // POS'tan yeni sipariş geldiğinde
    socket.on('newOrder', (order) => {
        const orderId = `POS-${Date.now()}`; // Eşsiz bir sipariş ID'si oluştur
        order.orderId = orderId;
        order.timestamp = new Date().toISOString(); // Sunucu tarafında zaman damgası ekle
        order.status = 'Beklemede'; // Başlangıç durumu

        // Siparişi veritabanına kaydet
        db.run(`INSERT INTO orders (orderId, tableName, totalAmount, timestamp, platform, status, paymentMethod) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [order.orderId, order.tableName, order.totalAmount, order.timestamp, order.platform, order.status, order.paymentMethod || null], function(err) {
                if (err) {
                    console.error('Sipariş veritabanına kaydedilirken hata:', err.message);
                    return;
                }
                console.log(`Sipariş ID ${order.orderId} veritabanına kaydedildi.`);

                // Sipariş kalemlerini kaydet
                const stmt = db.prepare(`INSERT INTO order_items (order_id, product_id, product_name, quantity, unit_price, total_price) VALUES (?, ?, ?, ?, ?, ?)`);
                order.items.forEach(item => {
                    stmt.run(order.orderId, item.productId, item.productName, item.quantity, item.unitPrice, item.totalPrice);
                });
                stmt.finalize((err) => {
                    if (err) {
                        console.error('Sipariş kalemleri kaydedilirken hata:', err.message);
                    } else {
                        console.log(`Sipariş kalemleri Order ID ${order.orderId} için kaydedildi.`);
                        activeOrders[order.orderId] = order; // Belleğe ekle
                        io.emit('newOrder', order); // Tüm bağlı client'lara yeni siparişi yayınla
                    }
                });
            }
        );
    });

    // Mutfak/Kasa ekranından sipariş ödendi olarak işaretlendiğinde
    socket.on('orderPaid', ({ orderId, tableName, totalAmount }) => {
        db.run(`UPDATE orders SET status = 'Tamamlandı' WHERE orderId = ?`, [orderId], function(err) {
            if (err) {
                console.error(`Sipariş ${orderId} ödendi olarak güncellenirken hata:`, err.message);
                return;
            }
            if (this.changes > 0) {
                console.log(`Sipariş ${orderId} ödendi olarak güncellendi.`);
                delete activeOrders[orderId]; // Bellekten kaldır
                io.emit('orderRemoved', orderId); // Tüm client'lara kaldırıldığını bildir
            } else {
                console.warn(`Sipariş ${orderId} bulunamadı veya zaten tamamlandı.`);
            }
        });
    });

    // POS ekranından ödeme yapılıp sipariş tamamlandığında (ve fiş basıldığında)
    socket.on('orderPaidFromPOS', (order) => {
        const orderId = `POS_PAID-${Date.now()}`; // Ödenmiş sipariş için farklı ID veya mevcut ID'yi kullan
        order.orderId = orderId; // Bu, server'da yeni oluşturulan bir sipariş olduğu için yeni ID veriyoruz.
        order.timestamp = new Date().toISOString();
        order.status = 'Tamamlandı'; // Zaten tamamlanmış olarak geliyor
        // paymentMethod zaten client'tan geliyor

        // Siparişi veritabanına kaydet
        db.run(`INSERT INTO orders (orderId, tableName, totalAmount, timestamp, platform, status, paymentMethod) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [order.orderId, order.tableName, order.totalAmount, order.timestamp, order.platform, order.status, order.paymentMethod], function(err) {
                if (err) {
                    console.error('POS\'tan ödenen sipariş veritabanına kaydedilirken hata:', err.message);
                    return;
                }
                console.log(`POS'tan ödenen sipariş ID ${order.orderId} veritabanına kaydedildi.`);

                // Sipariş kalemlerini kaydet
                const stmt = db.prepare(`INSERT INTO order_items (order_id, product_id, product_name, quantity, unit_price, total_price) VALUES (?, ?, ?, ?, ?, ?)`);
                order.items.forEach(item => {
                    stmt.run(order.orderId, item.productId, item.productName, item.quantity, item.unitPrice, item.totalPrice);
                });
                stmt.finalize((err) => {
                    if (err) {
                        console.error('POS\'tan ödenen sipariş kalemleri kaydedilirken hata:', err.message);
                    } else {
                        console.log(`POS'tan ödenen sipariş kalemleri Order ID ${order.orderId} için kaydedildi.`);
                        // Bu sipariş zaten tamamlandığı için 'activeOrders' listesine eklemeye gerek yok,
                        // doğrudan 'orderRemoved' olayı gönderilebilir veya hiç gönderilmeyebilir.
                        // Şimdilik mutfak ekranında görünmemesi için doğrudan kaldırıyoruz.
                        io.emit('orderRemoved', order.orderId); // Mutfak ekranından bu siparişi kaldır
                    }
                });
            }
        );
    });


    // Motorcu konum güncellemeleri (şimdilik basit bir bellek objesinde tutuluyor)
    let riderLocations = {}; // { riderId: { latitude, longitude, speed, bearing, timestamp } }

    socket.on('riderLocationUpdate', (locationData) => {
        riderLocations[locationData.riderId] = {
            latitude: locationData.latitude,
            longitude: locationData.longitude,
            speed: locationData.speed,
            bearing: locationData.bearing,
            timestamp: new Date().toISOString()
        };
        // console.log(`Motorcu ${locationData.riderId} konum güncelledi:`, riderLocations[locationData.riderId]);
        // Konum güncellemelerini diğer tüm client'lara yayınla (mutfak ekranı vb.)
        io.emit('riderLocationUpdate', riderLocations[locationData.riderId]);
    });

    socket.on('disconnect', () => {
        console.log('İstemci bağlantısı kesildi:', socket.id);
        // İstemci disconnect olduğunda motorcu konumunu temizleyebiliriz,
        // ancak gerçek bir uygulamada motorcu oturumu bitene kadar tutulabilir.
        // Örneğin: delete riderLocations[socket.id];
    });
});

// =========================================================
// HTTP API Uç Noktaları
// =========================================================

// Ürünleri kategorileriyle birlikte getir
app.get('/products-with-categories', (req, res) => {
    db.all(`SELECT p.id, p.name, p.price, c.name as categoryName
            FROM products p
            JOIN categories c ON p.category_id = c.id
            ORDER BY c.name, p.name`, (err, rows) => {
        if (err) {
            console.error('Ürünler ve kategoriler çekilirken hata:', err.message);
            res.status(500).json({ error: 'Ürünler ve kategoriler çekilemedi.' });
            return;
        }

        const organizedProducts = {};
        rows.forEach(row => {
            if (!organizedProducts[row.categoryName]) {
                organizedProducts[row.categoryName] = [];
            }
            organizedProducts[row.categoryName].push({
                id: row.id,
                name: row.name,
                price: row.price
            });
        });
        res.json(organizedProducts);
    });
});


// Sunucuyu başlat
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Garson POS Sunucusu ${PORT} portunda çalışıyor.`);
    loadCurrentOrdersFromDb(); // Sunucu başladığında mevcut siparişleri yükle
});

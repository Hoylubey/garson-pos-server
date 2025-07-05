// server.js dosyasının içeriği

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const server = http.createServer(app);

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
}));

app.use(express.json());
app.use(express.static('public'));

// =========================================================
// SQLite Veritabanı Bağlantısı ve Modeller (Güncellendi)
// =========================================================
const DB_PATH = './garson_pos.db';
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('Veritabanına bağlanırken hata oluştu:', err.message);
    } else {
        console.log('SQLite veritabanına başarıyla bağlandı.');
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
            // Ürünler tablosu (kategoriye bağlı) - ID INTEGER PRIMARY KEY oldu
            db.run(`CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                category_id INTEGER,
                FOREIGN KEY (category_id) REFERENCES categories(id)
            )`, (err) => {
                if (err) {
                    console.error('Ürünler tablosu oluşturulurken hata:', err.message);
                } else {
                    console.log('Ürünler tablosu hazır.');
                    seedData(); // Örnek verileri ekle
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
        status TEXT NOT NULL,
        paymentMethod TEXT
    )`, (err) => {
        if (err) {
            console.error('Siparişler tablosu oluşturulurken hata:', err.message);
        } else {
            console.log('Siparişler tablosu hazır.');
        }
    });

    // Sipariş kalemleri tablosu (ilişkisel) - product_id INTEGER oldu
    db.run(`CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id TEXT NOT NULL,
        product_id INTEGER NOT NULL, -- product_id INTEGER olarak değişti
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
        { name: "Künefe", price: 60.00, categoryName: "Tatlılar" },
         // Android uygulamasındaki ürün listesini buraya ekleyelim, böylece ID'ler uyumlu olur
        { name: "Yarım Ekmek İzmir Kokoreç ", fiyat: 240.0, categoryName: "Kokoreç" },
        { name: "Üç Çeyrek Ekmek Kokoreç ", fiyat: 300.0, categoryName: "Kokoreç" },
        { name: "Porsiyon Kokoreç ", fiyat: 400.0, categoryName: "Kokoreç" },
        { name: "Yarım Ekmek Tavuk Kokoreç ", fiyat: 100.0, categoryName: "Kokoreç" },
        { name: "Üç Çeyrek Tavuk Kokoreç", fiyat: 150.0, categoryName: "Kokoreç" },
        { name: "Sade Patso ", fiyat: 110.0, categoryName: "Yan Ürünler" },
        { name: "Sosisli Patso ", fiyat: 130.0, categoryName: "Yan Ürünler" },
        { name: "Ciğerli Patso ", fiyat: 180.0, categoryName: "Yan Ürünler" },
        { name: "Köfteli Patso", fiyat: 180.0, categoryName: "Yan Ürünler" },
        { name: "Kaşarlı Patso ", fiyat: 130.0, categoryName: "Yan Ürünler" },
        { name: "Tavuklu Patso ", fiyat: 160.0, categoryName: "Yan Ürünler" },
        { name: "Amerikanlı Patso ", fiyat: 130.0, categoryName: "Yan Ürünler" },
        { name: "Patates Kızartması", fiyat: 110.0, categoryName: "Yan Ürünler" },
        { name: "Yarım Ekmek Köfte ", fiyat: 170.0, categoryName: "Kokoreç" }, // Kategori buraya uygun mu kontrol edin
        { name: "Üç Çeyrek Ekmek Köfte ", fiyat: 250.0, categoryName: "Kokoreç" }, // Kategori buraya uygun mu kontrol edin
        { name: "Porsiyon Köfte ", fiyat: 270.0, categoryName: "Kokoreç" }, // Kategori buraya uygun mu kontrol edin
        { name: "Hamburger", fiyat: 130.0, categoryName: "Yan Ürünler" }, // Kategori buraya uygun mu kontrol edin
        { name: "Yarım Ekmek Ciğer ", fiyat: 170.0, categoryName: "Kokoreç" }, // Kategori buraya uygun mu kontrol edin
        { name: "Üç Çeyrek Ekmek Ciğer", fiyat: 250.0, categoryName: "Kokoreç" }, // Kategori buraya uygun mu kontrol edin
        { name: "Porsiyon Ciğer ", fiyat: 270.0, categoryName: "Kokoreç" }, // Kategori buraya uygun mu kontrol edin
        { name: "Cheeseburger", fiyat: 140.0, categoryName: "Yan Ürünler" }, // Kategori buraya uygun mu kontrol edin
        { name: "Yarım Ekmek Sucuk ", fiyat: 200.0, categoryName: "Kokoreç" }, // Kategori buraya uygun mu kontrol edin
        { name: "Üç Çeyrek Ekmek Sucuk ", fiyat: 300.0, categoryName: "Kokoreç" }, // Kategori buraya uygun mu kontrol edin
        { name: "Islak Burger ", fiyat: 70.0, categoryName: "Yan Ürünler" }, // Kategori buraya uygun mu kontrol edin
        { name: "Sosisli Sandviç", fiyat: 70.0, categoryName: "Yan Ürünler" }, // Kategori buraya uygun mu kontrol edin
        { name: "Yarım Ekmek Tavuk Döner ", fiyat: 70.0, categoryName: "Kokoreç" }, // Kategori buraya uygun mu kontrol edin
        { name: "Tombik Ekmek Tavuk Döner ", fiyat: 80.0, categoryName: "Kokoreç" }, // Kategori buraya uygun mu kontrol edin
        { name: "Üç Çeyrek Ekmek Döner ", fiyat: 100.0, categoryName: "Kokoreç" }, // Kategori buraya uygun mu kontrol edin
        { name: "Dürüm Tavuk Döner", fiyat: 100.0, categoryName: "Kokoreç" }, // Kategori buraya uygun mu kontrol edin
        { name: "Pilav Üstü Tavuk Döner ", fiyat: 170.0, categoryName: "Kokoreç" }, // Kategori buraya uygun mu kontrol edin
        { name: "Yarım Ekmek Kaşarlı Tost ", fiyat: 80.0, categoryName: "Yan Ürünler" }, // Kategori buraya uygun mu kontrol edin
        { name: "Yarım Ekmek Karışık Tost ", fiyat: 100.0, categoryName: "Yan Ürünler" }, // Kategori buraya uygun mu kontrol edin
        { name: "Kutu İçecek ", fiyat: 50.0, categoryName: "İçecekler" },
        { name: "Şişe Kola ", fiyat: 40.0, categoryName: "İçecekler" },
        { name: "Ayran ", fiyat: 50.0, categoryName: "İçecekler" },
        { name: "Küçük Ayran ", fiyat: 30.0, categoryName: "İçecekler" },
        { name: "Limonata ", fiyat: 50.0, categoryName: "İçecekler" },
        { name: "Çamlıca Gazoz ", fiyat: 40.0, categoryName: "İçecekler" },
        { name: "Sade Soda", fiyat: 30.0, categoryName: "İçecekler" },
        { name: "Limonlu Soda ", fiyat: 35.0, categoryName: "İçecekler" },
        { name: "Şalgam Suyu ", fiyat: 50.0, categoryName: "İçecekler" },
        { name: "Su ", fiyat: 15.0, categoryName: "İçecekler" },
        { name: "Çay ", fiyat: 15.0, categoryName: "İçecekler" },
        { name: "Midye ", fiyat: 10.0, categoryName: "Yan Ürünler" } // Kategori buraya uygun mu kontrol edin
    ];


    db.serialize(() => {
        categories.forEach(categoryName => {
            db.run(`INSERT OR IGNORE INTO categories (name) VALUES (?)`, [categoryName], function(err) {
                if (err) {
                    console.error(`Kategori eklenirken hata (${categoryName}):`, err.message);
                } else if (this.changes > 0) {
                    console.log(`Kategori eklendi: ${categoryName}`);
                }
            });
        });

        productsToAdd.forEach(product => {
            db.get(`SELECT id FROM categories WHERE name = ?`, [product.categoryName], (err, row) => {
                if (err) {
                    console.error(`Kategori ID alınırken hata (${product.categoryName}):`, err.message);
                    return;
                }
                if (row) {
                    const categoryId = row.id;
                    // id alanı artık otomatik artacak, biz eklemeyeceğiz
                    db.run(`INSERT OR IGNORE INTO products (name, price, category_id) VALUES (?, ?, ?)`,
                        [product.name, product.price, categoryId], function(err) {
                            if (err) {
                                console.error(`Ürün eklenirken hata (${product.name}):`, err.message);
                            } else if (this.changes > 0) {
                                console.log(`Ürün eklendi: ${product.name} (ID: ${this.lastID})`);
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
        origin: '*',
        methods: ['GET', 'POST']
    }
});

let activeOrders = {};

function loadCurrentOrdersFromDb() {
    db.all(`SELECT * FROM orders WHERE status NOT IN ('Tamamlandı', 'İptal Edildi') ORDER BY timestamp DESC`, (err, rows) => {
        if (err) {
            console.error('Mevcut siparişler veritabanından çekilirken hata:', err.message);
            return;
        }
        rows.forEach(orderRow => {
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
                activeOrders[order.orderId] = order;
                io.emit('newOrder', order);
            });
        });
        console.log('Mevcut aktif siparişler yüklendi ve client\'lara gönderildi.');
    });
}


io.on('connection', (socket) => {
    console.log('Yeni bir istemci bağlandı:', socket.id);

    socket.on('requestCurrentOrders', () => {
        const currentOrdersArray = Object.values(activeOrders);
        socket.emit('currentOrders', currentOrdersArray);
        console.log(`Client ${socket.id} için mevcut siparişler gönderildi.`);
    });

    // Motorcu konum güncellemeleri kısmı değişmiyor
    let riderLocations = {};
    socket.on('requestCurrentRiderLocations', () => {
        socket.emit('currentRiderLocations', Object.values(riderLocations));
    });


    // Yeni sipariş geldiğinde (Android uygulamadan da gelebilir)
    socket.on('newOrder', (order) => {
        const orderId = `ORDER-${Date.now()}`; // Eşsiz bir sipariş ID'si oluştur (hem POS hem Android için)
        order.orderId = orderId;
        order.timestamp = new Date().toISOString();
        order.status = 'Beklemede'; // Başlangıç durumu

        db.run(`INSERT INTO orders (orderId, tableName, totalAmount, timestamp, platform, status, paymentMethod) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [order.orderId, order.tableName, order.totalAmount, order.timestamp, order.platform, order.status, order.paymentMethod || null], function(err) {
                if (err) {
                    console.error('Sipariş veritabanına kaydedilirken hata:', err.message);
                    return;
                }
                console.log(`Sipariş ID ${order.orderId} veritabanına kaydedildi.`);

                const stmt = db.prepare(`INSERT INTO order_items (order_id, product_id, product_name, quantity, unit_price, total_price) VALUES (?, ?, ?, ?, ?, ?)`);
                order.items.forEach(item => {
                    // product_id artık sayısal olabilir, string dönüşümüne gerek yok
                    stmt.run(order.orderId, item.productId, item.productName, item.quantity, item.unitPrice, item.totalPrice);
                });
                stmt.finalize((err) => {
                    if (err) {
                        console.error('Sipariş kalemleri kaydedilirken hata:', err.message);
                    } else {
                        console.log(`Sipariş kalemleri Order ID ${order.orderId} için kaydedildi.`);
                        activeOrders[order.orderId] = order;
                        io.emit('newOrder', order);
                    }
                });
            }
        );
    });

    socket.on('orderPaid', ({ orderId, tableName, totalAmount }) => {
        db.run(`UPDATE orders SET status = 'Tamamlandı' WHERE orderId = ?`, [orderId], function(err) {
            if (err) {
                console.error(`Sipariş ${orderId} ödendi olarak güncellenirken hata:`, err.message);
                return;
            }
            if (this.changes > 0) {
                console.log(`Sipariş ${orderId} ödendi olarak güncellendi.`);
                delete activeOrders[orderId];
                io.emit('orderRemoved', orderId);
            } else {
                console.warn(`Sipariş ${orderId} bulunamadı veya zaten tamamlandı.`);
            }
        });
    });

    socket.on('orderPaidFromPOS', (order) => {
        const orderId = `PAID-${Date.now()}`; // Ödenmiş sipariş için yeni ID
        order.orderId = orderId;
        order.timestamp = new Date().toISOString();
        order.status = 'Tamamlandı';

        db.run(`INSERT INTO orders (orderId, tableName, totalAmount, timestamp, platform, status, paymentMethod) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [order.orderId, order.tableName, order.totalAmount, order.timestamp, order.platform, order.status, order.paymentMethod], function(err) {
                if (err) {
                    console.error('POS\'tan ödenen sipariş veritabanına kaydedilirken hata:', err.message);
                    return;
                }
                console.log(`POS'tan ödenen sipariş ID ${order.orderId} veritabanına kaydedildi.`);

                const stmt = db.prepare(`INSERT INTO order_items (order_id, product_id, product_name, quantity, unit_price, total_price) VALUES (?, ?, ?, ?, ?, ?)`);
                order.items.forEach(item => {
                    // product_id artık sayısal olabilir
                    stmt.run(order.orderId, item.productId, item.productName, item.quantity, item.unitPrice, item.totalPrice);
                });
                stmt.finalize((err) => {
                    if (err) {
                        console.error('POS\'tan ödenen sipariş kalemleri kaydedilirken hata:', err.message);
                    } else {
                        console.log(`POS'tan ödenen sipariş kalemleri Order ID ${order.orderId} için kaydedildi.`);
                        io.emit('orderRemoved', order.orderId);
                    }
                });
            }
        );
    });

    socket.on('riderLocationUpdate', (locationData) => {
        riderLocations[locationData.riderId] = {
            latitude: locationData.latitude,
            longitude: locationData.longitude,
            speed: locationData.speed,
            bearing: locationData.bearing,
            timestamp: new Date().toISOString()
        };
        io.emit('riderLocationUpdate', riderLocations[locationData.riderId]);
    });

    socket.on('disconnect', () => {
        console.log('İstemci bağlantısı kesildi:', socket.id);
    });
});

// =========================================================
// HTTP API Uç Noktaları (Güncellendi)
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
                id: row.id, // ID artık sayısal geliyor
                name: row.name,
                price: row.price
            });
        });
        res.json(organizedProducts);
    });
});


const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Garson POS Sunucusu ${PORT} portunda çalışıyor.`);
    loadCurrentOrdersFromDb();
});

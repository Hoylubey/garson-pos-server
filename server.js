// server.js dosyasının içeriği (SQLite kaldırıldı, bellek tabanlı)

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
// const sqlite3 = require('sqlite3').verbose(); // SQLite3 modülü kaldırıldı

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
// Bellek Tabanlı Ürünler ve Kategoriler (SQLite yerine)
// =========================================================

// Kategoriler ve Ürünler için basit bir bellek yapısı
// Ürün ID'lerini sayısal tutacağız, Android uygulamanızla uyumlu olması için.
let categories = [
    { id: 1, name: "İçecekler" },
    { id: 2, name: "Kokoreç" },
    { id: 3, name: "Yan Ürünler" },
    { id: 4, name: "Tatlılar" }
];

// Android uygulamasındaki ürün listesini buraya ekleyelim, ve ID'leri otomatik verelim
// Bu ürünler sadece sunucu belleğinde kalacak, kalıcı değil.
let products = [];
let productIdCounter = 1;

function initializeProducts() {
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
        // Android uygulamasından gelen ürün listesi:
        { name: "Yarım Ekmek İzmir Kokoreç ", price: 240.0, categoryName: "Kokoreç" },
        { name: "Üç Çeyrek Ekmek Kokoreç ", price: 300.0, categoryName: "Kokoreç" },
        { name: "Porsiyon Kokoreç ", price: 400.0, categoryName: "Kokoreç" },
        { name: "Yarım Ekmek Tavuk Kokoreç ", price: 100.0, categoryName: "Kokoreç" },
        { name: "Üç Çeyrek Tavuk Kokoreç", price: 150.0, categoryName: "Kokoreç" },
        { name: "Sade Patso ", price: 110.0, categoryName: "Yan Ürünler" },
        { name: "Sosisli Patso ", price: 130.0, categoryName: "Yan Ürünler" },
        { name: "Ciğerli Patso ", price: 180.0, categoryName: "Yan Ürünler" },
        { name: "Köfteli Patso", price: 180.0, categoryName: "Yan Ürünler" },
        { name: "Kaşarlı Patso ", price: 130.0, categoryName: "Yan Ürünler" },
        { name: "Tavuklu Patso ", price: 160.0, categoryName: "Yan Ürünler" },
        { name: "Amerikanlı Patso ", price: 130.0, categoryName: "Yan Ürünler" },
        { name: "Patates Kızartması", price: 110.0, categoryName: "Yan Ürünler" },
        { name: "Yarım Ekmek Köfte ", price: 170.0, categoryName: "Kokoreç" }, // Kategorileri kontrol et
        { name: "Üç Çeyrek Ekmek Köfte ", price: 250.0, categoryName: "Kokoreç" },
        { name: "Porsiyon Köfte ", price: 270.0, categoryName: "Kokoreç" },
        { name: "Hamburger", price: 130.0, categoryName: "Yan Ürünler" },
        { name: "Yarım Ekmek Ciğer ", price: 170.0, categoryName: "Kokoreç" },
        { name: "Üç Çeyrek Ekmek Ciğer", price: 250.0, categoryName: "Kokoreç" },
        { name: "Porsiyon Ciğer ", price: 270.0, categoryName: "Kokoreç" },
        { name: "Cheeseburger", price: 140.0, categoryName: "Yan Ürünler" },
        { name: "Yarım Ekmek Sucuk ", price: 200.0, categoryName: "Kokoreç" },
        { name: "Üç Çeyrek Ekmek Sucuk ", price: 300.0, categoryName: "Kokoreç" },
        { name: "Islak Burger ", price: 70.0, categoryName: "Yan Ürünler" },
        { name: "Sosisli Sandviç", price: 70.0, categoryName: "Yan Ürünler" },
        { name: "Yarım Ekmek Tavuk Döner ", price: 70.0, categoryName: "Kokoreç" },
        { name: "Tombik Ekmek Tavuk Döner ", price: 80.0, categoryName: "Kokoreç" },
        { name: "Üç Çeyrek Ekmek Döner ", price: 100.0, categoryName: "Kokoreç" },
        { name: "Dürüm Tavuk Döner", price: 100.0, categoryName: "Kokoreç" },
        { name: "Pilav Üstü Tavuk Döner ", price: 170.0, categoryName: "Kokoreç" },
        { name: "Yarım Ekmek Kaşarlı Tost ", price: 80.0, categoryName: "Yan Ürünler" },
        { name: "Yarım Ekmek Karışık Tost ", price: 100.0, categoryName: "Yan Ürünler" },
        { name: "Kutu İçecek ", price: 50.0, categoryName: "İçecekler" },
        { name: "Şişe Kola ", price: 40.0, categoryName: "İçecekler" },
        { name: "Ayran ", price: 50.0, categoryName: "İçecekler" },
        { name: "Küçük Ayran ", price: 30.0, categoryName: "İçecekler" },
        { name: "Limonata ", price: 50.0, categoryName: "İçecekler" },
        { name: "Çamlıca Gazoz ", price: 40.0, categoryName: "İçecekler" },
        { name: "Sade Soda", price: 30.0, categoryName: "İçecekler" },
        { name: "Limonlu Soda ", price: 35.0, categoryName: "İçecekler" },
        { name: "Şalgam Suyu ", price: 50.0, categoryName: "İçecekler" },
        { name: "Su ", price: 15.0, categoryName: "İçecekler" },
        { name: "Çay ", price: 15.0, categoryName: "İçecekler" },
        { name: "Midye ", price: 10.0, categoryName: "Yan Ürünler" }
    ];

    productsToAdd.forEach(p => {
        const category = categories.find(c => c.name === p.categoryName);
        if (category) {
            products.push({
                id: productIdCounter++, // Otomatik artan sayısal ID
                name: p.name,
                price: p.price,
                categoryId: category.id,
                categoryName: category.name // Frontend için kolaylık
            });
        } else {
            console.warn(`Kategori bulunamadı: ${p.categoryName} ürünü için ${p.name}.`);
        }
    });
    console.log('Bellek tabanlı ürünler başlatıldı.');
}
initializeProducts(); // Sunucu başladığında ürünleri belleğe yükle

// =========================================================
// Socket.IO Sunucu Ayarları ve Olayları
// =========================================================
const io = socketIo(server, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST']
    }
});

// Siparişleri bellekte tutmak için (artık kalıcı değil)
let activeOrders = {}; // { orderId: { ...orderData } }

// Bu fonksiyon artık veritabanından değil, bellekten yükleyecek
function loadCurrentOrdersFromMemory() {
    // Sunucu her başladığında activeOrders sıfırlanacağı için
    // bu fonksiyon şu an için aslında boş. Sadece yapıyı korumak adına var

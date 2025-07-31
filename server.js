const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const PdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const ExcelJS = require('exceljs');

const app = express();
const PORT = process.env.PORT || 3000;

const UPLOAD_DIR = path.join(__dirname, 'uploads');

// Multer disk storage configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const relativePath = path.dirname(file.originalname);
        const destinationPath = path.join(UPLOAD_DIR, relativePath);
        fs.ensureDirSync(destinationPath); // Klasör yoksa oluştur
        cb(null, destinationPath);
    },
    filename: (req, file, cb) => {
        cb(null, path.basename(file.originalname)); // Orijinal dosya adını kullan
    }
});

const upload = multer({ storage: storage });

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Information extraction function
async function extractInfo(filePath, originalRelativePath) {
    const docInfo = {
        'Döküman No': '',
        'Tarih': '',
        'Revizyon Tarihi': '',
        'Revizyon Sayısı': '',
        'Dosya İsmi': '',
        'Sorumlu Departman': ''
    };

    // --- Dosya İsmi Mantığı (Düzeltme Yapıldı) ---
    const fullFileNameWithExt = path.basename(originalRelativePath); // Örn: 'FR.01-BS.TL.02_0-SMS ve Maling Cevap Şablonu.pdf'
    const fileNameWithoutExt = path.parse(fullFileNameWithExt).name; // Uzantısız kısım: 'FR.01-BS.TL.02_0-SMS ve Maling Cevap Şablonu'

    // İlk '-' işaretinden sonraki kısmı al
    const firstHyphenIndex = fileNameWithoutExt.indexOf('-');
    if (firstHyphenIndex !== -1 && firstHyphenIndex < fileNameWithoutExt.length - 1) {
        // substring kullanarak ilk '-' işaretinden sonraki tüm kısmı alıyoruz.
        docInfo['Dosya İsmi'] = fileNameWithoutExt.substring(firstHyphenIndex + 1).trim();
    } else {
        docInfo['Dosya İsmi'] = fileNameWithoutExt.trim(); // '-' yoksa tüm uzantısız adı kullan
    }

    // --- Sorumlu Departman Mantığı ---
    const pathSegments = originalRelativePath.split(path.sep);
    
    // Eğer dosya doğrudan seçilen kök klasörde değilse (yani alt klasörlerdeyse)
    // pathSegments.length >= 2, dosyanın bir klasör içinde olduğunu gösterir (örn: ['Klasor', 'Dosya.pdf'])
    // pathSegments.length >= 3, dosyanın bir alt klasör içinde olduğunu gösterir (örn: ['AnaKlasor', 'AltKlasor', 'Dosya.pdf'])
    if (pathSegments.length > 1) {
        // Dosyanın olduğu klasör adı (son segmentten bir önceki)
        // Eğer 'some_folder/my_doc.pdf' ise pathSegments[0] = 'some_folder'
        // Eğer 'root/sub_folder/my_doc.pdf' ise pathSegments[1] = 'sub_folder'
        // Bu yüzden, pathSegments dizisindeki son eleman (dosya adı) hariç son klasör adını alıyoruz.
        const folderNameIndex = pathSegments.length - 2;
        if (folderNameIndex >= 0) { // Dizin geçerli ise
            docInfo['Sorumlu Departman'] = pathSegments[folderNameIndex];
        } else {
            docInfo['Sorumlu Departman'] = 'Ana Klasör';
        }
    } else {
        docInfo['Sorumlu Departman'] = 'Ana Klasör'; // Dosya direkt kök klasörde
    }

    let textContent = '';
    const fileExtension = path.extname(filePath).toLowerCase();

    try {
        if (fileExtension === '.pdf') {
            const dataBuffer = fs.readFileSync(filePath);
            const data = await PdfParse(dataBuffer);
            textContent = data.text;
            console.log(`--- PDF Metin İçeriği (${path.basename(filePath)}) ---`);
            console.log(textContent);
            console.log('--- Metin İçeriği Sonu ---');
        } else if (fileExtension === '.docx' || fileExtension === '.doc') {
            const result = await mammoth.extractRawText({ path: filePath });
            textContent = result.value;
        }
    } catch (e) {
        console.error(`Dosya metni okunurken hata oluştu ${filePath}:`, e);
        return docInfo;
    }

    // --- Bilgi Çekme ---
    let match;

    match = textContent.match(/Doküman No\s*[:\s]*([A-Z0-9.\-\s]+)/i);
    if (match) docInfo['Döküman No'] = match[1].trim();

    match = textContent.match(/Yayın Tarihi\s*[:\s]*(\d{2}[.\/]\d{2}[.\/]\d{4})/);
    if (match) docInfo['Tarih'] = match[1].trim();

    match = textContent.match(/Revizyon No\s*[:\s]*(\d+)/i);
    if (match) docInfo['Revizyon Sayısı'] = match[1].trim();

    match = textContent.match(/Revizyon Tarihi\s*[:\s]*(\d{2}[.\/]\d{2}[.\/]\d{4})/i);
    if (match) docInfo['Revizyon Tarihi'] = match[1].trim();

    return docInfo;
}

app.post('/upload', upload.array('files'), async (req, res) => {
    const uploadedFiles = req.files;
    if (!uploadedFiles || uploadedFiles.length === 0) {
        return res.status(400).send('No files uploaded or no folder selected.');
    }

    const extractedData = [];

    for (const file of uploadedFiles) {
        const originalRelativePath = file.originalname;
        
        const data = await extractInfo(file.path, originalRelativePath);
        if (data) {
            extractedData.push(data);
        }

        try {
            await fs.remove(file.path);
        } catch (e) {
            console.error(`Dosya silinirken hata oluştu ${file.path}:`, e);
        }
    }

    try {
        await fs.emptyDir(UPLOAD_DIR);
    } catch (e) {
        console.error(`Geçici yükleme klasörü temizlenirken hata oluştu ${UPLOAD_DIR}:`, e);
    }

    if (extractedData.length === 0) {
        return res.status(400).send('No PDF or Word documents found or processed.');
    }

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Belge Bilgileri');

    const headers = ['Döküman No', 'Tarih', 'Revizyon Tarihi', 'Revizyon Sayısı', 'Sorumlu Departman', 'Dosya İsmi'];
    worksheet.addRow(headers);

    extractedData.forEach(rowData => {
        const rowValues = headers.map(header => rowData[header] || '');
        worksheet.addRow(rowValues);
    });

    const buffer = await workbook.xlsx.writeBuffer();

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=Belge_Bilgileri.xlsx');
    res.send(buffer);
});

app.listen(PORT, () => {
    console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor`);
    fs.ensureDirSync(UPLOAD_DIR);
});

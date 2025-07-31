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
        // file.originalname contains the full relative path from the selected folder, e.g., 'FolderA/SubFolder/File.pdf'
        const relativePath = path.dirname(file.originalname);
        const destinationPath = path.join(UPLOAD_DIR, relativePath);
        fs.ensureDirSync(destinationPath); // Create folder if it doesn't exist
        cb(null, destinationPath);
    },
    filename: (req, file, cb) => {
        cb(null, path.basename(file.originalname)); // Use original file name
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

    // --- Dosya İsmi Mantığı (En Son Güncelleme) ---
    const fullFileNameWithExt = path.basename(originalRelativePath); // E.g., 'FR.01-BS.TL.02_0-SMS ve Maling Cevap Şablonu.pdf'
    const fileNameWithoutExt = path.parse(fullFileNameWithExt).name; // E.g., 'FR.01-BS.TL.02_0-SMS ve Maling Cevap Şablonu'

    // Split by the first hyphen and take the second part (index 1)
     const firstHyphenIndex = fileNameWithoutExt.indexOf('-');
    if (firstHyphenIndex !== -1 && firstHyphenIndex < fileNameWithoutExt.length - 1) {
        // substring kullanarak ilk '-' işaretinden sonraki tüm kısmı alıyoruz.
        docInfo['Dosya İsmi'] = fileNameWithoutExt.substring(firstHyphenIndex + 1).trim();
    } else {
        docInfo['Dosya İsmi'] = fileNameWithoutExt.trim(); // '-' yoksa tüm uzantısız adı kullan
    }

    // --- Sorumlu Departman Mantığı (En Son Güncelleme) ---
    // originalRelativePath: 'ParentFolder/ChildFolder/FileName.pdf'
    const pathSegments = originalRelativePath.split(path.sep); // Split by OS-specific path separator

    // If the file is in a subfolder (more than just filename + folder name)
    // Example: ['ParentFolder', 'ChildFolder', 'FileName.pdf']
    // If just: ['FileName.pdf'] or ['Folder', 'FileName.pdf']
    if (pathSegments.length >= 2) {
        // If the structure is 'Folder/File.pdf', the parent is 'Folder'
        // If the structure is 'Grandparent/Parent/File.pdf', the parent is 'Parent'
        // We want the *last folder name* in the relative path.
        // If 'some_folder/my_doc.pdf', pathSegments = ['some_folder', 'my_doc.pdf']
        // then pathSegments.length - 2 = 0, so pathSegments[0] = 'some_folder'
        // This handles cases where file is in immediate subfolder.
        const parentFolderName = pathSegments[pathSegments.length - 2];
        if (parentFolderName && parentFolderName !== fullFileNameWithExt) { // Ensure it's an actual folder name
            docInfo['Sorumlu Departman'] = parentFolderName;
        } else {
            docInfo['Sorumlu Departman'] = 'Ana Klasör'; // Fallback if direct file in root or parsing issue
        }
    } else {
        docInfo['Sorumlu Departman'] = 'Ana Klasör'; // File is directly in the selected root folder
    }

    let textContent = '';
    const fileExtension = path.extname(filePath).toLowerCase();

    try {
        if (fileExtension === '.pdf') {
            const dataBuffer = fs.readFileSync(filePath);
            const data = await PdfParse(dataBuffer);
            textContent = data.text;
            console.log(`--- PDF Metin İçeriği (${path.basename(filePath)}) ---`);
            console.log(textContent); // DEBUGGING LINE: Output the extracted text content
            console.log('--- Metin İçeriği Sonu ---');
        } else if (fileExtension === '.docx' || fileExtension === '.doc') {
            const result = await mammoth.extractRawText({ path: filePath });
            textContent = result.value;
        }
    } catch (e) {
        console.error(`Dosya metni okunurken hata oluştu ${filePath}:`, e);
        return docInfo; // Return empty info on error
    }

    // --- Bilgi Çekme (Revizyon Tarihi dahil, regex'ler daha da esnekleştirildi) ---
    let match;

    // Doküman No (More flexible regex: for spaces and hyphens)
    match = textContent.match(/Doküman No\s*[:\s]*([A-Z0-9.\-\s]+)/i);
    if (match) docInfo['Döküman No'] = match[1].trim();

    // Yayın Tarihi (More flexible regex)
    match = textContent.match(/Yayın Tarihi\s*[:\s]*(\d{2}[.\/]\d{2}[.\/]\d{4})/);
    if (match) docInfo['Tarih'] = match[1].trim();

    // Revizyon No (More flexible regex)
    match = textContent.match(/Revizyon No\s*[:\s]*(\d+)/i);
    if (match) docInfo['Revizyon Sayısı'] = match[1].trim();

    // Revizyon Tarihi (More flexible regex: for spaces, colon, and different date formats)
    // The previous output in the PDF content was "Revizyon Tarihi: 30.03.2020"
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

        // Delete temporary file
        try {
            await fs.remove(file.path);
        } catch (e) {
            console.error(`Dosya silinirken hata oluştu ${file.path}:`, e);
        }
    }

    // Clean up all temporary folders created by multer
    try {
        await fs.emptyDir(UPLOAD_DIR); // Empties the 'uploads' folder completely
    } catch (e) {
        console.error(`Geçici yükleme klasörü temizlenirken hata oluştu ${UPLOAD_DIR}:`, e);
    }

    if (extractedData.length === 0) {
        return res.status(400).send('No PDF or Word documents found or processed.');
    }

    // Create Excel
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Belge Bilgileri');

    // Add headers - Adjusted order for 'Sorumlu Departman' and 'Dosya İsmi'
    const headers = ['Döküman No', 'Tarih', 'Revizyon Tarihi', 'Revizyon Sayısı', 'Sorumlu Departman', 'Dosya İsmi'];
    worksheet.addRow(headers);

    // Add data
    extractedData.forEach(rowData => {
        const rowValues = headers.map(header => rowData[header] || '');
        worksheet.addRow(rowValues);
    });

    // Save Excel file to buffer
    const buffer = await workbook.xlsx.writeBuffer();

    // Send Excel file to the user
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=Belge_Bilgileri.xlsx');
    res.send(buffer);
});

app.listen(PORT, () => {
    console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor`);
    fs.ensureDirSync(UPLOAD_DIR); // Create uploads folder on app start
});

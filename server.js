const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors()); // Enable CORS for Angular app
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from assets folder
app.use('/assets', express.static(path.join(__dirname, 'assets')));

// Test endpoint to verify server is running
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Server is running!', 
    timestamp: new Date().toISOString(),
    endpoints: {
      upload: 'POST /api/upload-pdf',
      getAllPdfs: 'GET /api/pdfs',
      getPdfById: 'GET /api/pdfs/:id',
      viewPdf: 'GET /api/pdfs/:id/view'
    }
  });
});

// MongoDB connection - reading from .env file
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.warn('⚠️  MONGODB_URI not found in .env file. Using default: mongodb://localhost:27017/pdfstorage');
  console.warn('💡 Please create a .env file with: MONGODB_URI=your_connection_string');
}

mongoose.connect(MONGODB_URI || 'mongodb://localhost:27017/pdfstorage')
.then(() => {
  console.log('✅ MongoDB connected successfully');
  if (MONGODB_URI) {
    console.log('📝 Using connection string from .env file');
  }
})
.catch((err) => {
  console.error('❌ MongoDB connection error:', err.message);
  process.exit(1);
});

// PDF Schema
const pdfSchema = new mongoose.Schema({
  filename: {
    type: String,
    required: true
  },
  originalName: {
    type: String,
    required: true
  },
  filePath: {
    type: String,
    required: true
  },
  fileSize: {
    type: Number,
    required: true
  },
  uploadDate: {
    type: Date,
    default: Date.now
  }
});

const PDF = mongoose.model('PDF', pdfSchema);

// Create assets folder if it doesn't exist
const assetsDir = path.join(__dirname, 'assets');
if (!fs.existsSync(assetsDir)) {
  fs.mkdirSync(assetsDir, { recursive: true });
}

// Configure multer for file upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, assetsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype === 'application/pdf') {
    cb(null, true);
  } else {
    cb(new Error('Only PDF files are allowed!'), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Upload PDF endpoint
app.post('/api/upload-pdf', upload.single('pdf'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No PDF file uploaded' });
    }

    // Store only the relative path (assets/filename.pdf) instead of full absolute path
    const relativePath = path.join('assets', req.file.filename).replace(/\\/g, '/'); // Use forward slashes
    
    const pdfData = new PDF({
      filename: req.file.filename,
      originalName: req.file.originalname,
      filePath: relativePath, // Store relative path only
      fileSize: req.file.size
    });

    const savedPdf = await pdfData.save();

    res.status(201).json({
      message: 'PDF uploaded successfully',
      data: {
        id: savedPdf._id,
        filename: savedPdf.filename,
        originalName: savedPdf.originalName,
        fileSize: savedPdf.fileSize,
        uploadDate: savedPdf.uploadDate,
        url: `/assets/${savedPdf.filename}`
      }
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload PDF', details: error.message });
  }
});

// Get all PDFs endpoint
app.get('/api/pdfs', async (req, res) => {
  try {
    const pdfs = await PDF.find().sort({ uploadDate: -1 });
    const pdfsWithUrl = pdfs.map(pdf => ({
      id: pdf._id,
      filename: pdf.filename,
      originalName: pdf.originalName,
      fileSize: pdf.fileSize,
      uploadDate: pdf.uploadDate,
      url: `/assets/${pdf.filename}`
    }));
    res.json({ pdfs: pdfsWithUrl });
  } catch (error) {
    console.error('Error fetching PDFs:', error);
    res.status(500).json({ error: 'Failed to fetch PDFs', details: error.message });
  }
});

// Get single PDF by ID endpoint
app.get('/api/pdfs/:id', async (req, res) => {
  try {
    const pdf = await PDF.findById(req.params.id);
    if (!pdf) {
      return res.status(404).json({ error: 'PDF not found' });
    }

    res.json({
      id: pdf._id,
      filename: pdf.filename,
      originalName: pdf.originalName,
      fileSize: pdf.fileSize,
      uploadDate: pdf.uploadDate,
      url: `/assets/${pdf.filename}`
    });
  } catch (error) {
    console.error('Error fetching PDF:', error);
    res.status(500).json({ error: 'Failed to fetch PDF', details: error.message });
  }
});

// Serve PDF file endpoint (for Angular app)
app.get('/api/pdfs/:id/view', async (req, res) => {
  try {
    const pdf = await PDF.findById(req.params.id);
    if (!pdf) {
      return res.status(404).json({ error: 'PDF not found' });
    }

    const filePath = path.join(__dirname, 'assets', pdf.filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'PDF file not found on server' });
    }

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="${pdf.originalName}"`);
    res.sendFile(filePath);
  } catch (error) {
    console.error('Error serving PDF:', error);
    res.status(500).json({ error: 'Failed to serve PDF', details: error.message });
  }
});

// Delete PDF endpoint
app.delete('/api/pdfs/:id', async (req, res) => {
  try {
    const pdf = await PDF.findById(req.params.id);
    if (!pdf) {
      return res.status(404).json({ error: 'PDF not found' });
    }

    // Delete the file from filesystem
    // Handle both relative path (assets/filename.pdf) and absolute path (for backward compatibility)
    let filePath;
    if (pdf.filePath.startsWith('assets/') || pdf.filePath.startsWith('assets\\')) {
      // Relative path - construct full path
      filePath = path.join(__dirname, pdf.filePath);
    } else if (path.isAbsolute(pdf.filePath)) {
      // Absolute path (old format) - use as is
      filePath = pdf.filePath;
    } else {
      // Fallback to assets folder
      filePath = path.join(__dirname, 'assets', pdf.filename);
    }
    
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      console.log('Deleted file:', filePath);
    }

    // Delete from database
    await PDF.findByIdAndDelete(req.params.id);

    res.json({ 
      message: 'PDF deleted successfully',
      id: req.params.id
    });
  } catch (error) {
    console.error('Error deleting PDF:', error);
    res.status(500).json({ error: 'Failed to delete PDF', details: error.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

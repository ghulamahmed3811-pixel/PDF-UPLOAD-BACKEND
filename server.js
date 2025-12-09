const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Admin configuration
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin'; // Secret admin key from .env or default
const ADMIN_SESSIONS = new Map(); // Store active admin sessions (in production, use Redis or database)

// Middleware
app.use(cors({
  origin: true, // Allow all origins (adjust for production)
  credentials: true // Allow cookies/sessions
}));
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

const PDF = mongoose.models.PDF || mongoose.model("PDF", pdfSchema);

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

// Admin authentication endpoint
app.post('/api/admin/auth', (req, res) => {
  try {
    const { adminKey } = req.body;
    
    if (!adminKey) {
      return res.status(400).json({ error: 'Admin key is required' });
    }
    
    // Verify admin key
    if (adminKey !== ADMIN_KEY) {
      return res.status(401).json({ error: 'Invalid admin key' });
    }
    
    // Generate a secure session token
    const sessionToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + (24 * 60 * 60 * 1000); // 24 hours
    
    // Store session
    ADMIN_SESSIONS.set(sessionToken, {
      createdAt: Date.now(),
      expiresAt: expiresAt
    });
    
    console.log('✅ Admin authenticated, session created');
    
    res.json({
      success: true,
      message: 'Admin authenticated successfully',
      sessionToken: sessionToken,
      expiresAt: expiresAt
    });
  } catch (error) {
    console.error('Admin auth error:', error);
    res.status(500).json({ error: 'Authentication failed', details: error.message });
  }
});

// Middleware to verify admin session
const verifyAdmin = (req, res, next) => {
  const sessionToken = req.headers['x-admin-token'] || req.body.sessionToken;
  
  if (!sessionToken) {
    return res.status(401).json({ error: 'Admin authentication required' });
  }
  
  const session = ADMIN_SESSIONS.get(sessionToken);
  
  if (!session) {
    return res.status(401).json({ error: 'Invalid or expired admin session' });
  }
  
  // Check if session expired
  if (Date.now() > session.expiresAt) {
    ADMIN_SESSIONS.delete(sessionToken);
    return res.status(401).json({ error: 'Admin session expired' });
  }
  
  // Session is valid
  req.adminSession = session;
  next();
};

// Cleanup expired sessions periodically (every hour)
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of ADMIN_SESSIONS.entries()) {
    if (now > session.expiresAt) {
      ADMIN_SESSIONS.delete(token);
    }
  }
}, 60 * 60 * 1000); // Run every hour

// Upload PDF endpoint - PROTECTED
app.post('/api/upload-pdf', verifyAdmin, upload.single('pdf'), async (req, res) => {
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

// Delete PDF endpoint - PROTECTED
app.delete('/api/pdfs/:id', verifyAdmin, async (req, res) => {
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

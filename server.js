const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const cors = require('cors');
const crypto = require('crypto');
const cloudinary = require('cloudinary').v2;
const { Readable } = require('stream');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Admin configuration
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin'; // Secret admin key from .env or default
const ADMIN_SESSIONS = new Map(); // Store active admin sessions (in production, use Redis or database)

// Middleware
app.use(cors({
  origin: true, // Allow all origins (adjust for production)
  credentials: true, // Allow cookies/sessions
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Token', 'Accept'],
  exposedHeaders: ['Content-Type', 'Content-Disposition']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static files now served from Cloudinary - removed local assets folder

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

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
  console.warn('⚠️  Cloudinary credentials not found in .env file');
  console.warn('💡 Please add: CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET');
} else {
  console.log('✅ Cloudinary configured successfully');
}

// Configure multer to use memory storage (for Cloudinary upload)
const storage = multer.memoryStorage();

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

    console.log(`📤 Uploading PDF to Cloudinary: ${req.file.originalname} (${(req.file.size / 1024).toFixed(2)} KB)`);

    // Upload to Cloudinary
    const uniqueFilename = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    
    const uploadPromise = new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          resource_type: 'raw', // Use 'raw' for PDFs
          folder: 'pdf-uploads',
          public_id: uniqueFilename,
          format: 'pdf',
          overwrite: false
        },
        (error, result) => {
          if (error) {
            reject(error);
          } else {
            resolve(result);
          }
        }
      );

      // Pipe the file buffer to Cloudinary
      const bufferStream = new Readable();
      bufferStream.push(req.file.buffer);
      bufferStream.push(null);
      bufferStream.pipe(uploadStream);
    });

    const result = await uploadPromise;
    console.log('✅ PDF uploaded to Cloudinary:', result.secure_url);

    // Store Cloudinary URL in database
    const pdfData = new PDF({
      filename: `${uniqueFilename}.pdf`,
      originalName: req.file.originalname,
      filePath: result.secure_url, // Store Cloudinary URL
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
        url: savedPdf.filePath // Return Cloudinary URL (maintains API structure)
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
    const pdfs = await PDF.find({}).sort({ uploadDate: -1 });
    const pdfsWithUrl = pdfs.map(pdf => ({
      id: pdf._id,
      filename: pdf.filename,
      originalName: pdf.originalName,
      fileSize: pdf.fileSize,
      uploadDate: pdf.uploadDate,
      url: pdf.filePath // Return Cloudinary URL from database
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
      url: pdf.filePath // Return Cloudinary URL from database
    });
  } catch (error) {
    console.error('Error fetching PDF:', error);
    res.status(500).json({ error: 'Failed to fetch PDF', details: error.message });
  }
});

// Serve PDF file endpoint (for Angular app) - Redirects to Cloudinary URL
app.get('/api/pdfs/:id/view', async (req, res) => {
  try {
    const pdf = await PDF.findById(req.params.id);
    if (!pdf) {
      return res.status(404).json({ error: 'PDF not found' });
    }

    // Redirect to Cloudinary URL (works directly in iframes)
    if (pdf.filePath && pdf.filePath.startsWith('http')) {
      res.redirect(302, pdf.filePath);
    } else {
      return res.status(404).json({ error: 'PDF URL not found' });
    }
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

    // Delete from Cloudinary if it's a Cloudinary URL
    if (pdf.filePath && pdf.filePath.includes('cloudinary.com')) {
      try {
        // Extract public_id from Cloudinary URL
        // URL format: https://res.cloudinary.com/cloud_name/raw/upload/v1234567890/pdf-uploads/public_id.pdf
        const urlParts = pdf.filePath.split('/');
        const uploadIndex = urlParts.findIndex(part => part === 'upload');
        if (uploadIndex !== -1 && uploadIndex < urlParts.length - 1) {
          // Get everything after 'upload' including folder and public_id
          const pathAfterUpload = urlParts.slice(uploadIndex + 2).join('/'); // Skip 'upload' and version
          const publicId = pathAfterUpload.replace(/\.[^/.]+$/, ''); // Remove file extension
          
          const result = await cloudinary.uploader.destroy(publicId, { 
            resource_type: 'raw' 
          });
          console.log('✅ Deleted from Cloudinary:', publicId, result);
        }
      } catch (cloudinaryError) {
        console.error('⚠️  Failed to delete from Cloudinary:', cloudinaryError);
        // Continue with database deletion even if Cloudinary deletion fails
      }
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

// Export app for Vercel (serverless)
module.exports = app;

// Start server only in local/development environment
const isServerless = !!(process.env.VERCEL || process.env.VERCEL_ENV);
if (!isServerless) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

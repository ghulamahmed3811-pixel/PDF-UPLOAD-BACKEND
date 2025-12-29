const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const cors = require('cors');
const crypto = require('crypto');
const cloudinary = require('cloudinary').v2;
const { Readable } = require('stream');
const https = require('https');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Admin configuration
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin'; // Secret admin key from .env or default
const ADMIN_SESSIONS = new Map(); // Fallback in-memory store (for local dev)

// Admin Session Schema for MongoDB (persistent across serverless invocations)
const adminSessionSchema = new mongoose.Schema({
  sessionToken: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 86400 // Auto-delete after 24 hours (in seconds)
  },
  expiresAt: {
    type: Date,
    required: true,
    index: true
  }
}, {
  timestamps: false // We handle our own timestamps
});

// Create TTL index for automatic cleanup
adminSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const AdminSession = mongoose.models.AdminSession || mongoose.model("AdminSession", adminSessionSchema);

// Helper function to get base URL for API endpoints
const getBaseUrl = (req) => {
  // In production (Vercel), use the request host
  if (req && req.headers && req.headers.host) {
    const protocol = req.headers['x-forwarded-proto'] || 'https';
    return `${protocol}://${req.headers.host}`;
  }
  // Fallback for local development
  return process.env.API_BASE_URL || `http://localhost:${PORT}`;
};

// Middleware
app.use(cors({
  origin: true, // Allow all origins (adjust for production)
  credentials: true, // Allow cookies/sessions
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Token', 'Accept'],
  exposedHeaders: ['Content-Type']
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
app.post('/api/admin/auth', async (req, res) => {
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
    
    // Store session in MongoDB (persistent across serverless invocations)
    try {
      const session = new AdminSession({
        sessionToken: sessionToken,
        createdAt: Date.now(),
        expiresAt: new Date(expiresAt)
      });
      await session.save();
      
      // Also store in memory for local dev (backward compatibility)
      ADMIN_SESSIONS.set(sessionToken, {
        createdAt: Date.now(),
        expiresAt: expiresAt
      });
      
      console.log('✅ Admin authenticated, session created in MongoDB');
      
      res.json({
        success: true,
        message: 'Admin authenticated successfully',
        sessionToken: sessionToken,
        expiresAt: expiresAt
      });
    } catch (dbError) {
      console.error('❌ Error saving session to MongoDB:', dbError);
      // Fallback to in-memory storage if MongoDB fails
      ADMIN_SESSIONS.set(sessionToken, {
        createdAt: Date.now(),
        expiresAt: expiresAt
      });
      console.log('⚠️  Using in-memory session storage (fallback)');
      
      res.json({
        success: true,
        message: 'Admin authenticated successfully (using fallback storage)',
        sessionToken: sessionToken,
        expiresAt: expiresAt
      });
    }
  } catch (error) {
    console.error('Admin auth error:', error);
    res.status(500).json({ error: 'Authentication failed', details: error.message });
  }
});

// Middleware to verify admin session
const verifyAdmin = async (req, res, next) => {
  // Check headers (case-insensitive for serverless compatibility)
  // Vercel/AWS Lambda often normalize headers to lowercase
  const sessionToken = req.headers['x-admin-token'] || 
                       req.headers['X-Admin-Token'] || 
                       req.body.sessionToken;
  
  console.log('🔐 Admin verification check:');
  console.log(`   Method: ${req.method}`);
  console.log(`   Path: ${req.path}`);
  console.log(`   Headers received:`, Object.keys(req.headers).filter(h => h.toLowerCase().includes('admin')));
  console.log(`   Token present: ${!!sessionToken}`);
  console.log(`   Token length: ${sessionToken ? sessionToken.length : 0}`);
  
  if (!sessionToken) {
    console.error('❌ No admin token found in request');
    return res.status(401).json({ error: 'Admin authentication required' });
  }
  
  try {
    // First try MongoDB (persistent across serverless invocations)
    const dbSession = await AdminSession.findOne({ sessionToken: sessionToken });
    
    if (dbSession) {
      // Check if session expired
      if (Date.now() > dbSession.expiresAt.getTime()) {
        console.error('❌ Session expired in MongoDB');
        await AdminSession.deleteOne({ sessionToken: sessionToken });
        return res.status(401).json({ error: 'Admin session expired' });
      }
      
      // Session is valid
      console.log('✅ Admin session verified from MongoDB');
      req.adminSession = {
        createdAt: dbSession.createdAt.getTime(),
        expiresAt: dbSession.expiresAt.getTime()
      };
      return next();
    }
    
    // Fallback to in-memory storage (for local dev)
    const memorySession = ADMIN_SESSIONS.get(sessionToken);
    if (memorySession) {
      // Check if session expired
      if (Date.now() > memorySession.expiresAt) {
        console.error('❌ Session expired in memory');
        ADMIN_SESSIONS.delete(sessionToken);
        return res.status(401).json({ error: 'Admin session expired' });
      }
      
      // Session is valid
      console.log('✅ Admin session verified from memory');
      req.adminSession = memorySession;
      return next();
    }
    
    // Session not found
    console.error('❌ Session not found in MongoDB or memory');
    console.error(`   Token: ${sessionToken.substring(0, 10)}...`);
    return res.status(401).json({ error: 'Invalid or expired admin session' });
    
  } catch (dbError) {
    console.error('❌ Database error during session verification:', dbError);
    // Fallback to in-memory check
    const memorySession = ADMIN_SESSIONS.get(sessionToken);
    if (memorySession && Date.now() <= memorySession.expiresAt) {
      console.log('⚠️  Using in-memory session (MongoDB fallback)');
      req.adminSession = memorySession;
      return next();
    }
    return res.status(401).json({ error: 'Session verification failed' });
  }
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
          overwrite: false,
          access_mode: 'public', // CRITICAL: Make files publicly accessible to avoid 401 errors
          type: 'upload', // Ensure it's a direct upload (not private)
          allowed_formats: ['pdf'], // Explicitly allow PDF format
          use_filename: false, // Use our generated filename
          unique_filename: true // Ensure uniqueness
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
    console.log('   Resource type:', result.resource_type);
    console.log('   Access mode:', result.access_mode || 'public (default)');
    console.log('   Public ID:', result.public_id);
    
    // Verify the URL is accessible (should not require auth for public files)
    if (!result.secure_url || !result.secure_url.includes('cloudinary.com')) {
      console.error('⚠️  Warning: Invalid Cloudinary URL format:', result.secure_url);
    }

    // Store Cloudinary URL in database
    const pdfData = new PDF({
      filename: `${uniqueFilename}.pdf`,
      originalName: req.file.originalname,
      filePath: result.secure_url, // Store Cloudinary URL
      fileSize: req.file.size
    });

    const savedPdf = await pdfData.save();

    // Return backend proxy URL to avoid 401 errors (uses Admin API authentication)
    const baseUrl = getBaseUrl(req);
    const proxyUrl = `${baseUrl}/api/pdfs/${savedPdf._id}/view`;

    res.status(201).json({
      message: 'PDF uploaded successfully',
      data: {
        id: savedPdf._id,
        filename: savedPdf.filename,
        originalName: savedPdf.originalName,
        fileSize: savedPdf.fileSize,
        uploadDate: savedPdf.uploadDate,
        url: proxyUrl // Return backend proxy URL (uses Admin API to bypass delivery restrictions)
      }
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload PDF', details: error.message });
  }
});

// Get all PDFs endpoint - NO AUTH REQUIRED
app.get('/api/pdfs', async (req, res) => {
  try {
    const pdfs = await PDF.find({}).sort({ uploadDate: -1 });
    const baseUrl = getBaseUrl(req);
    const pdfsWithUrl = pdfs.map(pdf => ({
      id: pdf._id,
      filename: pdf.filename,
      originalName: pdf.originalName,
      fileSize: pdf.fileSize,
      uploadDate: pdf.uploadDate,
      url: `${baseUrl}/api/pdfs/${pdf._id}/view` // Return backend proxy URL (uses Admin API)
    }));
    res.json({ pdfs: pdfsWithUrl });
  } catch (error) {
    console.error('Error fetching PDFs:', error);
    res.status(500).json({ error: 'Failed to fetch PDFs', details: error.message });
  }
});

// Get single PDF by ID endpoint - NO AUTH REQUIRED
app.get('/api/pdfs/:id', async (req, res) => {
  try {
    const pdf = await PDF.findById(req.params.id);
    if (!pdf) {
      return res.status(404).json({ error: 'PDF not found' });
    }

    // Return backend proxy URL to avoid 401 errors (uses Admin API authentication)
    const baseUrl = getBaseUrl(req);
    const proxyUrl = `${baseUrl}/api/pdfs/${pdf._id}/view`;

    res.json({
      id: pdf._id,
      filename: pdf.filename,
      originalName: pdf.originalName,
      fileSize: pdf.fileSize,
      uploadDate: pdf.uploadDate,
      url: proxyUrl // Return backend proxy URL (uses Admin API to bypass delivery restrictions)
    });
  } catch (error) {
    console.error('Error fetching PDF:', error);
    res.status(500).json({ error: 'Failed to fetch PDF', details: error.message });
  }
});

// Serve PDF file endpoint (for Angular app) - Uses Cloudinary Admin API to fetch PDFs
// This bypasses public delivery restrictions and 401 errors using authenticated Admin API calls
app.get('/api/pdfs/:id/view', async (req, res) => {
  try {
    const pdf = await PDF.findById(req.params.id);
    if (!pdf) {
      return res.status(404).json({ error: 'PDF not found' });
    }

    const cloudinaryUrl = pdf.filePath;
    
    if (!cloudinaryUrl || !cloudinaryUrl.startsWith('http')) {
      return res.status(404).json({ error: 'PDF URL not found' });
    }

    console.log(`📄 Fetching PDF from Cloudinary using Admin API: ${pdf.originalName}`);
    console.log(`   Cloudinary URL: ${cloudinaryUrl}`);

    // Extract public_id from Cloudinary URL
    // URL format: https://res.cloudinary.com/{cloud_name}/raw/upload/{version}/{folder}/{public_id}
    let publicId = '';
    try {
      const urlMatch = cloudinaryUrl.match(/\/raw\/upload\/[^/]+\/(.+)$/);
      if (urlMatch) {
        publicId = urlMatch[1].replace(/\.pdf$/i, ''); // Remove .pdf extension if present
      } else {
        // Fallback: try to extract from pathname
        const parsedUrl = new URL(cloudinaryUrl);
        const pathParts = parsedUrl.pathname.split('/');
        const rawIndex = pathParts.indexOf('raw');
        if (rawIndex >= 0 && pathParts[rawIndex + 1] === 'upload') {
          // Extract everything after 'upload' excluding version
          publicId = pathParts.slice(rawIndex + 3).join('/').replace(/\.pdf$/i, '');
        }
      }
    } catch (parseError) {
      console.error('❌ Error parsing Cloudinary URL:', parseError);
    }

    if (!publicId) {
      console.error('❌ Could not extract public_id from URL:', cloudinaryUrl);
      // Fallback to HTTPS fetch
      return fetchViaHttps(cloudinaryUrl, pdf, res);
    }

    console.log(`   Extracted public_id: ${publicId}`);

    // Use Cloudinary Admin API with signed URLs to download the file
    // Signed URLs use Admin API credentials to bypass delivery restrictions
    try {
      console.log(`   Attempting to download via Admin API with authentication...`);
      
      // Generate a signed URL using Admin API credentials
      // This bypasses delivery restrictions by authenticating with API secret
      const signedUrl = cloudinary.utils.download_url(publicId, {
        resource_type: 'raw',
        secure: true,
        type: 'upload',
        sign_url: true, // CRITICAL: Sign the URL using API secret (bypasses 401)
        expiration_time: Math.round(Date.now() / 1000) + 3600 // Valid for 1 hour
      });

      console.log(`   Generated signed download URL: ${signedUrl.substring(0, 100)}...`);

      // Fetch using HTTPS with signed URL (authenticated request)
      const parsedUrl = new URL(signedUrl);
      const options = {
        hostname: parsedUrl.hostname,
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'GET',
        headers: {
          'User-Agent': 'PDF-Library-Server/1.0',
          'Accept': 'application/pdf, application/octet-stream, */*'
        }
      };

      https.get(options, (cloudinaryRes) => {
        if (cloudinaryRes.statusCode === 401) {
          console.error(`❌ Still getting 401 with signed URL. Please enable "PDF and ZIP files delivery" in Cloudinary Security settings.`);
          console.error(`   Go to: https://cloudinary.com/console > Settings > Security > Enable "PDF and ZIP files delivery"`);
        }
        handleCloudinaryResponse(cloudinaryRes, pdf, res, signedUrl);
      }).on('error', (err) => {
        console.error('❌ Error fetching PDF via signed URL:', err);
        // Try fallback to original URL
        console.log('   Falling back to original Cloudinary URL...');
        return fetchViaHttps(cloudinaryUrl, pdf, res);
      });

    } catch (apiError) {
      console.error('❌ Error generating signed download URL:', apiError);
      console.error('   Make sure CLOUDINARY_API_SECRET is set in your environment variables');
      // Fallback to direct HTTPS fetch
      console.log('   Falling back to direct HTTPS fetch...');
      return fetchViaHttps(cloudinaryUrl, pdf, res);
    }

  } catch (error) {
    console.error('Error serving PDF:', error);
    res.status(500).json({ error: 'Failed to serve PDF', details: error.message });
  }
});

// Helper function to fetch PDF via HTTPS (fallback method)
function fetchViaHttps(cloudinaryUrl, pdf, res) {
  console.log(`📄 Fetching PDF via HTTPS (fallback): ${pdf.originalName}`);
  const parsedUrl = new URL(cloudinaryUrl);
  const options = {
    hostname: parsedUrl.hostname,
    path: parsedUrl.pathname + parsedUrl.search,
    method: 'GET',
    headers: {
      'User-Agent': 'PDF-Library-Server/1.0',
      'Accept': 'application/pdf, application/octet-stream, */*'
    }
  };

  https.get(options, (cloudinaryRes) => {
    handleCloudinaryResponse(cloudinaryRes, pdf, res, cloudinaryUrl);
  }).on('error', (err) => {
    console.error('❌ Error fetching PDF via HTTPS:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to fetch PDF', details: err.message });
    }
  });
}

// Helper function to handle Cloudinary response
function handleCloudinaryResponse(cloudinaryRes, pdf, res, url) {
  if (cloudinaryRes.statusCode !== 200) {
    console.error(`❌ Cloudinary returned status ${cloudinaryRes.statusCode} for URL: ${url.substring(0, 100)}...`);
    console.error(`   Response headers:`, cloudinaryRes.headers);
    
    let errorBody = '';
    cloudinaryRes.on('data', (chunk) => { errorBody += chunk; });
    cloudinaryRes.on('end', () => {
      console.error(`   Error body: ${errorBody}`);
      
      // Provide specific guidance for 401 errors
      let errorMessage = `Failed to fetch PDF from Cloudinary (Status ${cloudinaryRes.statusCode})`;
      if (cloudinaryRes.statusCode === 401) {
        errorMessage += `. This usually means PDF delivery is disabled in your Cloudinary account. `;
        errorMessage += `Please enable "PDF and ZIP files delivery" in Cloudinary Security settings: `;
        errorMessage += `https://cloudinary.com/console > Settings > Security > "PDF and ZIP files delivery"`;
      }
      
      if (!res.headersSent) {
        return res.status(cloudinaryRes.statusCode).json({ 
          error: errorMessage,
          details: errorBody.substring(0, 200),
          help: cloudinaryRes.statusCode === 401 ? 
            'Enable PDF delivery in Cloudinary Settings > Security > "PDF and ZIP files delivery"' :
            'Check Cloudinary credentials and file accessibility'
        });
      }
    });
    return;
  }

  console.log(`✅ Successfully fetching PDF from Cloudinary, status: ${cloudinaryRes.statusCode}`);
  console.log(`   Cloudinary Content-Type: ${cloudinaryRes.headers['content-type']}`);
  console.log(`   Cloudinary Content-Disposition: ${cloudinaryRes.headers['content-disposition'] || 'none'}`);
  console.log(`   Content-Length: ${cloudinaryRes.headers['content-length']}`);

  // CRITICAL: Use writeHead to explicitly commit headers before any data
  // DO NOT include Content-Disposition header - this causes downloads
  // Only Content-Type: application/pdf is needed for browsers to display inline
  if (!res.headersSent) {
    const headers = {
      'Content-Type': 'application/pdf',
      'Cache-Control': 'public, max-age=3600',
      'Accept-Ranges': 'bytes'
    };
    
    // Add Content-Length if available
    if (cloudinaryRes.headers['content-length']) {
      headers['Content-Length'] = cloudinaryRes.headers['content-length'];
    }
    
    // Use writeHead to commit headers explicitly - this prevents Express from adding anything
    res.writeHead(200, headers);
    
    console.log(`   ✅ Headers committed - Content-Type: application/pdf`);
    console.log(`   ✅ NO Content-Disposition header`);
  } else {
    console.error('❌ ERROR: Headers already sent!');
    return;
  }
  
  // Pipe the stream - headers are already committed, so this will just send data
  cloudinaryRes.pipe(res);
  
  cloudinaryRes.on('error', (err) => {
    console.error('❌ Error streaming PDF from Cloudinary:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to stream PDF', details: err.message });
    } else {
      res.end();
    }
  });

  res.on('close', () => {
    console.log('✅ PDF stream completed');
  });
}

// Delete PDF endpoint - PROTECTED
app.delete('/api/pdfs/:id', verifyAdmin, async (req, res) => {
  try {
    const pdfId = req.params.id;
    console.log(`🗑️  Delete request for PDF ID: ${pdfId}`);
    
    // Validate MongoDB ObjectId format
    if (!mongoose.Types.ObjectId.isValid(pdfId)) {
      console.error(`❌ Invalid PDF ID format: ${pdfId}`);
      return res.status(400).json({ error: 'Invalid PDF ID format' });
    }
    
    const pdf = await PDF.findById(pdfId);
    if (!pdf) {
      console.error(`❌ PDF not found with ID: ${pdfId}`);
      return res.status(404).json({ error: 'PDF not found' });
    }

    console.log(`✅ PDF found: ${pdf.originalName}`);
    console.log(`   File path: ${pdf.filePath}`);

    // Delete from Cloudinary if it's a Cloudinary URL
    if (pdf.filePath && pdf.filePath.includes('cloudinary.com')) {
      try {
        // Extract public_id from Cloudinary URL using the same logic as view endpoint
        // URL format: https://res.cloudinary.com/{cloud_name}/raw/upload/{version}/{folder}/{public_id}
        let publicId = '';
        
        try {
          const urlMatch = pdf.filePath.match(/\/raw\/upload\/[^/]+\/(.+)$/);
          if (urlMatch) {
            publicId = urlMatch[1].replace(/\.pdf$/i, ''); // Remove .pdf extension if present
          } else {
            // Fallback: try to extract from pathname
            const parsedUrl = new URL(pdf.filePath);
            const pathParts = parsedUrl.pathname.split('/');
            const rawIndex = pathParts.indexOf('raw');
            if (rawIndex >= 0 && pathParts[rawIndex + 1] === 'upload') {
              // Extract everything after 'upload' excluding version
              publicId = pathParts.slice(rawIndex + 3).join('/').replace(/\.pdf$/i, '');
            }
          }
        } catch (parseError) {
          console.error('❌ Error parsing Cloudinary URL:', parseError);
        }

        if (publicId) {
          console.log(`   Extracted public_id: ${publicId}`);
          const result = await cloudinary.uploader.destroy(publicId, { 
            resource_type: 'raw' 
          });
          console.log(`✅ Deleted from Cloudinary: ${publicId}`, result);
        } else {
          console.warn('⚠️  Could not extract public_id from URL, skipping Cloudinary deletion');
        }
      } catch (cloudinaryError) {
        console.error('⚠️  Failed to delete from Cloudinary:', cloudinaryError);
        // Continue with database deletion even if Cloudinary deletion fails
      }
    } else {
      console.log('   Not a Cloudinary URL, skipping Cloudinary deletion');
    }

    // Delete from database
    await PDF.findByIdAndDelete(pdfId);
    console.log(`✅ PDF deleted from database: ${pdfId}`);

    res.json({ 
      message: 'PDF deleted successfully',
      id: pdfId
    });
  } catch (error) {
    console.error('❌ Error deleting PDF:', error);
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

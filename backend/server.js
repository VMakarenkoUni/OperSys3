const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');

const app = express();
const PORT = 8000;

// Database connection
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'FileManager',
    password: 'newpassword',
    port: 5433
});

// JWT configuration
const JWT_SECRET = 'REm6NjcNNbDXs92Dyk+YvfY7ZXWaeHm4uUxpNWHSaVUtyJgwzkC8l0rGkED3Vvzn';
const JWT_EXPIRATION = '7d';

// File upload directory
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Multer configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, `${req.userId}_${file.originalname}`)
});

const upload = multer({ 
    storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB max
});

// Middleware
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }
        req.userId = user.user_id;
        req.username = user.username;
        next();
    });
};

// ============ AUTH ROUTES (RESTful) ============

// POST /api/auth/register - Register new user
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        // Check if user exists
        const existing = await pool.query(
            'SELECT user_id FROM users WHERE username = $1',
            [username]
        );

        if (existing.rows.length > 0) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash password with SHA-256
        const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

        // Create user
        const result = await pool.query(
            'INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING user_id, username',
            [username, hashedPassword, email]
        );

        const user = result.rows[0];

        // Generate JWT token
        const token = jwt.sign(
            { user_id: user.user_id, username: user.username },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRATION }
        );

        res.status(201).json({ token, username: user.username });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// POST /api/auth/login - Login user
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        // Hash password
        const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

        // Find user
        const result = await pool.query(
            'SELECT user_id, username FROM users WHERE username = $1 AND password = $2',
            [username, hashedPassword]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];

        // Generate JWT token
        const token = jwt.sign(
            { user_id: user.user_id, username: user.username },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRATION }
        );

        res.json({ token, username: user.username });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// GET /api/auth/validate - Validate token
app.get('/api/auth/validate', authenticateToken, (req, res) => {
    res.json({ valid: true, username: req.username });
});

// ============ FILE ROUTES (RESTful) ============

// GET /api/files - List all files with optional sorting and filtering
app.get('/api/files', authenticateToken, async (req, res) => {
    try {
        const { ascending, types } = req.query;

        let query = 'SELECT * FROM file_metadata WHERE 1=1';
        const params = [];

        // Filter by types (variant 99: html, png)
        if (types) {
            const typeArray = Array.isArray(types) ? types : [types];
            const placeholders = typeArray.map((_, i) => `$${i + 1}`).join(',');
            query += ` AND type IN (${placeholders})`;
            params.push(...typeArray);
        }

        // Sort by name (variant 99)
        if (ascending === 'true') {
            query += ' ORDER BY name ASC';
        } else if (ascending === 'false') {
            query += ' ORDER BY name DESC';
        }

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        console.error('List files error:', error);
        res.status(500).json({ error: 'Failed to list files' });
    }
});

// POST /api/files - Upload new file (accepts ANY file type)
app.post('/api/files', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file provided' });
        }

        const filename = req.file.originalname;
        const extension = filename.includes('.') ? filename.split('.').pop().toLowerCase() : '';

        // Check for duplicate filename (global workspace)
        const existing = await pool.query(
            'SELECT file_id FROM file_metadata WHERE name = $1',
            [filename]
        );

        if (existing.rows.length > 0) {
            // Delete uploaded file
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'File with this name already exists' });
        }

        // Insert file metadata
        const result = await pool.query(
            `INSERT INTO file_metadata 
            (name, type, size, file_path, uploader_id, uploader_name, editor_id, editor_name)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *`,
            [filename, extension, req.file.size, req.file.path, req.userId, req.username, req.userId, req.username]
        );

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'File upload failed' });
    }
});

// GET /api/files/:id - Download file or get metadata (based on Accept header)
app.get('/api/files/:id', authenticateToken, async (req, res) => {
    try {
        const fileId = parseInt(req.params.id);

        const result = await pool.query(
            'SELECT * FROM file_metadata WHERE file_id = $1',
            [fileId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'File not found' });
        }

        const fileMetadata = result.rows[0];

        // Check Accept header for RESTful content negotiation
        const acceptHeader = req.headers['accept'] || '';
        
        if (acceptHeader.includes('application/json')) {
            // Return metadata as JSON
            res.json(fileMetadata);
        } else {
            // Return file content
            if (!fs.existsSync(fileMetadata.file_path)) {
                return res.status(404).json({ error: 'File not found on disk' });
            }

            res.download(fileMetadata.file_path, fileMetadata.name);
        }
    } catch (error) {
        console.error('Get file error:', error);
        res.status(500).json({ error: 'Failed to retrieve file' });
    }
});

// PUT /api/files/:id - Replace/edit file (anyone can edit in shared workspace)
app.put('/api/files/:id', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        const fileId = parseInt(req.params.id);

        if (!req.file) {
            return res.status(400).json({ error: 'No file provided' });
        }

        // Get existing file metadata
        const existing = await pool.query(
            'SELECT * FROM file_metadata WHERE file_id = $1',
            [fileId]
        );

        if (existing.rows.length === 0) {
            fs.unlinkSync(req.file.path); // Clean up uploaded file
            return res.status(404).json({ error: 'File not found' });
        }

        const oldMetadata = existing.rows[0];
        const newExtension = req.file.originalname.includes('.') 
            ? req.file.originalname.split('.').pop().toLowerCase() 
            : '';

        // Verify file type matches original
        if (newExtension !== oldMetadata.type) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ 
                error: `File type must match original (${oldMetadata.type})` 
            });
        }

        // Delete old file
        if (fs.existsSync(oldMetadata.file_path)) {
            fs.unlinkSync(oldMetadata.file_path);
        }

        // Update metadata with new file info and editor
        const result = await pool.query(
            `UPDATE file_metadata 
            SET size = $1, file_path = $2, editor_id = $3, editor_name = $4, modified_date = CURRENT_TIMESTAMP
            WHERE file_id = $5
            RETURNING *`,
            [req.file.size, req.file.path, req.userId, req.username, fileId]
        );

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Edit file error:', error);
        res.status(500).json({ error: 'Failed to edit file' });
    }
});

// DELETE /api/files/:id - Delete file (only owner can delete)
app.delete('/api/files/:id', authenticateToken, async (req, res) => {
    try {
        const fileId = parseInt(req.params.id);

        // Get file metadata
        const result = await pool.query(
            'SELECT * FROM file_metadata WHERE file_id = $1',
            [fileId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'File not found' });
        }

        const fileMetadata = result.rows[0];

         // Check ownership (convert both to numbers for comparison)
        if (parseInt(fileMetadata.uploader_id) !== parseInt(req.userId)) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Delete physical file
        if (fs.existsSync(fileMetadata.file_path)) {
            fs.unlinkSync(fileMetadata.file_path);
        }

        // Delete metadata
        await pool.query('DELETE FROM file_metadata WHERE file_id = $1', [fileId]);

        res.status(204).send();
    } catch (error) {
        console.error('Delete file error:', error);
        res.status(500).json({ error: 'Failed to delete file' });
    }
});

// ============ SYNC ROUTES (RESTful) ============

// POST /api/sync/compare - Compare local and remote files
app.post('/api/sync/compare', authenticateToken, async (req, res) => {
    try {
        const { localFiles } = req.body;

        if (!Array.isArray(localFiles)) {
            return res.status(400).json({ error: 'localFiles must be an array' });
        }

        // Get all remote files
        const result = await pool.query('SELECT name FROM file_metadata');
        const remoteNames = result.rows.map(row => row.name);

        const toUpload = localFiles.filter(name => !remoteNames.includes(name));
        const toDownload = remoteNames.filter(name => !localFiles.includes(name));

        res.json({ toUpload, toDownload });
    } catch (error) {
        console.error('Sync compare error:', error);
        res.status(500).json({ error: 'Sync comparison failed' });
    }
});

// GET /api/sync/files - Get all remote files
app.get('/api/sync/files', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM file_metadata');
        res.json(result.rows);
    } catch (error) {
        console.error('Get sync files error:', error);
        res.status(500).json({ error: 'Failed to get remote files' });
    }
});

// ============ SERVER START ============

app.listen(PORT, () => {
    console.log(`✓ File Manager API running on http://localhost:${PORT}`);
    console.log(`✓ RESTful endpoints ready`);
});

module.exports = app; // For testing
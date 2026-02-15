const express = require('express');
const mysql = require('mysql2/promise');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const SECRET_KEY = process.env.JWT_SECRET || 'battledesign_SUPER_SECRET_2026';

// ======================================================
// MIDDLEWARE
// ======================================================
app.use(express.json());
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ======================================================
// DATABASE CONNECTION
// ======================================================
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// ======================================================
// EMAIL CONFIGURATION
// ======================================================
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'mail.battledesign.id',
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: { rejectUnauthorized: false }
});

// ======================================================
// JWT AUTH MIDDLEWARE
// ======================================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// ======================================================
// MULTER (UPLOAD IMAGE)
// ======================================================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = 'uploads/';
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname.replace(/\s/g, '_'));
    }
});
const upload = multer({ storage });

// ======================================================
// ACTIVITY LOG
// ======================================================
async function logActivity(userId, action, details) {
    try {
        await pool.execute(
            'INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)',
            [userId, action, details]
        );
    } catch (err) {
        console.error('Log Error:', err.message);
    }
}

// ======================================================
// AUTH ROUTES
// ======================================================

// ----------------------
// LOGIN
// ----------------------
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [users] = await pool.execute(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({ success: false, message: 'User tidak ditemukan' });
        }

        const user = users[0];
        let isMatch = false;

        if (user.password_hash?.startsWith('$2')) {
            isMatch = await bcrypt.compare(password, user.password_hash);
        } else {
            isMatch = password === user.password_hash;
        }

        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Password salah' });
        }

        const token = jwt.sign(
            { id: user.id, role: user.role, name: user.full_name },
            SECRET_KEY,
            { expiresIn: '1d' }
        );

        await logActivity(user.id, 'LOGIN', 'Login ke dashboard');

        res.json({ success: true, token });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ----------------------
// FORGOT PASSWORD (FIX)
// ----------------------
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const [users] = await pool.execute(
            'SELECT id, full_name FROM users WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'Email tidak terdaftar' });
        }

        const token = crypto.randomBytes(32).toString('hex');

        // 🔥 FIX: hitung expire langsung di MySQL
        await pool.execute(
            `UPDATE users 
             SET reset_token = ?, 
                 reset_expires = DATE_ADD(NOW(), INTERVAL 1 HOUR)
             WHERE id = ?`,
            [token, users[0].id]
        );

        const resetLink = `https://battledesign.id/reset-password.html?token=${token}`;

        await transporter.sendMail({
            from: `"battledesign" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Reset Password Akun Anda',
            html: `
                <p>Halo <b>${users[0].full_name}</b>,</p>
                <p>Silakan klik link berikut untuk reset password:</p>
                <a href="${resetLink}">${resetLink}</a>
                <p><i>Link berlaku selama 1 jam</i></p>
            `
        });

        res.json({ success: true, message: 'Link reset password berhasil dikirim' });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ----------------------
// RESET PASSWORD
// ----------------------
app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    if (!newPassword || newPassword.length < 8) {
        return res.status(400).json({
            success: false,
            message: 'Password minimal 8 karakter'
        });
    }

    try {
        const [users] = await pool.execute(
            'SELECT id FROM users WHERE reset_token = ? AND reset_expires > NOW()',
            [token]
        );

        if (users.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Token tidak valid atau sudah kedaluwarsa'
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await pool.execute(
            `UPDATE users 
             SET password_hash = ?, 
                 reset_token = NULL, 
                 reset_expires = NULL 
             WHERE id = ?`,
            [hashedPassword, users[0].id]
        );

        await logActivity(users[0].id, 'RESET_PASSWORD', 'Reset password via email');

        res.json({ success: true, message: 'Password berhasil diperbarui' });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ======================================================
// USERS MANAGEMENT
// ======================================================
app.get('/api/users', async (req, res) => {
    const [rows] = await pool.execute(
        'SELECT id, full_name, email, phone, role FROM users ORDER BY full_name'
    );
    res.json({ success: true, data: rows });
});

app.post('/api/users', authenticateToken, async (req, res) => {
    const { email, full_name, phone, role, password } = req.body;
    const id = uuidv4();
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.execute(
        'INSERT INTO users (id, email, full_name, phone, role, password_hash) VALUES (?, ?, ?, ?, ?, ?)',
        [id, email, full_name, phone, role, hashedPassword]
    );

    res.json({ success: true, message: 'User berhasil ditambahkan' });
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
    const { full_name, email, phone, role, password } = req.body;

    let query = 'UPDATE users SET full_name=?, email=?, phone=?, role=?';
    let params = [full_name, email, phone, role];

    if (password) {
        const hashed = await bcrypt.hash(password, 10);
        query += ', password_hash=?';
        params.push(hashed);
    }

    query += ' WHERE id=?';
    params.push(req.params.id);

    await pool.execute(query, params);
    res.json({ success: true, message: 'User berhasil diperbarui' });
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
    await pool.execute('DELETE FROM users WHERE id=?', [req.params.id]);
    res.json({ success: true, message: 'User berhasil dihapus' });
});

// ======================================================
// PROPERTIES
// ======================================================
app.post('/api/upload-multiple', authenticateToken, upload.array('images', 10), (req, res) => {
    const urls = req.files.map(file =>
        `${req.protocol}://${req.get('host')}/uploads/${file.filename}`
    );
    res.json({ success: true, urls });
});

app.get('/api/properties', async (req, res) => {
    const [rows] = await pool.execute(
        'SELECT * FROM properties ORDER BY created_at DESC'
    );
    res.json({ success: true, data: rows });
});

app.post('/api/properties', authenticateToken, async (req, res) => {
    const id = uuidv4();
    const slug = req.body.title.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '-' + Date.now();

    await pool.execute(
        `INSERT INTO properties
         (id, agent_id, title, slug, description, p_type, category, price, location_address, features, image_url, is_available)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
        [
            id,
            req.body.agent_id,
            req.body.title,
            slug,
            req.body.description,
            req.body.p_type,
            req.body.category,
            req.body.price,
            req.body.location_address,
            req.body.features,
            req.body.image_url
        ]
    );

    res.json({ success: true, message: 'Properti berhasil disimpan' });
});

app.delete('/api/properties/:id', authenticateToken, async (req, res) => {
    await pool.execute('DELETE FROM properties WHERE id=?', [req.params.id]);
    res.json({ success: true, message: 'Properti berhasil dihapus' });
});

// ======================================================
// DASHBOARD STATS
// ======================================================
app.get('/api/stats', authenticateToken, async (req, res) => {
    const [[total]] = await pool.execute('SELECT COUNT(*) count FROM properties');
    const [[aktif]] = await pool.execute('SELECT COUNT(*) count FROM properties WHERE is_available = 1');
    const [[agen]] = await pool.execute("SELECT COUNT(*) count FROM users WHERE role = 'AGENT'");

    res.json({
        success: true,
        data: {
            total_listing: total.count,
            properti_aktif: aktif.count,
            total_agen: agen.count
        }
    });
});

// ======================================================
// START SERVER
// ======================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server battledesign.id berjalan di port ${PORT}`);
});

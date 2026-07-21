const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

// Import Middleware
const { requireAuth, requireAdmin, verifySession } = require('./middleware/auth');
const { 
    globalLimiter, 
    authLimiter, 
    adminLimiter,
    sanitizeInput,
    xssProtection,
    securityHeaders 
} = require('./middleware/security');

const app = express();
const PORT = process.env.PORT || 10000;

// ============ TRUST PROXY ============
app.set('trust proxy', 1);

// ============ DATABASE CONNECTION ============
console.log('🔐 CONNECTING TO MONGODB...');

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
.then(() => {
    console.log('✅ MONGODB CONNECTED SUCCESSFULLY!');
    createDefaultAdmin();
})
.catch(err => {
    console.log('❌ MONGODB CONNECTION ERROR:', err.message);
    process.exit(1);
});

// ============ USER SCHEMA ============
const UserSchema = new mongoose.Schema({
    deviceId: { 
        type: String, 
        unique: true, 
        required: true,
        trim: true,
        minlength: 3,
        index: true
    },
    passwordHash: { 
        type: String, 
        required: true,
        select: false
    },
    role: { 
        type: String, 
        default: 'user',
        enum: ['user', 'admin'],
        index: true
    },
    isActive: { 
        type: Boolean, 
        default: true,
        index: true
    },
    lastLogin: { 
        type: Date 
    },
    loginAttempts: { 
        type: Number, 
        default: 0 
    },
    lockUntil: { 
        type: Date 
    },
    ipAddress: { 
        type: String 
    },
    userAgent: { 
        type: String 
    },
    sessionId: { 
        type: String 
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    }
}, {
    timestamps: true
});

// Indexes for performance
UserSchema.index({ deviceId: 1, isActive: 1 });
UserSchema.index({ role: 1, isActive: 1 });

const User = mongoose.model('User', UserSchema);

// ============ CREATE DEFAULT ADMIN ============
async function createDefaultAdmin() {
    try {
        const adminExists = await User.findOne({ role: 'admin' });
        if (!adminExists) {
            const adminPassword = process.env.ADMIN_PASSWORD || 'ZenoxUltraAdmin@2026#Secure$';
            const hashedPassword = await bcrypt.hash(adminPassword, 12);
            const admin = new User({
                deviceId: 'ZENOX-ADMIN-001',
                passwordHash: hashedPassword,
                role: 'admin',
                isActive: true
            });
            await admin.save();
            console.log('✅ DEFAULT ADMIN USER CREATED!');
            console.log('📛 ADMIN DEVICE ID: ZENOX-ADMIN-001');
            console.log('🔑 ADMIN PASSWORD: ' + adminPassword);
            console.log('🔒 THIS IS THE ONLY ADMIN ACCESS POINT!');
        }
    } catch (error) {
        console.log('⚠️ ADMIN USER CREATION ERROR:', error.message);
    }
}

// ============ SESSION STORE ============
const sessionStore = MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 24 * 60 * 60,
    autoRemove: 'native',
    touchAfter: 24 * 3600
});

// ============ MIDDLEWARE ============

// HELMET - ULTRA SECURE HEADERS
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"]
        }
    },
    hsts: { 
        maxAge: 31536000, 
        includeSubDomains: true, 
        preload: true 
    },
    noSniff: true,
    referrerPolicy: { 
        policy: 'same-origin' 
    },
    frameguard: { 
        action: 'deny' 
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { 
        policy: 'same-origin' 
    },
    crossOriginResourcePolicy: { 
        policy: 'same-origin' 
    },
    dnsPrefetchControl: { 
        allow: false 
    },
    expectCt: {
        maxAge: 86400,
        enforce: true
    }
}));

// Security Headers
app.use(securityHeaders);

// Body Parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Data Sanitization
app.use(sanitizeInput);
app.use(xssProtection);

// Static Files
app.use('/static', express.static(path.join(__dirname, '../public')));

// Global Rate Limiter
app.use(globalLimiter);

// ============ SESSION ============
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback_secret_change_this',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000,
        path: '/'
    },
    name: '__Secure-zx-session',
    rolling: true
}));

// ============ CSRF ============
app.use((req, res, next) => {
    if (!req.session.token) {
        req.session.token = crypto.randomBytes(64).toString('hex');
    }
    res.locals.csrfToken = req.session.token;
    req.csrfToken = () => req.session.token;
    next();
});

app.use((req, res, next) => {
    if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE') {
        const token = req.body._csrf || req.headers['x-csrf-token'];
        if (!token || token !== req.session.token) {
            console.log('⚠️ CSRF MISMATCH - REJECTED');
            return res.status(403).send('CSRF TOKEN INVALID');
        }
    }
    next();
});

// ============ VERIFY SESSION ============
app.use(verifySession);

// ============ VIEW ENGINE ============
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ============ ROUTES ============

// ROOT - REDIRECT TO LOGIN
app.get('/', (req, res) => {
    res.redirect('/login');
});

// LOGIN PAGE
app.get('/login', (req, res) => {
    if (req.session && req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.render('login', { 
        csrfToken: req.csrfToken(), 
        error: null 
    });
});

// LOGIN POST - WITH AUTH LIMITER
app.post('/login', authLimiter, async (req, res) => {
    const { deviceId, password } = req.body;
    
    if (!deviceId || !password) {
        return res.render('login', { 
            csrfToken: req.csrfToken(), 
            error: 'ALL FIELDS REQUIRED' 
        });
    }
    
    try {
        // Find user with password
        let user = await User.findOne({ deviceId }).select('+passwordHash');
        
        if (!user) {
            // Check if access key exists
            const keyExists = await User.findOne({ deviceId: password });
            if (!keyExists) {
                return res.render('login', { 
                    csrfToken: req.csrfToken(), 
                    error: 'INVALID CREDENTIALS' 
                });
            }
            
            // Create new user
            const hashedPassword = await bcrypt.hash(password, 12);
            user = new User({
                deviceId: deviceId,
                passwordHash: hashedPassword,
                role: 'user',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent']
            });
            await user.save();
            console.log(`✅ NEW USER REGISTERED: ${deviceId}`);
        }
        
        if (!user.isActive) {
            return res.render('login', { 
                csrfToken: req.csrfToken(), 
                error: 'ACCOUNT DISABLED' 
            });
        }
        
        if (user.lockUntil && user.lockUntil > Date.now()) {
            const remaining = Math.ceil((user.lockUntil - Date.now()) / 60000);
            return res.render('login', { 
                csrfToken: req.csrfToken(), 
                error: `ACCOUNT LOCKED. TRY IN ${remaining} MINUTES` 
            });
        }
        
        const isValid = await bcrypt.compare(password, user.passwordHash);
        if (!isValid) {
            user.loginAttempts += 1;
            if (user.loginAttempts >= 5) {
                user.lockUntil = Date.now() + 15 * 60 * 1000;
                await user.save();
                return res.render('login', { 
                    csrfToken: req.csrfToken(), 
                    error: 'TOO MANY ATTEMPTS. LOCKED 15 MINUTES' 
                });
            }
            await user.save();
            return res.render('login', { 
                csrfToken: req.csrfToken(), 
                error: 'INVALID CREDENTIALS' 
            });
        }
        
        user.loginAttempts = 0;
        user.lockUntil = null;
        user.lastLogin = new Date();
        user.ipAddress = req.ip;
        user.userAgent = req.headers['user-agent'];
        await user.save();
        
        req.session.userId = user._id;
        req.session.role = user.role;
        req.session.deviceId = user.deviceId;
        
        console.log(`✅ USER LOGGED IN: ${deviceId} (${user.role})`);
        
        if (user.role === 'admin') {
            return res.redirect('/admin');
        }
        res.redirect('/dashboard');
        
    } catch (error) {
        console.error('LOGIN ERROR:', error);
        res.render('login', { 
            csrfToken: req.csrfToken(), 
            error: 'SERVER ERROR. TRY AGAIN.' 
        });
    }
});

// DASHBOARD - SECURE, AUTH REQUIRED
app.get('/dashboard', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            req.session.destroy();
            return res.redirect('/login');
        }
        res.render('dashboard', { 
            deviceId: user.deviceId,
            role: user.role,
            csrfToken: req.csrfToken()
        });
    } catch (error) {
        console.error('DASHBOARD ERROR:', error);
        res.redirect('/login');
    }
});

// ADMIN PANEL - ADMIN ONLY
app.get('/admin', adminLimiter, requireAdmin, async (req, res) => {
    try {
        const users = await User.find({}).select('-passwordHash').sort({ createdAt: -1 });
        res.render('admin', { 
            users: users,
            csrfToken: req.csrfToken(),
            adminDeviceId: req.session.deviceId
        });
    } catch (error) {
        console.error('ADMIN ERROR:', error);
        res.render('admin', { 
            users: [], 
            csrfToken: req.csrfToken(),
            adminDeviceId: req.session.deviceId
        });
    }
});

// ADMIN: TOGGLE USER
app.post('/admin/user/:id/toggle', adminLimiter, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (user && user.deviceId !== 'ZENOX-ADMIN-001') {
            user.isActive = !user.isActive;
            await user.save();
            console.log(`✅ USER ${user.deviceId} ${user.isActive ? 'ENABLED' : 'DISABLED'}`);
        }
        res.redirect('/admin');
    } catch (error) {
        console.error('TOGGLE ERROR:', error);
        res.redirect('/admin');
    }
});

// ADMIN: DELETE USER
app.post('/admin/user/:id/delete', adminLimiter, requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (user && user.deviceId !== 'ZENOX-ADMIN-001') {
            await user.deleteOne();
            console.log(`✅ USER DELETED: ${user.deviceId}`);
        }
        res.redirect('/admin');
    } catch (error) {
        console.error('DELETE ERROR:', error);
        res.redirect('/admin');
    }
});

// LOGOUT
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('LOGOUT ERROR:', err);
        }
        res.redirect('/login');
    });
});

// HEALTH CHECK
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// ============ ERROR HANDLING ============
app.use((err, req, res, next) => {
    console.error('SERVER ERROR:', err);
    res.status(500).send('SOMETHING WENT WRONG. PLEASE TRY AGAIN LATER.');
});

// ============ 404 HANDLER ============
app.use((req, res) => {
    res.status(404).send('PAGE NOT FOUND');
});

// ============ START SERVER ============
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️ ZENOX-ULTRA-SECURE RUNNING ON PORT ${PORT}`);
    console.log(`🔐 https://zenox-ultra-secure.onrender.com`);
    console.log(`📱 HEALTH: https://zenox-ultra-secure.onrender.com/health`);
    console.log('🔒 ALL SECURITY MEASURES ACTIVE:');
    console.log('   ✅ HTTP-ONLY COOKIES');
    console.log('   ✅ CSRF PROTECTION');
    console.log('   ✅ RATE LIMITING');
    console.log('   ✅ XSS PROTECTION');
    console.log('   ✅ MONGODB INJECTION PROTECTION');
    console.log('   ✅ SERVER-SIDE RENDERING');
    console.log('   ✅ ADMIN-ONLY ROUTES');
});

// ============ GRACEFUL SHUTDOWN ============
process.on('SIGTERM', async () => {
    console.log('SIGTERM RECEIVED. SHUTTING DOWN GRACEFULLY...');
    await mongoose.disconnect();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('SIGINT RECEIVED. SHUTTING DOWN GRACEFULLY...');
    await mongoose.disconnect();
    process.exit(0);
});
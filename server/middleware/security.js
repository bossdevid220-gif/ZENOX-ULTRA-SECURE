const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss');

// ============ RATE LIMITING ============

// Global Rate Limiter
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'TOO MANY REQUESTS. PLEASE TRY AGAIN LATER.',
    standardHeaders: true,
    legacyHeaders: false
});

// Auth Rate Limiter - 5 attempts only
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'TOO MANY ATTEMPTS. ACCOUNT LOCKED FOR 15 MINUTES.',
    standardHeaders: true,
    legacyHeaders: false
});

// Admin Rate Limiter
const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: 'TOO MANY ADMIN REQUESTS. PLEASE SLOW DOWN.',
    standardHeaders: true,
    legacyHeaders: false
});

// ============ DATA SANITIZATION ============

// MongoDB Injection Protection
const sanitizeInput = mongoSanitize();

// XSS Protection
const xssProtection = (req, res, next) => {
    if (req.body) {
        for (let key in req.body) {
            if (typeof req.body[key] === 'string') {
                req.body[key] = xss(req.body[key]);
            }
        }
    }
    next();
};

// ============ SECURITY HEADERS ============

const securityHeaders = (req, res, next) => {
    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    // Referrer policy
    res.setHeader('Referrer-Policy', 'same-origin');
    // Permissions policy
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    next();
};

module.exports = {
    globalLimiter,
    authLimiter,
    adminLimiter,
    sanitizeInput,
    xssProtection,
    securityHeaders
};

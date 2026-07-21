const User = require('../models/User');

// ============ AUTH MIDDLEWARE ============

// Require Authentication - Every Route
const requireAuth = (req, res, next) => {
    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }
    next();
};

// Require Admin - Only Admin Users
const requireAdmin = async (req, res, next) => {
    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }
    
    try {
        const user = await User.findById(req.session.userId);
        if (!user || user.role !== 'admin') {
            return res.status(403).send('⛔ ACCESS DENIED');
        }
        next();
    } catch (error) {
        return res.status(500).send('SERVER ERROR');
    }
};

// Verify Session - Check if session is valid
const verifySession = async (req, res, next) => {
    if (req.session && req.session.userId) {
        try {
            const user = await User.findById(req.session.userId);
            if (!user || !user.isActive) {
                req.session.destroy();
                return res.redirect('/login');
            }
            req.user = user;
        } catch (error) {
            req.session.destroy();
            return res.redirect('/login');
        }
    }
    next();
};

module.exports = { requireAuth, requireAdmin, verifySession };

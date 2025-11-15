// ========================================
// EduVault Backend Server
// Node.js + Express + MongoDB
// ========================================

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'eduvault_secret_key_2025';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/eduvault';

// ========================================
// Middleware Configuration
// ========================================
app.use(cors({
    origin: '*',
    credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'eduvault_session_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to true in production with HTTPS
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// ========================================
// MongoDB Connection
// ========================================
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// ========================================
// Database Schemas
// ========================================

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    fullName: { type: String, required: true },
    userType: { 
        type: String, 
        enum: ['student', 'institution', 'employer', 'government'], 
        required: true 
    },
    phone: { type: String },
    institutionName: { type: String },
    apaarId: { type: String, unique: true, sparse: true },
    isVerified: { type: Boolean, default: false },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date },
    profileImage: { type: String },
    address: {
        street: String,
        city: String,
        state: String,
        pincode: String,
        country: { type: String, default: 'India' }
    }
});

// Student Activity Schema
const activitySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    activityType: { 
        type: String, 
        enum: ['academic', 'co-curricular', 'extracurricular', 'internship', 'research', 'certification'],
        required: true 
    },
    title: { type: String, required: true },
    description: { type: String },
    institutionName: { type: String },
    startDate: { type: Date },
    endDate: { type: Date },
    credits: { type: Number, default: 0 },
    grade: { type: String },
    documents: [{ 
        fileName: String, 
        fileUrl: String, 
        uploadDate: { type: Date, default: Date.now } 
    }],
    isVerified: { type: Boolean, default: false },
    verifiedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    verifiedAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

// Verification Request Schema
const verificationSchema = new mongoose.Schema({
    requesterId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    activityId: { type: mongoose.Schema.Types.ObjectId, ref: 'Activity' },
    requestType: { 
        type: String, 
        enum: ['credential', 'activity', 'complete_record'],
        required: true 
    },
    status: { 
        type: String, 
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending' 
    },
    purpose: { type: String },
    createdAt: { type: Date, default: Date.now },
    processedAt: { type: Date }
});

// Create Models
const User = mongoose.model('User', userSchema);
const Activity = mongoose.model('Activity', activitySchema);
const VerificationRequest = mongoose.model('VerificationRequest', verificationSchema);

// ========================================
// Authentication Middleware
// ========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'Access token required' 
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                message: 'Invalid or expired token' 
            });
        }
        req.user = user;
        next();
    });
};

// Role-based authorization middleware
const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.userType)) {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied: Insufficient permissions' 
            });
        }
        next();
    };
};

// ========================================
// API Routes - Authentication
// ========================================

// User Registration
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, fullName, userType, phone, institutionName } = req.body;

        // Validation
        if (!username || !email || !password || !fullName || !userType) {
            return res.status(400).json({ 
                success: false, 
                message: 'All required fields must be provided' 
            });
        }

        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid email format' 
            });
        }

        // Password strength validation
        if (password.length < 8) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password must be at least 8 characters long' 
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ 
            $or: [{ email }, { username }] 
        });

        if (existingUser) {
            return res.status(409).json({ 
                success: false, 
                message: 'User with this email or username already exists' 
            });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Generate APAAR ID for students
        let apaarId = null;
        if (userType === 'student') {
            apaarId = `APAAR${Date.now()}${Math.floor(Math.random() * 10000)}`;
        }

        // Create new user
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            fullName,
            userType,
            phone,
            institutionName,
            apaarId
        });

        await newUser.save();

        res.status(201).json({ 
            success: true, 
            message: 'User registered successfully',
            data: {
                userId: newUser._id,
                username: newUser.username,
                email: newUser.email,
                userType: newUser.userType,
                apaarId: newUser.apaarId
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during registration',
            error: error.message 
        });
    }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password, rememberMe } = req.body;

        // Validation
        if (!username || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Username and password are required' 
            });
        }

        // Find user by username or email
        const user = await User.findOne({
            $or: [{ username }, { email: username }]
        });

        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }

        // Check if account is active
        if (!user.isActive) {
            return res.status(403).json({ 
                success: false, 
                message: 'Account has been deactivated. Please contact support.' 
            });
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Generate JWT token
        const tokenExpiry = rememberMe ? '30d' : '24h';
        const token = jwt.sign(
            { 
                userId: user._id, 
                username: user.username, 
                userType: user.userType 
            },
            JWT_SECRET,
            { expiresIn: tokenExpiry }
        );

        // Set session
        req.session.userId = user._id;
        req.session.userType = user.userType;

        res.json({ 
            success: true, 
            message: 'Login successful',
            data: {
                token,
                user: {
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    fullName: user.fullName,
                    userType: user.userType,
                    apaarId: user.apaarId,
                    profileImage: user.profileImage
                }
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during login',
            error: error.message 
        });
    }
});

// Logout
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ 
                success: false, 
                message: 'Error during logout' 
            });
        }
        res.json({ 
            success: true, 
            message: 'Logged out successfully' 
        });
    });
});

// Forgot Password
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            // Don't reveal if user exists for security
            return res.json({ 
                success: true, 
                message: 'If the email exists, a password reset link has been sent' 
            });
        }

        // Generate reset token (in production, send email with link)
        const resetToken = jwt.sign(
            { userId: user._id },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        // In production, send email here
        // For now, return token (remove in production)
        res.json({ 
            success: true, 
            message: 'Password reset token generated',
            resetToken // Remove this in production
        });

    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Reset Password
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { resetToken, newPassword } = req.body;

        // Verify reset token
        const decoded = jwt.verify(resetToken, JWT_SECRET);
        const user = await User.findById(decoded.userId);

        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();

        res.json({ 
            success: true, 
            message: 'Password reset successfully' 
        });

    } catch (error) {
        res.status(400).json({ 
            success: false, 
            message: 'Invalid or expired reset token' 
        });
    }
});

// ========================================
// API Routes - User Profile
// ========================================

// Get User Profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        res.json({ 
            success: true, 
            data: user 
        });

    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Update User Profile
app.put('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const updates = req.body;
        delete updates.password; // Don't allow password update through this endpoint
        delete updates.email; // Don't allow email update without verification

        const user = await User.findByIdAndUpdate(
            req.user.userId,
            { $set: updates },
            { new: true, runValidators: true }
        ).select('-password');

        res.json({ 
            success: true, 
            message: 'Profile updated successfully',
            data: user 
        });

    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// ========================================
// API Routes - Activities
// ========================================

// Add Activity
app.post('/api/activities', authenticateToken, async (req, res) => {
    try {
        const activityData = {
            ...req.body,
            userId: req.user.userId
        };

        const activity = new Activity(activityData);
        await activity.save();

        res.status(201).json({ 
            success: true, 
            message: 'Activity added successfully',
            data: activity 
        });

    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Get User Activities
app.get('/api/activities', authenticateToken, async (req, res) => {
    try {
        const { activityType, isVerified } = req.query;
        const filter = { userId: req.user.userId };

        if (activityType) filter.activityType = activityType;
        if (isVerified !== undefined) filter.isVerified = isVerified === 'true';

        const activities = await Activity.find(filter).sort({ createdAt: -1 });

        res.json({ 
            success: true, 
            data: activities 
        });

    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Get Activity by ID
app.get('/api/activities/:id', authenticateToken, async (req, res) => {
    try {
        const activity = await Activity.findOne({
            _id: req.params.id,
            userId: req.user.userId
        });

        if (!activity) {
            return res.status(404).json({ 
                success: false, 
                message: 'Activity not found' 
            });
        }

        res.json({ 
            success: true, 
            data: activity 
        });

    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Update Activity
app.put('/api/activities/:id', authenticateToken, async (req, res) => {
    try {
        const activity = await Activity.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.userId },
            { $set: req.body },
            { new: true, runValidators: true }
        );

        if (!activity) {
            return res.status(404).json({ 
                success: false, 
                message: 'Activity not found' 
            });
        }

        res.json({ 
            success: true, 
            message: 'Activity updated successfully',
            data: activity 
        });

    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Delete Activity
app.delete('/api/activities/:id', authenticateToken, async (req, res) => {
    try {
        const activity = await Activity.findOneAndDelete({
            _id: req.params.id,
            userId: req.user.userId
        });

        if (!activity) {
            return res.status(404).json({ 
                success: false, 
                message: 'Activity not found' 
            });
        }

        res.json({ 
            success: true, 
            message: 'Activity deleted successfully' 
        });

    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// ========================================
// API Routes - Verification
// ========================================

// Request Verification
app.post('/api/verification/request', authenticateToken, async (req, res) => {
    try {
        const verificationRequest = new VerificationRequest({
            requesterId: req.user.userId,
            ...req.body
        });

        await verificationRequest.save();

        res.status(201).json({ 
            success: true, 
            message: 'Verification request submitted',
            data: verificationRequest 
        });

    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// Get Verification Requests (for institutions)
app.get('/api/verification/requests', 
    authenticateToken, 
    authorize('institution', 'government'), 
    async (req, res) => {
        try {
            const requests = await VerificationRequest.find({ status: 'pending' })
                .populate('requesterId', 'fullName email userType')
                .populate('targetUserId', 'fullName email apaarId')
                .sort({ createdAt: -1 });

            res.json({ 
                success: true, 
                data: requests 
            });

        } catch (error) {
            res.status(500).json({ 
                success: false, 
                message: 'Server error',
                error: error.message 
            });
        }
});

// Process Verification Request
app.put('/api/verification/process/:id', 
    authenticateToken, 
    authorize('institution', 'government'), 
    async (req, res) => {
        try {
            const { status } = req.body;

            const request = await VerificationRequest.findByIdAndUpdate(
                req.params.id,
                { 
                    status, 
                    processedAt: new Date() 
                },
                { new: true }
            );

            if (!request) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Verification request not found' 
                });
            }

            // If approved, update activity verification status
            if (status === 'approved' && request.activityId) {
                await Activity.findByIdAndUpdate(request.activityId, {
                    isVerified: true,
                    verifiedBy: req.user.userId,
                    verifiedAt: new Date()
                });
            }

            res.json({ 
                success: true, 
                message: 'Verification request processed',
                data: request 
            });

        } catch (error) {
            res.status(500).json({ 
                success: false, 
                message: 'Server error',
                error: error.message 
            });
        }
});

// ========================================
// API Routes - Statistics
// ========================================

// Get Dashboard Statistics
app.get('/api/statistics/dashboard', authenticateToken, async (req, res) => {
    try {
        let stats = {};

        if (req.user.userType === 'student') {
            const totalActivities = await Activity.countDocuments({ userId: req.user.userId });
            const verifiedActivities = await Activity.countDocuments({ 
                userId: req.user.userId, 
                isVerified: true 
            });
            const totalCredits = await Activity.aggregate([
                { $match: { userId: mongoose.Types.ObjectId(req.user.userId) } },
                { $group: { _id: null, total: { $sum: '$credits' } } }
            ]);

            stats = {
                totalActivities,
                verifiedActivities,
                totalCredits: totalCredits[0]?.total || 0,
                verificationRate: totalActivities > 0 
                    ? ((verifiedActivities / totalActivities) * 100).toFixed(1) 
                    : 0
            };

        } else if (req.user.userType === 'institution') {
            const totalStudents = await User.countDocuments({ 
                userType: 'student', 
                institutionName: req.user.institutionName 
            });
            const totalActivities = await Activity.countDocuments({});
            const pendingVerifications = await VerificationRequest.countDocuments({ 
                status: 'pending' 
            });

            stats = {
                totalStudents,
                totalActivities,
                pendingVerifications
            };
        }

        res.json({ 
            success: true, 
            data: stats 
        });

    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// ========================================
// API Routes - Search
// ========================================

// Search Users
app.get('/api/search/users', authenticateToken, async (req, res) => {
    try {
        const { query, userType } = req.query;

        const filter = {};
        if (query) {
            filter.$or = [
                { fullName: { $regex: query, $options: 'i' } },
                { username: { $regex: query, $options: 'i' } },
                { email: { $regex: query, $options: 'i' } }
            ];
        }
        if (userType) {
            filter.userType = userType;
        }

        const users = await User.find(filter)
            .select('username fullName email userType institutionName apaarId')
            .limit(20);

        res.json({ 
            success: true, 
            data: users 
        });

    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});

// ========================================
// Serve Frontend
// ========================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'EduVault.html'));
});

// ========================================
// Error Handling Middleware
// ========================================
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ 
        success: false, 
        message: 'Something went wrong!',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// ========================================
// Start Server
// ========================================
app.listen(PORT, () => {
    console.log(`🚀 EduVault Server running on http://localhost:${PORT}`);
    console.log(`📚 API Documentation available at http://localhost:${PORT}/api/docs`);
});

module.exports = app;

import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import dotenv from 'dotenv';
import crypto from 'crypto';
// import Razorpay from 'razorpay';
import { z } from 'zod';
import webpush from 'web-push';
import nodemailer from 'nodemailer';
import { Storage } from '@google-cloud/storage';
import multer from 'multer';

// Load environment variables from .env file
dotenv.config();

// Check for essential environment variables at startup
if (!process.env.JWT_SECRET) {
  console.error('FATAL ERROR: JWT_SECRET is not defined in .env file.');
  process.exit(1); // Exit the process with an error code
}

// Assuming you have moved otp.js to backend/models/
import OTP from './models/otp.js'; 

const app = express();
const PORT = process.env.PORT || 3003;

// Trust the first proxy in front of the app (e.g., on Render, Heroku)
// This is required for express-rate-limit to work correctly.
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  // 1. Configure a strong Content Security Policy (CSP)
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://connect.facebook.net"],
      styleSrc: ["'self'", "'unsafe-inline'"], // 'unsafe-inline' is often needed for CSS-in-JS
      imgSrc: ["'self'", "data:", "https:", "https://storage.googleapis.com"],
      connectSrc: [
        "'self'",
        process.env.FRONTEND_URL,
        "https://Yash Agency.in",
        "https://storage.googleapis.com"
      ],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'self'"], // Allow Razorpay's iframe
      frameAncestors: ["'self'"], // Mitigates clickjacking
      requireTrustedTypesFor: ["'script'"], // Mitigate DOM-based XSS with Trusted Types
      upgradeInsecureRequests: [],
    },
  },
  // 2. Set a strong HSTS policy: 2 years, include subdomains, preload
  strictTransportSecurity: {
    maxAge: 63072000,
    includeSubDomains: true,
    preload: true,
  },
  // 3. Isolate the origin
  crossOriginOpenerPolicy: { policy: "same-origin" },
}));

const whitelist = [
  'http://localhost:3000',
  'http://localhost:3003',
  'http://localhost:5173', // Add this for Vite's default dev server
  process.env.FRONTEND_URL,
  'https://yashagencydev.netlify.app'

];

const corsOptions = {
  origin: process.env.NODE_ENV === 'development' ? '*' : whitelist.filter(Boolean),
  credentials: true,
};
app.use(cors(corsOptions));

// Rate limiting (relaxed for better user experience)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // increased limit
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Relaxed rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50, // increased from 5 to 50
  message: 'Too many authentication attempts, please try again later.'
});

app.use(express.json({ limit: '10mb' }));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/yashdb', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Razorpay instance
// const razorpay = new Razorpay({
//   key_id: process.env.RAZORPAY_KEY_ID,
//   key_secret: process.env.RAZORPAY_KEY_SECRET,
// });

// VAPID keys for web-push
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(
    'mailto:yashagency25@gmail.com',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );
} else {
  console.warn('VAPID keys are missing. Web push notifications will be disabled.');
}

// --- Centralized Nodemailer Transporter ---
// Create a single, reusable transporter instance.
const emailTransporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: parseInt(process.env.EMAIL_PORT || '587', 10),
  secure: process.env.EMAIL_SECURE === 'true', // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
});

// GCS Configuration
const storage = new Storage({
  keyFilename: process.env.GCS_KEYFILE_PATH,
});
const bucket = storage.bucket(process.env.GCS_BUCKET);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
});

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Schemas
const cartItemSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  quantity: { type: Number, required: true, min: 1, default: 1 }
}, { _id: false });

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true, minlength: 6 },
  phone: { type: String, trim: true },

  wishlist: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
  cart: { type: [cartItemSchema], default: [] },

  pushSubscriptions: [{
    endpoint: String,
    keys: {
      p256dh: String,
      auth: String
    }
  }],

  addresses: [{
    name: { type: String },
    mobileNumber: { type: String },
    alternateMobileNumber: { type: String },
    addressType: { type: String, enum: ['home', 'work'], default: 'home' },
    street: { type: String, required: true },
    city: { type: String, required: true },
    state: { type: String },
    zipCode: { type: String },
    country: { type: String, default: 'India' },
    createdAt: { type: Date, default: Date.now }
  }],

  createdAt: { type: Date, default: Date.now },

  passwordResetToken: String,
  passwordResetExpires: Date,

  isEmailVerified: { type: Boolean, default: false },

  role: { type: String, enum: ['user', 'customer', 'salesman', 'admin'], default: 'customer' },

  // Salesman specific fields
  isActive: { type: Boolean, default: true },
  maxDiscountPercent: { type: Number },
  createdByAdmin: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  salesmanAddress: { type: String },
  salesmanPincode: { type: String },

  // 🔥 Added for secure session management
  sessionVersion: { type: Number, default: 0 },
  activeSessions: { type: [String], default: [] }
});

// Hash password if modified
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

const User = mongoose.model('User', userSchema);

// Product Schema
const productSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  description: { type: String, required: true },
  price: { type: Number, required: true, min: 0 },
  minSellPrice: { type: Number, default: 0 }, // Added for price protection
  originalPrice: { type: Number },
  discountPercentage: { type: Number, default: 0, min: 0, max: 100 },
  imageUrl: { type: String, required: true },
  images: [{ type: String }],
  category: { type: String, required: true },
  soldBy: { type: String, trim: true }, // To store the wholesaler/seller name
  stock: { type: Number, default: 0, min: 0 },
  variants: [{
    size: String,
    color: String,
    stock: { type: Number, default: 0, min: 0 },
    sku: String
  }],
  highlights: [{ type: String }],
  specifications: [{
    key: { type: String, required: true },
    value: { type: String, required: true }
  }],
  warranty: { type: String },
  showHighlights: { type: Boolean, default: false },
  showSpecifications: { type: Boolean, default: false },
  showWarranty: { type: Boolean, default: false },
  enabled: { type: Boolean, default: true },
  ratings: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    rating: { type: Number, min: 1, max: 5 },
    review: String,
    createdAt: { type: Date, default: Date.now }
  }],
  averageRating: { type: Number, default: 0 },
  totalRatings: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const Product = mongoose.model('Product', productSchema);

// Order Schema
const orderSchema = new mongoose.Schema({
  orderNumber: { type: String, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    name: String,
    price: Number,
    quantity: Number,
    selectedVariant: {
      size: String,
      color: String,
      stock: Number
    }
  }],
  total: { type: Number, required: true },
  status: { type: String, default: 'pending', enum: ['pending', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'] },
  shippingAddress: {
    name: String,
    mobileNumber: String,
    alternateMobileNumber: String,
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  paymentMethod: { type: String, default: 'cod', enum: ['cod'] },
  paymentStatus: { type: String, enum: ['pending', 'received'], default: 'pending' },
  courierDetails: {
    courierName: String,
    trackingNumber: String,
    estimatedDelivery: Date,
    shippedAt: Date
  },
  statusHistory: [{
    status: String,
    updatedAt: { type: Date, default: Date.now },
    updatedBy: String,
    notes: String
  }],
  // paymentDetails: {
  //   razorpay_payment_id: String,
  //   razorpay_order_id: String,
  //   razorpay_signature: String,
  // },
  couponCode: String,
  discount: { type: Number, default: 0 },
  shippingCost: { type: Number, default: 0 },
  tax: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  refundDetailsSubmitted: { type: Boolean, default: false }, // New field

  // Salesman fields
  orderSource: { type: String, default: 'website', enum: ['website', 'salesman'] },
  orderBy: { type: String, default: 'self', enum: ['self', 'salesman'] },
  salesmanId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  salesmanName: String
});

// Counter Schema for order numbers
const counterSchema = new mongoose.Schema({
  date: { type: String, required: true, unique: true },
  count: { type: Number, default: 0 }
});

const Counter = mongoose.model('Counter', counterSchema);

const Order = mongoose.model('Order', orderSchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  message: { type: String, required: true },
  link: { type: String }, // e.g., /track/orderId
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  deleted: { type: Boolean, default: false, index: true } // Add this line for soft deletes
});
const Notification = mongoose.model('Notification', notificationSchema);

// Pincode Schema for Delivery Areas
const pincodeSchema = new mongoose.Schema({
  officeName: { type: String, required: true },
  pincode: { type: Number, required: true, index: true },
  officeType: String,
  deliveryStatus: String,
  districtName: { type: String, required: true, index: true },
  stateName: { type: String, required: true, index: true },
  deliverable: { type: Boolean, default: false, index: true }
});

pincodeSchema.index({ pincode: 1, officeName: 1 }, { unique: true });

const Pincode = mongoose.model('Pincode', pincodeSchema);

// NEW: Schema for the pre-aggregated State-District map
const OTPSchema = new mongoose.Schema({
  email: { type: String, required: true, index: true },
  otp: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: '10m' } // OTP expires in 10 minutes
});
const stateDistrictMapSchema = new mongoose.Schema({
  stateName: { type: String, required: true, unique: true },
  districts: [{ type: String }]
});
const StateDistrictMap = mongoose.model('StateDistrictMap', stateDistrictMapSchema);

// SECURE JWT Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 🔥 1. Token MUST be login type (blocks reset-password tokens)
    if (decoded.type !== "login") {
      return res.status(401).json({ error: "Invalid token type" });
    }

    // 🔥 2. Validate user exists
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return res.status(401).json({ error: 'Invalid token user not found' });
    }

    // 🔥 3. Validate session (Support for multiple sessions)
    if (decoded.sessionId) {
      if (!user.activeSessions || !user.activeSessions.includes(decoded.sessionId)) {
        return res.status(401).json({ error: 'Session expired. Please login again.' });
      }
    } else if (decoded.sessionVersion !== user.sessionVersion) {
      return res.status(401).json({ error: 'Session expired. Please login again.' });
    }

    // Authenticated user stored in request
    req.user = user;
    req.sessionId = decoded.sessionId;
    next();

  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};


// // CSRF Protection
// const csrfTokens = new Map();

// const generateCSRFToken = () => {
//   return crypto.randomBytes(32).toString('hex');
// };

// const csrfProtection = (req, res, next) => {
//   if (req.method === 'GET') return next();
  
//   const token = req.headers['x-csrf-token'];
//   const sessionId = req.headers['authorization'];
  
//   if (!token || !csrfTokens.has(sessionId) || csrfTokens.get(sessionId) !== token) {
//     return res.status(403).json({ error: 'Invalid CSRF token' });
//   }
  
//   next();
// };

// // CSRF token endpoint (requires authentication)
// app.get('/api/csrf-token', authenticateToken, (req, res) => {
//   const token = generateCSRFToken();
//   const sessionId = req.headers['authorization'];
//   csrfTokens.set(sessionId, token);
//   res.json({ csrfToken: token });
// });

// Zod validation middleware
const validate = (schema) => (req, res, next) => {
  try {
    schema.parse({
      body: req.body,
      query: req.query,
      params: req.params,
    });
    next();
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        errors: error.errors.map((err) => ({
          msg: err.message,
          param: err.path.slice(1).join('.'), // e.g., body.email
          location: err.path[0], // e.g., body
        })),
      });
    }
    // Handle other unexpected errors
    res.status(500).json({ error: 'Internal server error' });
  }
};

// SECURE Admin middleware
const adminAuth = (req, res, next) => {
  // 1. Ensure authentication middleware has attached the user
  if (!req.user || !req.user.role) {
    return res.status(401).json({ error: 'User not authenticated' });
  }

  // 2. Strict role-based admin check
  const isAdmin = req.user.role === 'admin';

  // (Optional) backward compatibility using ADMIN_EMAIL
  const isAdminByEmail =
    process.env.ADMIN_EMAIL &&
    req.user.email &&
    req.user.email.toLowerCase() === process.env.ADMIN_EMAIL.toLowerCase();

  if (!isAdmin && !isAdminByEmail) {
    console.warn(`[Admin Auth] Access denied for user: ${req.user.email} (Role: ${req.user.role})`);
    return res.status(403).json({
      error: 'Admin access required'
    });
  }

  // 3. Allow admin access
  next();
};

// Salesman middleware
const salesmanAuth = (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  
  // Allow admin or salesman
  if (req.user.role === 'salesman' || req.user.role === 'admin') {
    if (req.user.role === 'salesman' && req.user.isActive === false) {
      return res.status(403).json({ error: 'Account disabled. Contact admin.' });
    }
    next();
  } else {
    return res.status(403).json({ error: 'Salesman access required' });
  }
};

const sendOrderStatusEmail = async (userEmail, userName, order) => {
  if (!process.env.EMAIL_HOST || !process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.error('Email service is not configured. Skipping order status email.');
    return;
  }

  let subject = '';
  let htmlBody = '';
  const orderLink = `${FRONTEND_URL}/track/${order._id}`;
  const status = order.status;

  switch (status) {
    case 'pending':
      const orderIdentifier = order.orderNumber || order._id.toString().slice(-8);
      subject = `✅ Order Confirmed: Your Yash Agency Order #${orderIdentifier} has been placed!`;
      const orderItemsHtml = order.items.map(item => `
        <tr>
          <td style="padding:10px; border-top:1px solid #ddd;">${item.name}</td>
          <td align="center" style="padding:10px; border-top:1px solid #ddd;">${item.quantity}</td>
          <td align="right" style="padding:10px; border-top:1px solid #ddd;">₹${(item.price * item.quantity).toFixed(2)}</td>
        </tr>
      `).join('');
      htmlBody = `
        <body style="margin:0; padding:0; background-color:#f7f7f7; font-family: Arial, sans-serif;">
          <table align="center" cellpadding="0" cellspacing="0" width="600" style="background-color:#ffffff; border-radius:8px; overflow:hidden; margin-top:40px; border: 1px solid #ddd;">
            <tr>
              <td style="background-color:#4CAF50; padding:20px; text-align:center; color:#ffffff; font-size:24px;">
                <strong>Order Confirmation</strong>
              </td>
            </tr>
            <tr>
              <td style="padding:30px;">
                <p style="font-size:18px; color:#333;">Hi ${userName},</p>
                <p style="font-size:16px; color:#555;">Thank you for shopping with us! We're happy to let you know that your order has been placed successfully.</p>
                <table cellpadding="10" cellspacing="0" width="100%" style="border-collapse:collapse; margin-top:20px;">
                  <tr><td style="background-color:#f2f2f2; font-weight:bold; width: 150px;">Order Number:</td><td>#${orderIdentifier}</td></tr>
                  <tr><td style="background-color:#f2f2f2; font-weight:bold;">Order Date:</td><td>${new Date(order.createdAt).toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' })}</td></tr>
                  <tr><td style="background-color:#f2f2f2; font-weight:bold;">Total Amount:</td><td>₹${order.total.toFixed(2)}</td></tr>
                </table>
                <h3 style="margin-top:30px; color:#333; border-bottom: 2px solid #eee; padding-bottom: 5px;">Order Details:</h3>
                <table cellpadding="10" cellspacing="0" width="100%" style="border-collapse:collapse;">
                  <tr style="background-color:#f2f2f2;"><th align="left">Product</th><th align="center">Quantity</th><th align="right">Price</th></tr>
                  ${orderItemsHtml}
                </table>
                <p style="font-size:16px; color:#555; margin-top:30px;">You can track your order status by clicking the button below:</p>
                <p style="text-align:center; margin-top:20px;">
                  <a href="${orderLink}" style="background-color:#4CAF50; color:#ffffff; text-decoration:none; padding:12px 24px; border-radius:5px; font-weight:bold; display: inline-block;">Track My Order</a>
                </p>
                <p style="font-size:14px; color:#888; margin-top:30px;">If you have any questions, reply to this email or contact our support team at <a href="mailto:support@Yash Agency.com" style="color:#4CAF50; text-decoration:none;">Yashagency25@gmail.com</a>.</p>
              </td>
            </tr>
            <tr>
              <td style="background-color:#f2f2f2; text-align:center; padding:15px; font-size:12px; color:#777;">
                © ${new Date().getFullYear()} Yash Agency. All rights reserved.
              </td>
            </tr>
          </table>
        </body>`;
      break;
    case 'shipped':
      const shippedOrderIdentifier = order.orderNumber || order._id.toString().slice(-8);
      subject = `🚚 Your Yash Agency Order #${shippedOrderIdentifier} has been shipped!`;
      htmlBody = `
        <body style="margin:0; padding:0; background-color:#f7f7f7; font-family: Arial, sans-serif;">
          <table align="center" cellpadding="0" cellspacing="0" width="600" style="background-color:#ffffff; border-radius:8px; overflow:hidden; margin-top:40px; border: 1px solid #ddd;">
            <tr>
              <td style="background-color:#FFC107; padding:20px; text-align:center; color:#ffffff; font-size:24px;">
                <strong>Order Shipped!</strong>
              </td>
            </tr>
            <tr>
              <td style="padding:30px;">
                <p style="font-size:18px; color:#333;">Hi ${userName},</p>
                <p style="font-size:16px; color:#555;">Great news! Your Yash Agency order #${shippedOrderIdentifier} has been shipped and is on its way to you.</p>
                <table cellpadding="10" cellspacing="0" width="100%" style="border-collapse:collapse; margin-top:20px;">
                  <tr><td style="background-color:#f2f2f2; font-weight:bold; width: 150px;">Order Number:</td><td>#${shippedOrderIdentifier}</td></tr>
                  <tr><td style="background-color:#f2f2f2; font-weight:bold;">Shipped Date:</td><td>${order.courierDetails?.shippedAt ? new Date(order.courierDetails.shippedAt).toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' }) : 'N/A'}</td></tr>
                  ${order.courierDetails?.courierName ? `<tr><td style="background-color:#f2f2f2; font-weight:bold;">Courier:</td><td>${order.courierDetails.courierName}</td></tr>` : ''}
                  ${order.courierDetails?.trackingNumber ? `<tr><td style="background-color:#f2f2f2; font-weight:bold;">Tracking Number:</td><td>${order.courierDetails.trackingNumber}</td></tr>` : ''}
                  ${order.courierDetails?.estimatedDelivery ? `<tr><td style="background-color:#f2f2f2; font-weight:bold;">Estimated Delivery:</td><td>${new Date(order.courierDetails.estimatedDelivery).toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' })}</td></tr>` : ''}
                </table>
                <p style="font-size:16px; color:#555; margin-top:30px;">You can track your order's journey by clicking the button below:</p>
                <p style="text-align:center; margin-top:20px;">
                  <a href="${orderLink}" style="background-color:#FFC107; color:#ffffff; text-decoration:none; padding:12px 24px; border-radius:5px; font-weight:bold; display: inline-block;">Track My Order</a>
                </p>
                <p style="font-size:14px; color:#888; margin-top:30px;">If you have any questions, reply to this email or contact our support team at <a href="mailto:support@Yash Agency.com" style="color:#4CAF50; text-decoration:none;">Yashagency25@gmail.com</a>.</p>
              </td>
            </tr>
            <tr>
              <td style="background-color:#f2f2f2; text-align:center; padding:15px; font-size:12px; color:#777;">
                © ${new Date().getFullYear()} Yash Agency. All rights reserved.
              </td>
            </tr>
          </table>
        </body>`;
      break;
    case 'delivered':
      const deliveredOrderIdentifier = order.orderNumber || order._id.toString().slice(-8);
      subject = `📦 Your Yash Agency Order #${deliveredOrderIdentifier} has been delivered!`;
      htmlBody = `
        <body style="margin:0; padding:0; background-color:#f7f7f7; font-family: Arial, sans-serif;">
          <table align="center" cellpadding="0" cellspacing="0" width="600" style="background-color:#ffffff; border-radius:8px; overflow:hidden; margin-top:40px; border: 1px solid #ddd;">
            <tr>
              <td style="background-color:#28A745; padding:20px; text-align:center; color:#ffffff; font-size:24px;">
                <strong>Order Delivered!</strong>
              </td>
            </tr>
            <tr>
              <td style="padding:30px;">
                <p style="font-size:18px; color:#333;">Hi ${userName},</p>
                <p style="font-size:16px; color:#555;">Great news! Your Yash Agency order #${deliveredOrderIdentifier} has been successfully delivered. We hope you enjoy your new products!</p>
                <table cellpadding="10" cellspacing="0" width="100%" style="border-collapse:collapse; margin-top:20px;">
                  <tr><td style="background-color:#f2f2f2; font-weight:bold; width: 150px;">Order Number:</td><td>#${deliveredOrderIdentifier}</td></tr>
                  <tr><td style="background-color:#f2f2f2; font-weight:bold;">Delivery Date:</td><td>${new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' })}</td></tr>
                  <tr><td style="background-color:#f2f2f2; font-weight:bold;">Total Amount:</td><td>₹${order.total.toFixed(2)}</td></tr>
                </table>
                <p style="font-size:16px; color:#555; margin-top:30px;">We'd love to hear your feedback! You can view your order details and rate your products by clicking the button below:</p>
                <p style="text-align:center; margin-top:20px;">
                  <a href="${orderLink}" style="background-color:#28A745; color:#ffffff; text-decoration:none; padding:12px 24px; border-radius:5px; font-weight:bold; display: inline-block;">View My Order</a>
                </p>
                <p style="font-size:14px; color:#888; margin-top:30px;">If you have any questions, reply to this email or contact our support team at <a href="mailto:support@Yash Agency.com" style="color:#4CAF50; text-decoration:none;">Yashagency25@gmail.com</a>.</p>
              </td>
            </tr>
            <tr>
              <td style="background-color:#f2f2f2; text-align:center; padding:15px; font-size:12px; color:#777;">
                © ${new Date().getFullYear()} Yash Agency. All rights reserved.
              </td>
            </tr>
          </table>
        </body>`;
      break;
    case 'cancelled':
      const cancelledOrderIdentifier = order.orderNumber || order._id.toString().slice(-8);
      subject = `❌ Your Yash Agency Order #${cancelledOrderIdentifier} has been cancelled.`;
      htmlBody = `
        <body style="margin:0; padding:0; background-color:#f7f7f7; font-family: Arial, sans-serif;">
          <table align="center" cellpadding="0" cellspacing="0" width="600" style="background-color:#ffffff; border-radius:8px; overflow:hidden; margin-top:40px; border: 1px solid #ddd;">
            <tr>
              <td style="background-color:#DC3545; padding:20px; text-align:center; color:#ffffff; font-size:24px;">
                <strong>Order Cancelled</strong>
              </td>
            </tr>
            <tr>
              <td style="padding:30px;">
                <p style="font-size:18px; color:#333;">Hi ${userName},</p>
                <p style="font-size:16px; color:#555;">Your Yash Agency order #${cancelledOrderIdentifier} has been successfully cancelled.</p>
                <p style="font-size:16px; color:#555;">If you paid for this order online, your refund will be processed and should reflect in your account within 5-7 business days. If you have any questions, please don't hesitate to contact our support team.</p>
                <table cellpadding="10" cellspacing="0" width="100%" style="border-collapse:collapse; margin-top:20px;">
                  <tr><td style="background-color:#f2f2f2; font-weight:bold; width: 150px;">Order Number:</td><td>#${cancelledOrderIdentifier}</td></tr>
                  <tr><td style="background-color:#f2f2f2; font-weight:bold;">Cancellation Date:</td><td>${new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' })}</td></tr>
                </table>
                <p style="text-align:center; margin-top:30px;">
                  <a href="${orderLink}" style="background-color:#6c757d; color:#ffffff; text-decoration:none; padding:12px 24px; border-radius:5px; font-weight:bold; display: inline-block;">View Order Details</a>
                </p>
                <p style="font-size:14px; color:#888; margin-top:30px;">We're sorry to see you go. We hope to see you again soon!</p>
              </td>
            </tr>
            <tr><td style="background-color:#f2f2f2; text-align:center; padding:15px; font-size:12px; color:#777;">© ${new Date().getFullYear()} Yash Agency. All rights reserved.</td></tr>
          </table>
        </body>`;
      break;
    default:
      // For other statuses like 'processing', 'refunded', etc.
      const defaultOrderIdentifier = order.orderNumber || order._id.toString().slice(-8);
      subject = `🔔 Order Update: Your Yash Agency Order #${defaultOrderIdentifier} is now ${status}.`;
      htmlBody = `
        <body style="margin:0; padding:0; background-color:#f7f7f7; font-family: Arial, sans-serif;">
          <table align="center" cellpadding="0" cellspacing="0" width="600" style="background-color:#ffffff; border-radius:8px; overflow:hidden; margin-top:40px; border: 1px solid #ddd;">
            <tr>
              <td style="background-color:#007BFF; padding:20px; text-align:center; color:#ffffff; font-size:24px;">
                <strong>Order Status Update</strong>
              </td>
            </tr>
            <tr>
              <td style="padding:30px;">
                <p style="font-size:18px; color:#333;">Hi ${userName},</p>
                <p style="font-size:16px; color:#555;">The status of your order #${defaultOrderIdentifier} has been updated to: <strong style="text-transform: capitalize;">${status}</strong>.</p>
                <p style="font-size:16px; color:#555; margin-top:20px;">You can view the latest details of your order by clicking the button below.</p>
                <p style="text-align:center; margin-top:20px;">
                  <a href="${orderLink}" style="background-color:#007BFF; color:#ffffff; text-decoration:none; padding:12px 24px; border-radius:5px; font-weight:bold; display: inline-block;">View Order Details</a>
                </p>
                <p style="font-size:14px; color:#888; margin-top:30px;">If you have any questions, reply to this email or contact our support team at <a href="mailto:Yashagency25@gmail.com" style="color:#4CAF50; text-decoration:none;">Yashagency25@gmail.com</a>.</p>
              </td>
            </tr>
            <tr>
              <td style="background-color:#f2f2f2; text-align:center; padding:15px; font-size:12px; color:#777;">
                © ${new Date().getFullYear()} Yash Agency. All rights reserved.
              </td>
            </tr>
          </table>
        </body>`;
      break;
  }

  try {
    await emailTransporter.sendMail({
      from: `"Yash Agency" <${process.env.EMAIL_USER}>`,
      to: userEmail,
      subject: subject,
      html: htmlBody,
    });
  } catch (error) {
    console.error(`Failed to send order status email to ${userEmail}:`, error);
  }
};

// API Routes

// Get all products
app.get('/api/products', async (req, res) => {
  try {

    // Prevent caching
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');

    const products = await Product.find({
      $or: [{ enabled: true }, { enabled: { $exists: false } }]
    }).sort({ createdAt: -1 });

    res.json(products);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id).populate('ratings.userId', 'name');
    if (!product || (product.enabled === false)) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

// Zod schema for the first step of user registration (details)
const registerDetailsSchema = z.object({
  body: z.object({
    name: z.string().trim().min(1, { message: 'Name is required' }),
    email: z.string().email({ message: 'Invalid email address' }),
    password: z.string().min(6, { message: 'Password must be at least 6 characters' }),
    phone: z.string().trim().min(10, { message: 'Phone number must be at least 10 digits' })
  })
});

// Zod schema for the second step of user registration (OTP verification)
const registerOtpSchema = z.object({
  body: z.object({
    email: z.string().email({ message: 'Invalid email address' }),
    otp: z.string().trim().length(6, { message: 'OTP must be 6 digits' })
  })
});

// User registration
app.post('/api/register', 
  // We will validate inside the handler based on the step
  async (req, res) => {
    try {
      const { name, email, password, phone, otp } = req.body;

      // 1. Verify OTP
      const otpRecord = await OTP.findOne({ email });
      if (!otpRecord) {
        return res.status(400).json({ error: 'OTP has expired or is invalid. Please request a new one.' });
      }

      // The user submits a plain OTP. We need to compare it with the hashed OTP in the database.
      // bcrypt.compare handles this securely.
      // The first argument is the plain text, the second is the hash.
      const isMatch = await bcrypt.compare(otp, otpRecord.otp); 

      if (!isMatch) {
        return res.status(400).json({ error: 'Invalid OTP. Please check the code and try again.' });
      }

      // OTP is correct, proceed with registration
      // Delete the OTP so it can't be used again
      await OTP.deleteOne({ email });
      
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
      }

      const user = new User({ name, email, password, phone, isEmailVerified: true }); // Mark as verified after OTP
      await user.save();

      const token = jwt.sign(
        { userId: user._id }, 
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.status(201).json({
        message: 'Account created successfully!',
        token,
        user: { id: user._id, name: user.name, email: user.email, phone: user.phone }
      });
    } catch (error) {
      console.error("Registration Error:", error); // Added for better debugging
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

// Endpoint to send OTP for registration
app.post('/api/send-otp', async (req, res) => {
  const { email, type } = req.body;
  
  if (!email || !type) {
    return res.status(400).json({ error: 'Email and type are required.' });
  }

  try {
    // For registration, check if user already exists
    if (type === 'register') {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({ error: 'An account with this email already exists.' });
      }
    } else if (type === 'change-email') {
      const existingUser = await User.findOne({ email });
      if (existingUser && existingUser._id.toString() !== req.user._id.toString()) { // Ensure it's not another user's email
        return res.status(409).json({ error: 'This email is already registered by another user.' });
      }
    }

    // Generate a 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    
    // Hash the OTP before saving
    const hashedOtp = await bcrypt.hash(otp, 10);

    // Save OTP to the database, replacing any existing one for that email
    await OTP.findOneAndUpdate({ email }, { otp: hashedOtp }, { upsert: true, new: true, setDefaultsOnInsert: true });

    // Send the plain text OTP via email
    const { sendOTPEmail } = await import('./utils/emailService.js');
    await sendOTPEmail(email, otp);

    res.status(200).json({ message: 'OTP sent successfully to your email.' });

  } catch (error) {
    console.error('Error sending OTP:', error);
    // Use a generic error message for security
    res.status(500).json({ error: 'An internal server error occurred while sending the OTP.' });
  }
});

// Zod schema for requesting email change
const requestEmailChangeSchema = z.object({
  body: z.object({
    newEmail: z.string().email({ message: 'Invalid email address' }),
  })
});

// Endpoint to request OTP for email change
app.post('/api/request-email-change', authenticateToken, validate(requestEmailChangeSchema), async (req, res) => {
  const { newEmail } = req.body;
  const userId = req.user._id;

  try {
    // Check if the new email is already registered by another user
    const existingUser = await User.findOne({ email: newEmail });
    if (existingUser && existingUser._id.toString() !== userId.toString()) {
      return res.status(409).json({ error: 'This email is already registered by another user.' });
    }

    // Generate a 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    const hashedOtp = await bcrypt.hash(otp, 10);

    // Store OTP for the new email (this will overwrite any existing OTP for this email)
    await OTP.findOneAndUpdate({ email: newEmail }, { otp: hashedOtp, createdAt: new Date() }, { upsert: true, new: true, setDefaultsOnInsert: true });

    // Send the OTP via email
    const { sendOTPEmail } = await import('./utils/emailService.js');
    await sendOTPEmail(newEmail, otp);

    res.status(200).json({ message: 'OTP sent to your new email address for verification.' });

  } catch (error) {
    console.error('Error requesting email change OTP:', error);
    res.status(500).json({ error: 'An internal server error occurred while sending the OTP.' });
  }
});

// Zod schema for verifying email change
const verifyEmailChangeSchema = z.object({
  body: z.object({
    newEmail: z.string().email({ message: 'Invalid email address' }),
    otp: z.string().trim().length(6, { message: 'OTP must be 6 digits' })
  })
});

// Endpoint to verify OTP and change email
app.post('/api/verify-email-change', authenticateToken, validate(verifyEmailChangeSchema), async (req, res) => {
  const { newEmail, otp } = req.body;
  const userId = req.user._id;

  try {
    const otpRecord = await OTP.findOne({ email: newEmail });
    if (!otpRecord) {
      return res.status(400).json({ error: 'OTP has expired or is invalid. Please request a new one.' });
    }

    const isMatch = await bcrypt.compare(otp, otpRecord.otp);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid OTP. Please check the code and try again.' });
    }

    // OTP is correct, update user's email and mark as verified
    const updatedUser = await User.findByIdAndUpdate(userId, { email: newEmail, isEmailVerified: true }, { new: true }).select('-password');
    await OTP.deleteOne({ email: newEmail }); // Delete the used OTP

    // Re-issue JWT token with updated user info
    const newToken = jwt.sign({ userId: updatedUser._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(200).json({ message: 'Email updated and verified successfully!', token: newToken, user: { id: updatedUser._id, name: updatedUser.name, email: updatedUser.email, phone: updatedUser.phone, isEmailVerified: updatedUser.isEmailVerified } });

  } catch (error) {
    console.error('Error verifying email change:', error);
    res.status(500).json({ error: 'An internal server error occurred.' });
  }
});

// Zod schema for user login
const loginSchema = z.object({
  body: z.object({
    email: z.string().email({ message: 'Invalid email address' }),
    password: z.string().min(1, { message: 'Password is required' })
  })
});

// User login (SECURE VERSION)
app.post('/api/login', validate(loginSchema), async (req, res) => {
  try {
    const { email, password } = req.body;

    // 🔒 If user already has a token in request header → force logout first
    const existingToken = req.headers['authorization'];
    if (existingToken) {
      return res.status(400).json({
        error: 'You are already logged in. Please logout first.'
      });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if salesman is active
    if (user.role === 'salesman' && user.isActive === false) {
      return res.status(403).json({ error: 'Account is disabled. Please contact admin.' });
    }

    // Manage Active Sessions (Limit to 3)
    const sessionId = crypto.randomBytes(16).toString('hex');
    if (!user.activeSessions) user.activeSessions = [];
    user.activeSessions.push(sessionId);
    if (user.activeSessions.length > 3) {
      user.activeSessions.shift(); // Remove oldest session
    }
    await user.save();

    // Generate secure login JWT
    const token = jwt.sign(
      { 
        userId: user._id,
        role: user.role,
        sessionId: sessionId,
        type: "login"   // prevents reset-token abuse
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Response
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        isEmailVerified: user.isEmailVerified,
        role: user.role
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post("/api/logout", authenticateToken, async (req, res) => {
  try {
    if (req.sessionId) {
      // Remove only the current session
      req.user.activeSessions = req.user.activeSessions.filter(id => id !== req.sessionId);
    } else {
      // Legacy: Increase sessionVersion to invalidate all tokens
      req.user.sessionVersion = (req.user.sessionVersion || 0) + 1;
    }
    await req.user.save();

    res.json({ message: "Logged out successfully" });

  } catch (error) {
    res.status(500).json({ error: "Logout failed" });
  }
});

// Add item to cart (for logged-in users)
app.post('/api/cart/add', authenticateToken, async (req, res) => {
  try {
    const { productId, quantity = 1 } = req.body;

    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const user = req.user;

    const existingItem = user.cart.find(item =>
      item.productId.toString() === productId
    );

    if (existingItem) {
      existingItem.quantity += Number(quantity);
    } else {
      user.cart.push({ productId, quantity: Number(quantity) });
    }

    await user.save();
    await user.populate('cart.productId');

    res.json({ message: 'Item added to cart', cart: user.cart });

  } catch (error) {
    res.status(500).json({ error: 'Failed to add item to cart' });
  }
});

// Get user orders
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .populate('items.productId');
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Get single order for tracking
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id).populate('items.productId');
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // Check if user owns the order
    if (order.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(order);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch order details' });
  }
});

// Zod schema for checkout
const checkoutSchema = z.object({
  body: z.object({
    items: z.array(z.any()).min(1, { message: 'Checkout must include at least one item' }),
    total: z.number().min(0, { message: 'Total must be a positive number' })
  })
});

// Checkout
app.post('/api/checkout', authenticateToken, validate(checkoutSchema),
  async (req, res) => {
    try {
      const { items, total, discount, shippingCost, tax } = req.body;

      // --- START: New Pincode Deliverability Check ---
      const shippingAddressForCheck = req.body.shippingAddress;
      if (!shippingAddressForCheck || !shippingAddressForCheck.zipCode) {
        return res.status(400).json({ error: 'Shipping address with a pincode is required.' });
      }

      const pincodeToCheck = shippingAddressForCheck.zipCode;
      const isDeliverable = await Pincode.findOne({ pincode: parseInt(pincodeToCheck, 10), deliverable: true });

      if (!isDeliverable) {
        return res.status(400).json({ 
          error: `Sorry, we do not currently deliver to your pincode ${pincodeToCheck}. Please change the address to proceed.` 
        });
      }
      // --- END: New Pincode Deliverability Check ---

      // Validate all products exist and calculate total
      let subtotal = 0;
      const orderItems = [];

      for (const item of items) {
        const product = await Product.findById(item._id);
        if (!product) {
          return res.status(404).json({ error: `Product ${item.name} not found` });
        }
        
        subtotal += product.price * item.quantity;
        orderItems.push({
          productId: product._id,
          name: product.name,
          price: product.price,
          quantity: item.quantity,
          selectedVariant: item.selectedVariant
        });
      }

      // Check Minimum Order Amount
      const settings = await Settings.findOne();
      if (settings && settings.minOrderAmount > 0 && subtotal < settings.minOrderAmount) {
        return res.status(400).json({ error: `Minimum order amount is ₹${settings.minOrderAmount}` });
      }

      // Recalculate the final total on the backend for security
      const calculatedTotal = subtotal + (shippingCost || 0) - (discount || 0) + (tax || 0);

      // Verify total matches
      if (Math.abs(calculatedTotal - total) > 0.01) {
        console.error(`Total mismatch: Frontend total: ${total}, Backend calculated: ${calculatedTotal}`);
        return res.status(400).json({ error: 'Total amount mismatch. Please try again.' });
      }

      // Generate order number
      const now = new Date();
      const dateStr = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}`;
      
      const counter = await Counter.findOneAndUpdate(
        { date: dateStr },
        { $inc: { count: 1 } },
        { upsert: true, new: true }
      );
      
      const orderNumber = `${dateStr}${String(counter.count).padStart(4, '0')}`;

      const order = new Order({
        orderNumber,
        userId: req.user._id,
        items: orderItems,
        total: total, // Use the verified total from the request
        orderBy: 'self',
        status: 'pending',
        shippingAddress: req.body.shippingAddress,
        paymentMethod: req.body.paymentMethod || 'cod',
        paymentStatus: req.body.paymentMethod !== 'cod' ? 'received' : 'pending',
        couponCode: req.body.couponCode,
        discount: req.body.discount || 0,
        shippingCost: req.body.shippingCost || 0,
        tax: req.body.tax || 0,
        // paymentDetails: {
        //   razorpay_payment_id: req.body.razorpay_payment_id,
        //   razorpay_order_id: req.body.razorpay_order_id,
        //   razorpay_signature: req.body.razorpay_signature,
        // }
      });

      await order.save();
      
      // Send order confirmation email
      if (req.user.email) {
        sendOrderStatusEmail(req.user.email, req.user.name, order);
        sendNewOrderAdminNotification(order); // Notify admin of the new order
      }

      // Update coupon usage if coupon was used
      if (req.body.couponCode && req.body.couponId) {
        await Coupon.findByIdAndUpdate(req.body.couponId, {
          $inc: { usageCount: 1 },
          $push: {
            usedBy: {
              userId: req.user._id,
              orderId: order._id,
              usedAt: new Date()
            }
          }
        });
      }

      res.json({ 
        message: 'Order placed successfully', 
        orderId: order._id,
        total: total
      });
    } catch (error) {
      res.status(500).json({ error: 'Checkout failed' });
    }
  }
);

// --- Admin New Order Notification ---
const sendNewOrderAdminNotification = async (order) => {
	const adminEmail = process.env.ADMIN_EMAIL || 'Yashagency25@gmail.com';
	const orderIdentifier = order.orderNumber || order._id.toString().slice(-8);
	const adminOrderLink = `${FRONTEND_URL}/admin/orders`;

	// --- Send Email Notification ---
	if (process.env.EMAIL_HOST && process.env.EMAIL_USER && process.env.EMAIL_PASS) {
		try {
			const subject = `📦 New Order Received: #${orderIdentifier}`;
			const customer = await User.findById(order.userId).select('name email phone');

			const orderItemsHtml = order.items.map(item => `
        <tr>
          <td style="padding:10px; border-top:1px solid #ddd;">${item.name}</td>
          <td align="center" style="padding:10px; border-top:1px solid #ddd;">${item.quantity}</td>
          <td align="right" style="padding:10px; border-top:1px solid #ddd;">₹${(item.price * item.quantity).toFixed(2)}</td>
        </tr>
      `).join('');

			const shippingAddressHtml = order.shippingAddress ? `
        <h3 style="margin-top:30px; color:#333; border-bottom: 2px solid #eee; padding-bottom: 5px;">Shipping Address:</h3>
        <div style="font-size:16px; color:#555; line-height:1.6;">
          <strong>${order.shippingAddress.name}</strong><br>
          ${order.shippingAddress.street}<br>
          ${order.shippingAddress.city}, ${order.shippingAddress.state} ${order.shippingAddress.zipCode}<br>
          ${order.shippingAddress.country || 'India'}<br>
          Phone: ${order.shippingAddress.mobileNumber}
          ${order.shippingAddress.alternateMobileNumber ? `<br>Alt Phone: ${order.shippingAddress.alternateMobileNumber}` : ''}
        </div>
      ` : `
        <h3 style="margin-top:30px; color:#333; border-bottom: 2px solid #eee; padding-bottom: 5px;">Shipping Address:</h3>
        <p style="font-size:16px; color:#555;">No shipping address provided.</p>
      `;

			const htmlBody = `
        <body style="margin:0; padding:0; background-color:#f7f7f7; font-family: Arial, sans-serif;">
          <table align="center" cellpadding="0" cellspacing="0" width="600" style="background-color:#ffffff; border-radius:8px; overflow:hidden; margin-top:40px; border: 1px solid #ddd;">
            <tr><td style="background-color:#007BFF; padding:20px; text-align:center; color:#ffffff; font-size:24px;"><strong>New Order Notification</strong></td></tr>
            <tr>
              <td style="padding:30px;">
                <p style="font-size:18px; color:#333;">A new order has been placed on Yash Agency.</p>
                <table cellpadding="10" cellspacing="0" width="100%" style="border-collapse:collapse; margin-top:20px;">
                  <tr><td style="background-color:#f2f2f2; font-weight:bold; width: 150px;">Order Number:</td><td>#${orderIdentifier}</td></tr>
                  <tr><td style="background-color:#f2f2f2; font-weight:bold;">Order Total:</td><td>₹${order.total.toFixed(2)}</td></tr>
                  <tr><td style="background-color:#f2f2f2; font-weight:bold;">Payment Method:</td><td>${order.paymentMethod.toUpperCase()}</td></tr>
                  <tr><td style="background-color:#f2f2f2; font-weight:bold;">Customer:</td><td>${customer ? customer.name : 'N/A'} (${customer ? customer.email : 'N/A'})</td></tr>
                </table>
                <h3 style="margin-top:30px; color:#333; border-bottom: 2px solid #eee; padding-bottom: 5px;">Items Ordered:</h3>
                <table cellpadding="10" cellspacing="0" width="100%" style="border-collapse:collapse;"><tr style="background-color:#f2f2f2;"><th align="left">Product</th><th align="center">Quantity</th><th align="right">Price</th></tr>${orderItemsHtml}</table>
                ${shippingAddressHtml}
                <p style="text-align:center; margin-top:30px;">
                  <a href="${adminOrderLink}" style="background-color:#007BFF; color:#ffffff; text-decoration:none; padding:12px 24px; border-radius:5px; font-weight:bold; display: inline-block;">View Order in Admin Panel</a>
                </p>
              </td>
            </tr>
            <tr><td style="background-color:#f2f2f2; text-align:center; padding:15px; font-size:12px; color:#777;">© ${new Date().getFullYear()} Yash Agency. All rights reserved.</td></tr>
          </table>
        </body>`;

			await emailTransporter.sendMail({
				from: `"Yash Agency Orders" <${process.env.EMAIL_USER}>`,
				to: adminEmail,
				subject: subject,
				html: htmlBody,
			});
		} catch (error) {
			console.error(`Failed to send new order admin notification email for order ${order._id}:`, error);
		}
	} else {
		console.warn('Email service is not configured. Skipping admin new order notification email.');
	}

	// --- Send Push Notification ---
	if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
		try {
			const adminUser = await User.findOne({ email: adminEmail });
			if (adminUser && adminUser.pushSubscriptions.length > 0) {
				const payload = JSON.stringify({
					title: '📦 New Order Received!',
					body: `Order #${orderIdentifier} for ₹${order.total.toFixed(2)} has been placed.`,
					url: adminOrderLink
				});

				adminUser.pushSubscriptions.forEach(sub => {
					webpush.sendNotification(sub, payload).catch(async (error) => {
						if (error.statusCode === 410) { // Gone, subscription is no longer valid
							await User.updateOne(
								{ _id: adminUser._id },
								{ $pull: { pushSubscriptions: { endpoint: sub.endpoint } } }
							);
						} else {
							console.error('Error sending push notification to admin:', error);
						}
					});
				});
			}
		} catch (error) {
			console.error(`Failed to send new order admin push notification for order ${order._id}:`, error);
		}
	} else {
		console.warn('VAPID keys not configured. Skipping admin push notification.');
	}
};

// --- Password Reset Routes ---

// --- Forgot Password ---
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    // Do NOT reveal if user exists
    if (!user) {
      return res.json({ message: 'If a user with that email exists, a password reset link has been sent.' });
    }

    // Generate secure reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.passwordResetExpires = Date.now() + 5 * 60 * 1000; // 5 minutes

    await user.save();

    // Email config check
    if (!process.env.EMAIL_HOST || !process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      return res.status(500).json({ error: 'Email service is not configured on the server.' });
    }

    const resetUrl = `${FRONTEND_URL}/reset-password/${resetToken}`;
    const message = `Click to reset your password:\n\n${resetUrl}\n\nIf not requested, please ignore.`;

    await emailTransporter.sendMail({
      from: `"Yash Agency Support" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: 'Password Reset Request',
      text: message,
    });

    res.json({ message: 'If a user with that email exists, a password reset link has been sent.' });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Error sending password reset email.' });
  }
});

// --- Reset Password ---
app.post('/api/reset-password/:token', async (req, res) => {
  try {
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ error: 'Password reset token is invalid or has expired.' });
    }

    // 🔒 Update password (ensure hashing via pre-save hook)
    user.password = req.body.password;

    // 🔥 Invalidate old tokens by bumping sessionVersion
    user.sessionVersion = (user.sessionVersion || 0) + 1;
    user.activeSessions = []; // Clear all active sessions

    // Remove reset token
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save();

    res.json({ message: 'Password has been reset successfully. Please login again.' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to reset password.' });
  }
});

// Create Razorpay Order
/*
app.post('/api/payment/create-order', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;
    const options = {
      amount: Math.round(amount * 100), // amount in the smallest currency unit
      currency: "INR",
      receipt: `receipt_order_${crypto.randomBytes(4).toString('hex')}`
    };

    const order = await razorpay.orders.create(options);

    if (!order) {
      return res.status(500).send("Error creating Razorpay order");
    }

    res.json({
      orderId: order.id,
      amount: order.amount,
      keyId: process.env.RAZORPAY_KEY_ID
    });
  } catch (error) {
    res.status(500).send("Error creating Razorpay order");
  }
});

// Verify Razorpay Payment
app.post('/api/payment/verify', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    const body = razorpay_order_id + "|" + razorpay_payment_id;

    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body.toString())
      .digest('hex');

    if (expectedSignature === razorpay_signature) {
      res.json({ success: true, message: "Payment verified successfully" });
    } else {
      res.status(400).json({ success: false, message: "Payment verification failed" });
    }
  } catch (error) {
    res.status(500).json({ error: 'Payment verification failed' });
  }
});
*/

app.post('/api/create-admin', async (req, res) => {
  // This endpoint is intentionally left less secure for initial setup.
  // In a real production environment, this should be removed or heavily secured.
  // ... (implementation from server11.js can be copied here if needed)
}
);

// Zod schema for order status update
const updateOrderStatusSchema = z.object({
  body: z.object({
    status: z.enum(['pending', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'])
  })
});

// Update order status (for admin/testing)
app.patch('/api/orders/:id/status', authenticateToken, validate(updateOrderStatusSchema),
  async (req, res) => {
    try {
      const { status, courierName, trackingNumber, estimatedDelivery, notes } = req.body;
      const order = await Order.findById(req.params.id);
      
      if (!order) {
        return res.status(404).json({ error: 'Order not found' });
      }

      // Allow admin or order owner to update status
      const adminEmail = process.env.ADMIN_EMAIL || 'yashagency25@gmail.com';
      if (req.user.email !== adminEmail && order.userId.toString() !== req.user._id.toString()) {
        return res.status(403).json({ error: 'Access denied' });
      }

      // Add to status history
      if (order.status !== status) { // Only add to history if status has changed
        order.statusHistory.push({
          status: status, // Use the NEW status
          updatedAt: new Date(),
          updatedBy: req.user.email,
          notes: notes || `Status changed from ${order.status} to ${status}`
        });
      }
      order.status = status;

      // If a COD order is marked as delivered, automatically mark payment as received
      if (status === 'delivered' && order.paymentMethod === 'cod') {
        order.paymentStatus = 'received';
      }

      // If status is shipped, update courier details and reduce stock
      if (status === 'shipped' && (courierName || trackingNumber)) {
        order.courierDetails = {
          courierName: courierName || order.courierDetails?.courierName,
          trackingNumber: trackingNumber || order.courierDetails?.trackingNumber,
          estimatedDelivery: estimatedDelivery ? new Date(estimatedDelivery) : order.courierDetails?.estimatedDelivery,
          shippedAt: new Date()
        };
        
        // Reduce stock when shipped
        for (const item of order.items) {
          if (item.selectedVariant) {
            // Reduce variant stock
            await Product.findOneAndUpdate(
              { 
                _id: item.productId,
                'variants.size': item.selectedVariant.size,
                'variants.color': item.selectedVariant.color
              },
              { $inc: { 'variants.$.stock': -item.quantity } }
            );
          } else {
            // Reduce main product stock
            await Product.findByIdAndUpdate(item.productId, {
              $inc: { stock: -item.quantity }
            });
          }
        }
      }

      await order.save();

      // Send order status update email to the customer
      const customer = await User.findById(order.userId);
      if (customer && customer.email) {
        sendOrderStatusEmail(customer.email, customer.name, order);
      }


      // Create a notification for the user and send a push notification
      if (order.userId) {
        const notificationMessage = `Your order #${order.orderNumber || order._id.slice(-8)} has been updated to: ${status}.`;
        const notification = new Notification({
            userId: order.userId,
            message: notificationMessage,
            link: `/track/${order._id}`
        });
        await notification.save();

        // Send push notification
        const user = await User.findById(order.userId);
        if (user && user.pushSubscriptions.length > 0 && process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
          const payload = JSON.stringify({
            title: 'Order Status Update',
            body: notificationMessage,
            url: `${FRONTEND_URL}/track/${order._id}`
          });

          user.pushSubscriptions.forEach(sub => {
            webpush.sendNotification(sub, payload).catch(async (error) => {
              if (error.statusCode === 410) { // Gone, subscription is no longer valid
                await User.updateOne(
                  { _id: user._id },
                  { $pull: { pushSubscriptions: { endpoint: sub.endpoint } } }
                );
              }
            });
          });
        }
      }

      res.json({ message: 'Order status updated', order });
    } catch (error) {
      res.status(500).json({ error: 'Failed to update order status' });
    }
  }
);

// User-initiated order cancellation
app.patch('/api/orders/:id/cancel', authenticateToken, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // Ensure the user owns the order
    if (order.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied. You can only cancel your own orders.' });
    }

    // Check if the order is in a cancellable state
    if (order.status !== 'pending' && order.status !== 'processing') {
      return res.status(400).json({ error: `Order cannot be cancelled. Current status: ${order.status}` });
    }

    const previousStatus = order.status;
    order.status = 'cancelled';

    // Add a record to the status history
    order.statusHistory.push({
      status: 'cancelled',
      updatedAt: new Date(),
      updatedBy: req.user.email, // Identify that the customer initiated this action
      notes: `Order cancelled by customer. Previous status was ${previousStatus}.`
    });

    await order.save();

    // Send cancellation confirmation email
    if (req.user.email) {
      sendOrderStatusEmail(req.user.email, req.user.name, order);
      sendOrderCancellationAdminNotification(order, req.user); // Notify admin of the cancellation
    }

    res.json({ message: 'Your order has been successfully cancelled.', order });
  } catch (error) {
    res.status(500).json({ error: 'Failed to cancel order.' });
  }
});

// --- Admin Order Cancellation Notification ---
const sendOrderCancellationAdminNotification = async (order, user) => {
  const adminEmail = process.env.ADMIN_EMAIL || 'Yashagency25@gmail.com';
  const orderIdentifier = order.orderNumber || order._id.toString().slice(-8);
  const adminOrderLink = `${FRONTEND_URL}/admin/orders`;

  // --- Send Email Notification ---
  if (process.env.EMAIL_HOST && process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    try {
      const subject = `❌ Order Cancelled by Customer: #${orderIdentifier}`;
      const htmlBody = `
        <body style="margin:0; padding:0; background-color:#f7f7f7; font-family: Arial, sans-serif;">
          <table align="center" cellpadding="0" cellspacing="0" width="600" style="background-color:#ffffff; border-radius:8px; overflow:hidden; margin-top:40px; border: 1px solid #ddd;">
            <tr><td style="background-color:#DC3545; padding:20px; text-align:center; color:#ffffff; font-size:24px;"><strong>Order Cancelled by Customer</strong></td></tr>
            <tr>
              <td style="padding:30px;">
                <p style="font-size:18px; color:#333;">An order has been cancelled by the customer.</p>
                <table cellpadding="10" cellspacing="0" width="100%" style="border-collapse:collapse; margin-top:20px;">
                  <tr><td style="background-color:#f2f2f2; font-weight:bold; width: 150px;">Order Number:</td><td>#${orderIdentifier}</td></tr>
                  <tr><td style="background-color:#f2f2f2; font-weight:bold;">Order Total:</td><td>₹${order.total.toFixed(2)}</td></tr>
                  <tr><td style="background-color:#f2f2f2; font-weight:bold;">Customer:</td><td>${user.name} (${user.email})</td></tr>
                </table>
                <p style="font-size:16px; color:#555; margin-top:20px;">The order status has been updated to 'cancelled'. Please review any necessary refund procedures.</p>
                <p style="text-align:center; margin-top:30px;"><a href="${adminOrderLink}" style="background-color:#6c757d; color:#ffffff; text-decoration:none; padding:12px 24px; border-radius:5px; font-weight:bold; display: inline-block;">View Order Details</a></p>
              </td>
            </tr>
            <tr><td style="background-color:#f2f2f2; text-align:center; padding:15px; font-size:12px; color:#777;">© ${new Date().getFullYear()} Yash Agency. All rights reserved.</td></tr>
          </table>
        </body>`;

      await emailTransporter.sendMail({ from: `"Yash Agency Alerts" <${process.env.EMAIL_USER}>`, to: adminEmail, subject, html: htmlBody });
    } catch (error) {
      console.error(`Failed to send order cancellation admin email for order ${order._id}:`, error);
    }
  }

  // --- Send Push Notification ---
  if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
    try {
      const adminUser = await User.findOne({ email: adminEmail });
      if (adminUser && adminUser.pushSubscriptions.length > 0) {
        const payload = JSON.stringify({
          title: '❌ Order Cancelled',
          body: `Order #${orderIdentifier} was cancelled by the customer.`,
          url: adminOrderLink
        });
        adminUser.pushSubscriptions.forEach(sub => webpush.sendNotification(sub, payload).catch(err => console.error('Error sending cancellation push notification:', err)));
      }
    } catch (error) {
      console.error(`Failed to send order cancellation admin push notification for order ${order._id}:`, error);
    }
  }
};

// Endpoint to mark that refund details have been submitted
app.patch('/api/orders/:id/refund-details-submitted', authenticateToken, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // Ensure the user owns the order
    if (order.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied.' });
    }

    order.refundDetailsSubmitted = true;
    await order.save();

    res.json({ message: 'Refund details status updated.', order });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update order.' });
  }
});
// Get orders by date range for admin
app.get('/api/admin/orders/date-range', authenticateToken, adminAuth, async (req, res) => {
  try {
    const { startDate, endDate, status, searchTerm } = req.query;
    
    let query = {};
    
    if (startDate && endDate) {
      query.createdAt = {
        $gte: new Date(startDate),
        $lte: new Date(endDate + 'T23:59:59.999Z')
      };
    }
    
    if (status && status !== 'all') {
      query.status = status;
    }

    if (searchTerm) {
      query.orderNumber = { $regex: searchTerm, $options: 'i' };
    }
    
    const orders = await Order.find(query)
      .sort({ createdAt: -1 })
      .populate('userId', 'name email phone');
    
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Get order analytics for admin
app.get('/api/admin/analytics', authenticateToken, adminAuth, async (req, res) => {
  try {
    const today = new Date();
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const endOfDay = new Date();
    endOfDay.setHours(23, 59, 59, 999);
    
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    sevenDaysAgo.setHours(0, 0, 0, 0);

    const [dailyStats, weeklySales, totalRevenueResult, statusCounts, totalCancelledResult, totalRefundedResult] = await Promise.all([
      Order.aggregate([
        { $match: { createdAt: { $gte: startOfDay, $lte: endOfDay } } },
        {
          $group: {
            _id: {
              paymentMethod: "$paymentMethod",
              status: "$status"
            },
            count: { $sum: 1 },
            totalAmount: { $sum: "$total" }
          }
        }
      ]),
      Order.aggregate([
        { $match: { 
            createdAt: { $gte: sevenDaysAgo },
            status: { $nin: ['cancelled', 'refunded'] } 
        } },
        { $group: {
            _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            totalSales: { $sum: "$total" }
        }},
        { $sort: { _id: 1 } }
      ]),
      Order.aggregate([
        { $match: { status: { $nin: ['cancelled', 'refunded'] } } },
        { $group: { 
            _id: null, total: { $sum: '$total' } 
        } }
      ]),
      Order.aggregate([
        { $group: { _id: '$status', count: { $sum: 1 } } }
      ]),
      Order.aggregate([
        { $match: { status: 'cancelled' } },
        { $group: { _id: null, total: { $sum: '$total' } } }
      ]),
      Order.aggregate([
        { $match: { status: 'refunded' } },
        { $group: { _id: null, total: { $sum: '$total' } } }
      ]),
    ]);

    const todayAnalytics = {
      totalOrders: 0,
      totalRevenue: 0,
      codOrders: 0,
      codRevenue: 0,
      prepaidOrders: 0,
      prepaidRevenue: 0,
      cancelledRevenue: 0,
      refundedRevenue: 0,
    };

    // Process all daily stats from the single aggregation
    dailyStats.forEach(group => {
      const status = group._id.status;
      const paymentMethod = group._id.paymentMethod;

      if (status === 'cancelled') {
        todayAnalytics.cancelledRevenue += group.totalAmount;
      } else if (status === 'refunded') {
        todayAnalytics.refundedRevenue += group.totalAmount;
      } else {
        // Only count non-cancelled/refunded orders towards total revenue and orders
        todayAnalytics.totalOrders += group.count;
        todayAnalytics.totalRevenue += group.totalAmount;

        if (paymentMethod === 'cod') {
          todayAnalytics.codOrders += group.count;
          todayAnalytics.codRevenue += group.totalAmount;
        } else { // Assumes 'razorpay' or other prepaid methods
          todayAnalytics.prepaidOrders += group.count;
          todayAnalytics.prepaidRevenue += group.totalAmount;
        }
      }
    });

    res.json({
      today: todayAnalytics,
      statusCounts,
      totalRevenue: totalRevenueResult[0]?.total || 0,
      weeklySales: weeklySales || [],
      totalCancelled: totalCancelledResult[0]?.total || 0,
      totalRefunded: totalRefundedResult[0]?.total || 0,
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// Get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Zod schema for profile update
const updateProfileSchema = z.object({
  body: z.object({
    name: z.string().trim().min(1, { message: 'Name is required' }),
    email: z.string().email({ message: 'Invalid email address' }),
    phone: z.string().trim().optional()
  })
});

// Update user profile
app.put('/api/profile', authenticateToken, validate(updateProfileSchema),
  async (req, res) => {
    try {
      const { name, email, phone } = req.body;
      
      const existingUser = await User.findOne({ email, _id: { $ne: req.user._id } });
      if (existingUser) {
        return res.status(400).json({ error: 'Email already in use' });
      }

      const user = await User.findByIdAndUpdate(
        req.user._id,
        { name, email, phone },
        { new: true }
      ).select('-password');

      res.json({ 
        message: 'Profile updated successfully',
        user: { id: user._id, name: user.name, email: user.email, phone: user.phone }
      }); // Note: isEmailVerified is not returned here, but it's not changed by this route.
    } catch (error) {
      res.status(500).json({ error: 'Failed to update profile' });
    }
  }
);

// Zod schema for password change
const changePasswordSchema = z.object({
  body: z.object({
    currentPassword: z.string().min(1, { message: 'Current password is required' }),
    newPassword: z.string().min(6, { message: 'New password must be at least 6 characters long' })
  })
});

// Change password
app.put('/api/change-password', authenticateToken, validate(changePasswordSchema),
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      
      const user = await User.findById(req.user._id);
      const isValidPassword = await bcrypt.compare(currentPassword, user.password);
      
      if (!isValidPassword) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 12);
      await User.findByIdAndUpdate(req.user._id, { password: hashedPassword });

      res.json({ message: 'Password changed successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Failed to change password' });
    }
  }
);

// Zod schema for adding an address
const addAddressSchema = z.object({
  body: z.object({
    name: z.string().trim().min(1, { message: 'Name is required' }),
    mobileNumber: z.string().trim().min(10, { message: 'Mobile number must be at least 10 digits' }),
    alternateMobileNumber: z.string().trim().optional(),
    addressType: z.enum(['home', 'work']),
    street: z.string().trim().min(1, { message: 'Street/House No. is required' }),
    city: z.string().trim().min(1, { message: 'City/Town is required' }),
    zipCode: z.string().trim().min(6, { message: 'A 6-digit Pincode is required' })
  })
});

// Add address
app.post('/api/addresses', authenticateToken, validate(addAddressSchema),
  async (req, res) => {
    try {
      const { name, mobileNumber, alternateMobileNumber, addressType, street, city, state, zipCode, country } = req.body;
      
      const user = await User.findById(req.user._id);
      user.addresses.push({ name, mobileNumber, alternateMobileNumber, addressType, street, city, state, zipCode, country: country || 'India' });
      await user.save();

      res.json({ message: 'Address added successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Failed to add address' });
    }
  }
);

// Update address
app.put('/api/addresses/:id', authenticateToken, validate(addAddressSchema),
  async (req, res) => {
    try {
      const { id } = req.params;
      const updatedAddressData = req.body;

      const user = await User.findById(req.user._id);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      const addressToUpdate = user.addresses.id(id);
      if (!addressToUpdate) {
        return res.status(404).json({ error: 'Address not found' });
      }

      addressToUpdate.set(updatedAddressData);
      await user.save();

      res.json({ message: 'Address updated successfully', address: addressToUpdate });
    } catch (error) {
      res.status(500).json({ error: 'Failed to update address' });
    }
  }
);
// Delete address
app.delete('/api/addresses/:id', authenticateToken, async (req, res) => {
  try {
    await User.findByIdAndUpdate(
      req.user._id,
      { $pull: { addresses: { _id: req.params.id } } }
    );

    res.json({ message: 'Address deleted successfully' });
  } catch (error) {
    console.error('Delete address error:', error);
    res.status(500).json({ error: 'Failed to delete address', details: error.message });
  }
});

// Coupon Schema
const couponSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true, uppercase: true },
  discount: { type: Number, required: true },
  type: { type: String, enum: ['percentage', 'fixed'], default: 'percentage' },
  minAmount: { type: Number, default: 0 },
  maxDiscount: { type: Number },
  expiryDate: { type: Date, required: true },
  isActive: { type: Boolean, default: true },
  oneTimeUse: { type: Boolean, default: false },
  usageCount: { type: Number, default: 0 },
  usedBy: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    usedAt: { type: Date, default: Date.now },
    orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Order' }
  }],
  createdAt: { type: Date, default: Date.now }
});

const Coupon = mongoose.model('Coupon', couponSchema);

// NEW: Sub-schema for individual shipping zones
const shippingZoneSchema = new mongoose.Schema({
  id: { type: Number, required: true },
  name: { type: String, required: true },
  states: { type: String, default: '' },
  pincodes: { type: String, default: '' },
  cost: { type: Number, required: true }
});

// Settings Schema
const settingsSchema = new mongoose.Schema({
  shippingCost: { type: Number, default: 0 },
  minOrderAmount: { type: Number, default: 0 },
  phone: { type: String, default: 'NA' },
  email: { type: String, default: 'NA' },
  instagram: { type: String, default: 'NA' },
  facebook: { type: String, default: 'NA' },
  shippingZones: [shippingZoneSchema], // Add shipping zones array
  updatedAt: { type: Date, default: Date.now }
});

const Settings = mongoose.model('Settings', settingsSchema);

// Banner Schema
const bannerSchema = new mongoose.Schema({
  desktop: {
    title: { type: String, default: 'Welcome to Yash Agency' },
    subtitle: { type: String, default: 'Discover amazing products at great prices' },
    backgroundImage: { type: String, default: '' },
    backgroundVideo: { type: String, default: '' },
  },
  mobile: {
    title: { type: String, default: 'Welcome to Yash Agency' },
    subtitle: { type: String, default: 'Amazing products, great prices' },
    backgroundImage: { type: String, default: '' },
    backgroundVideo: { type: String, default: '' },
  },
  isActive: { type: Boolean, default: true },
  updatedAt: { type: Date, default: Date.now }
});

const Banner = mongoose.model('Banner', bannerSchema);

// Contact Schema
const contactSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, lowercase: true },
  subject: { type: String, required: true, trim: true },
  message: { type: String, required: true, trim: true },
  status: { type: String, enum: ['new', 'read', 'replied'], default: 'new' },
  createdAt: { type: Date, default: Date.now }
});

const Contact = mongoose.model('Contact', contactSchema);

// Admin - Get all products
app.get('/api/admin/products', authenticateToken, adminAuth, async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Admin - Add product
app.post('/api/admin/products', authenticateToken, adminAuth, async (req, res) => {
  try {
    // Explicitly destructure fields from req.body for security and clarity
    const { name, description, price, minSellPrice, originalPrice, discountPercentage, imageUrl, images, category, soldBy, stock, variants, highlights, specifications, warranty, showHighlights, showSpecifications, showWarranty, enabled } = req.body;

    const product = new Product({
      name, description, price, minSellPrice, originalPrice, discountPercentage, imageUrl, images, category, soldBy, stock, variants, highlights, specifications, warranty, showHighlights, showSpecifications, showWarranty, enabled
    });

    await product.save();

    res.json({ message: 'Product added successfully', product });
  } catch (error) {
    // Log the detailed error on the server for debugging
    console.error('Error adding product:', error); 
    // Send a more descriptive error to the client
    res.status(500).json({ error: 'Failed to add product. Please check all fields.', details: error.message });
  }
});

// Admin - Upload Image to GCS
app.post('/api/admin/upload', authenticateToken, adminAuth, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const folder = 'yashproduct';
    const originalName = req.file.originalname.replace(/\s+/g, '-');
    const filename = `${folder}/${Date.now()}-${originalName}`;
    const blob = bucket.file(filename);

    const blobStream = blob.createWriteStream({
      resumable: false,
      contentType: req.file.mimetype,
    });

    blobStream.on('error', (err) => {
      console.error('GCS Upload Error:', err);
      res.status(500).json({ error: 'Failed to upload image to GCS' });
    });

    blobStream.on('finish', () => {
      const publicUrl = `https://storage.googleapis.com/${process.env.GCS_BUCKET}/${filename}`;
      res.json({ imageUrl: publicUrl });
    });

    blobStream.end(req.file.buffer);
  } catch (error) {
    console.error('Upload route error:', error);
    res.status(500).json({ error: 'Internal server error during upload' });
  }
});

// Admin - Update product
app.put('/api/admin/products/:id', authenticateToken, adminAuth, async (req, res) => {
  try {
    // For updates, it's also good practice to be explicit.
    // We can create an update object with all the fields from the body.
    const updateData = req.body;

    const product = await Product.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json({ message: 'Product updated successfully', product });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update product' });
  }
});

// Admin - Toggle product status
app.patch('/api/admin/products/:id/toggle', authenticateToken, adminAuth, async (req, res) => {
  try {
    const { enabled } = req.body;
    const product = await Product.findByIdAndUpdate(req.params.id, { enabled }, { new: true });
    res.json({ message: 'Product status updated', product });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update product status' });
  }
});

// Admin - Get all orders
app.get('/api/admin/orders', authenticateToken, adminAuth, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 }).populate('userId', 'name email phone');
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Admin - Get all coupons
app.get('/api/admin/coupons', authenticateToken, adminAuth, async (req, res) => {
  try {
    const coupons = await Coupon.find().sort({ createdAt: -1 });
    res.json(coupons);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

// Admin - Get all users
app.get('/api/admin/users', authenticateToken, adminAuth, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    
    // Get order stats for all users in single aggregation
    const userStats = await Order.aggregate([
      { $match: { status: 'delivered' } },
      { $group: {
        _id: '$userId',
        orderCount: { $sum: 1 },
        totalAmount: { $sum: '$total' }
      }}
    ]);
    
    const statsMap = new Map(userStats.map(stat => [stat._id.toString(), stat]));
    
    const usersWithStats = users.map(user => {
      const stats = statsMap.get(user._id.toString()) || { orderCount: 0, totalAmount: 0 };
      return {
        ...user.toObject(),
        orderCount: stats.orderCount,
        totalAmount: stats.totalAmount
      };
    });
    
    res.json(usersWithStats);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Admin - Create a new user (can be admin or user)
app.post('/api/admin/users', authenticateToken, adminAuth, async (req, res) => {
  try {
    const { name, email, password, phone, role } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: 'A user with this email already exists.' });
    }

    const newUser = new User({
      name,
      email,
      password, // The 'pre-save' hook will hash this automatically
      phone,
      role: role === 'admin' ? 'admin' : 'user', // Ensure role is either 'admin' or defaults to 'user'
      isEmailVerified: true, // Admins create verified users
    });

    await newUser.save();
    res.status(201).json({ message: 'User created successfully.', user: { id: newUser._id, name: newUser.name, email: newUser.email, role: newUser.role } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create user.' });
  }
});

// Admin - Create coupon
app.post('/api/admin/coupons', authenticateToken, adminAuth, async (req, res) => {
  try {
    const allowedFields = ['code', 'discount', 'type', 'minAmount', 'maxDiscount', 'expiryDate', 'oneTimeUse'];
    const couponData = {};
    
    allowedFields.forEach(field => {
      if (req.body[field] !== undefined) {
        couponData[field] = req.body[field];
      }
    });
    
    const coupon = new Coupon(couponData);
    await coupon.save();
    res.json({ message: 'Coupon created successfully', coupon });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create coupon' });
  }
});

// Admin - Toggle coupon status
app.patch('/api/admin/coupons/:id/toggle', authenticateToken, adminAuth, async (req, res) => {
  try {
    const { isActive } = req.body;
    const coupon = await Coupon.findByIdAndUpdate(req.params.id, { isActive }, { new: true });
    res.json({ message: 'Coupon status updated', coupon });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update coupon status' });
  }
});

// Admin - Get coupon usage report
app.get('/api/admin/coupons/report', authenticateToken, adminAuth, async (req, res) => {
  try {
    const coupons = await Coupon.find()
      .populate('usedBy.userId', 'name email')
      .populate('usedBy.orderId', 'orderNumber total')
      .sort({ createdAt: -1 });
    res.json(coupons);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch coupon report' });
  }
});

// Apply coupon
app.post('/api/apply-coupon', authenticateToken, async (req, res) => {
  try {
    const { code, total } = req.body;
    const coupon = await Coupon.findOne({ 
      code: code.toUpperCase(), 
      isActive: true, 
      expiryDate: { $gt: new Date() } 
    });
    
    if (!coupon) {
      return res.status(400).json({ error: 'Invalid or expired coupon' });
    }
    
    if (total < coupon.minAmount) {
      return res.status(400).json({ error: `Minimum order amount is ₹${coupon.minAmount}` });
    }
    
    // Check if user already used this coupon (for one-time use coupons)
    if (coupon.oneTimeUse && coupon.usedBy.some(usage => usage.userId.toString() === req.user._id.toString())) {
      return res.status(400).json({ error: 'Coupon already used by you' });
    }
    
    let discount = 0;
    if (coupon.type === 'percentage') {
      discount = Math.round((total * coupon.discount) / 100);
      if (coupon.maxDiscount && discount > coupon.maxDiscount) {
        discount = coupon.maxDiscount;
      }
    } else {
      discount = coupon.discount;
    }
    
    res.json({ discount, message: 'Coupon applied successfully', couponId: coupon._id });
  } catch (error) {
    res.status(500).json({ error: 'Failed to apply coupon' });
  }
});

// NEW: Endpoint to calculate shipping cost based on address
app.post('/api/calculate-shipping', async (req, res) => {
  try {
    const { pincode, state } = req.body;

    if (!pincode) {
      return res.status(400).json({ error: 'Pincode is required for shipping calculation.' });
    }

    const settings = await Settings.findOne({});
    // If no settings exist, default to free shipping.
    if (!settings) {
      return res.json({ shippingCost: 0 });
    }

    const { shippingZones = [], shippingCost: fallbackCost = 0 } = settings;

    let matchedCost = -1;
    let bestMatchLevel = 0; // 0: fallback, 1: catch-all, 2: state, 3: pincode

    const customerPincode = pincode.trim();
    const customerState = state ? state.trim().toLowerCase() : '';

    for (const zone of shippingZones) {
      // Level 3: Direct Pincode Match (Highest priority)
      const zonePincodes = (zone.pincodes || '').split(',').map(p => p.trim());
      if (zonePincodes.includes(customerPincode)) {
        matchedCost = zone.cost;
        bestMatchLevel = 3;
        break; // Found the best possible match
      }

      // Level 2: State Match
      if (bestMatchLevel < 2 && customerState) {
        const zoneStates = (zone.states || '').toLowerCase().split(',').map(s => s.trim());
        if (zoneStates.includes(customerState)) {
          matchedCost = zone.cost;
          bestMatchLevel = 2;
        }
      }
    }

    // If no specific zone matched, use the fallback cost
    const finalCost = matchedCost !== -1 ? matchedCost : fallbackCost;
    res.json({ shippingCost: finalCost });

  } catch (error) {
    console.error('Error calculating shipping:', error);
    res.status(500).json({ error: 'Could not calculate shipping cost.' });
  }
});

// Get all public settings
app.get('/api/settings', async (req, res) => {
  try {
    const settings = await Settings.findOne();
    res.json(settings || {});
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

// Admin - Update settings
app.put('/api/admin/settings', authenticateToken, adminAuth, async (req, res) => {
  try {
    // Destructure to handle shippingZones separately
    const { shippingZones, ...otherSettings } = req.body;
    const settingsData = {
      ...otherSettings,
      shippingZones: shippingZones || [] // Ensure shippingZones is an array
    };

    const settings = await Settings.findOneAndUpdate({}, settingsData, { upsert: true, new: true });
    res.json({ message: 'Settings updated successfully', settings });
  } catch (error) {
    console.error('Error updating settings:', error);
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// Add product rating
app.post('/api/products/:id/rating', authenticateToken, async (req, res) => {
  try {
    const { rating, review } = req.body;
    const productId = req.params.id;
    
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    // Check if user already rated this product
    const existingRating = product.ratings.find(r => r.userId.toString() === req.user._id.toString());
    
    if (existingRating) {
      // Update existing rating
      existingRating.rating = rating;
      existingRating.review = review;
    } else {
      // Add new rating
      product.ratings.push({
        userId: req.user._id,
        rating,
        review
      });
    }
    
    // Calculate average rating
    const totalRatings = product.ratings.length;
    const avgRating = product.ratings.reduce((sum, r) => sum + r.rating, 0) / totalRatings;
    
    product.averageRating = Math.round(avgRating * 10) / 10;
    product.totalRatings = totalRatings;
    
    await product.save();
    
    res.json({ message: 'Rating added successfully', averageRating: product.averageRating });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add rating' });
  }
});

// Get banner settings
app.get('/api/banner', async (req, res) => {
  try {
    const banner = await Banner.findOne({ isActive: true }) || new Banner();
    res.json(banner);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch banner' });
  }
});

// Admin - Update banner
app.put('/api/admin/banner', authenticateToken, adminAuth, async (req, res) => {
  try {
    const banner = await Banner.findOneAndUpdate(
      {}, // Find the first (and only) banner document
      { $set: req.body, updatedAt: new Date(), $setOnInsert: { isActive: true } },
      { upsert: true, new: true }
    );
    res.json({ message: 'Banner updated successfully', banner });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update banner' });
  }
});

// Get user's wishlist
app.get('/api/wishlist', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate('wishlist');
    res.json({ 
      wishlist: user.wishlist || [],
      products: user.wishlist || []
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get wishlist' });
  }
});

app.get('/api/cart', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate('cart.productId');
    const cartItems = user.cart.map(item => ({
      ...item.productId.toObject(),
      quantity: item.quantity
    }));
    res.json({ cart: cartItems });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get cart' });
  }
});

// Update user's cart
app.post('/api/cart', authenticateToken, async (req, res) => {
  try {
    const { cart: cartData } = req.body;
    if (!Array.isArray(cartData)) {
      return res.status(400).json({ error: 'Cart data must be an array.' });
    }
    const newCart = cartData.map(item => ({
      productId: item.productId || item._id,
      quantity: item.quantity
    }));

    await User.findByIdAndUpdate(req.user._id, {
      $set: { cart: newCart }
    });
    res.json({ message: 'Cart updated' });
  } catch (error) {
    console.error('Cart update error:', error); // Log the full error on the server
    res.status(500).json({ error: 'Failed to update cart' });
  }
});

// Add to wishlist
app.post('/api/wishlist/:id', authenticateToken, async (req, res) => {
  try {
    const productId = req.params.id;
    const user = await User.findById(req.user._id);
    
    if (user.wishlist.includes(productId)) {
      return res.status(400).json({ error: 'Product already in wishlist' });
    }
    
    user.wishlist.push(productId);
    await user.save();
    
    res.json({ message: 'Product added to wishlist' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add to wishlist' });
  }
});

// Remove from wishlist
app.delete('/api/wishlist/:id', authenticateToken, async (req, res) => {
  try {
    const productId = req.params.id;
    const user = await User.findById(req.user._id);
    
    user.wishlist = user.wishlist.filter(id => id.toString() !== productId);
    await user.save();
    
    res.json({ message: 'Product removed from wishlist' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to remove from wishlist' });
  }
});

// Zod schema for contact form
const contactSchemaZod = z.object({
  body: z.object({
    name: z.string().trim().min(1, { message: 'Name is required' }),
    email: z.string().email({ message: 'Invalid email address' }),
    subject: z.string().trim().min(1, { message: 'Subject is required' }),
    message: z.string().trim().min(10, { message: 'Message must be at least 10 characters long' })
  })
});

// Contact form submission
app.post('/api/contact', validate(contactSchemaZod),
  async (req, res) => {
    const { name, email, subject, message } = req.body;

    // Ensure email service is configured before proceeding
    if (!process.env.EMAIL_HOST || !process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      console.error('Contact form submission failed: Email service is not configured on the server.');
      return res.status(500).json({ error: 'Could not process your request at this time.' });
    }

    try {
      const adminEmail = process.env.ADMIN_EMAIL || 'Yashagency25@gmail.com';

      await emailTransporter.sendMail({
        from: `"Yash Agency Contact Form" <${process.env.EMAIL_USER}>`,
        to: adminEmail,
        replyTo: email, // Set the user's email as the reply-to address
        subject: `New Contact Form Submission:  ${subject}`,
        html: `
          <p><strong>Name:</strong> ${name}</p>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>Subject:</strong> ${subject}</p>
          <p><strong>Message:</strong></p>
          <p>${message.replace(/\n/g, '<br>')}</p>
        `,
      });

      res.json({ message: 'Thank you for your message. We will get back to you shortly.' });
    } catch (error) {
      console.error('Failed to send contact form email:', error);
      res.status(500).json({ error: 'Failed to send your message. Please try again later.' });
    }
  }
);

// Admin - Get all contact messages
app.get('/api/admin/contacts', authenticateToken, adminAuth, async (req, res) => {
  try {
    const contacts = await Contact.find().sort({ createdAt: -1 });
    res.json(contacts);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch contact messages' });
  }
});

// Admin - Update contact message status
app.patch('/api/admin/contacts/:id/status', authenticateToken, adminAuth, async (req, res) => {
  try {
    const { status } = req.body;
    await Contact.findByIdAndUpdate(req.params.id, { status });
    res.json({ message: 'Status updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update status' });
  }
});

// Create admin account (bypasses rate limiting)
app.post('/api/create-admin', async (req, res) => {
  try {
    const adminEmail = ['yashagency25@gmail.com'];
    const { password } = req.body;
    
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const existingUser = await User.findOne({ email: adminEmail });
    if (existingUser) {
      return res.status(400).json({ error: 'Admin account already exists' });
    }
    
    const adminUser = new User({
      name: 'Admin',
      email: adminEmail,
      password: password
    });
    
    await adminUser.save();
    
    const token = jwt.sign(
      { userId: adminUser._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      message: 'Admin account created successfully',
      token,
      user: { id: adminUser._id, name: adminUser.name, email: adminUser.email }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create admin account' });
  }
});

// --- Salesman Management Routes (Admin Only) ---

const createSalesmanSchema = z.object({
  body: z.object({
    name: z.string().min(1),
    email: z.string().email(),
    password: z.string().min(6),
    phone: z.string().optional(),
    maxDiscountPercent: z.number().optional(),
    address: z.string().optional(),
    pincode: z.string().regex(/^\d{6}$/, "Pincode must be 6 digits").optional().or(z.literal(''))
  })
});

app.post('/api/admin/salesmen', authenticateToken, adminAuth, validate(createSalesmanSchema), async (req, res) => {
  try {
    const { name, email, password, phone, maxDiscountPercent, address, pincode } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    const salesman = new User({
      name,
      email,
      password, // Hashed by pre-save
      phone,
      role: 'salesman',
      isEmailVerified: true,
      isActive: true,
      maxDiscountPercent: maxDiscountPercent || 0,
      createdByAdmin: req.user._id,
      salesmanAddress: address,
      salesmanPincode: pincode
    });

    await salesman.save();
    res.status(201).json({ message: 'Salesman account created', salesman: { id: salesman._id, name: salesman.name, email: salesman.email } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create salesman' });
  }
});

app.get('/api/admin/salesmen', authenticateToken, adminAuth, async (req, res) => {
  try {
    const salesmen = await User.find({ role: 'salesman' }).select('-password').sort({ createdAt: -1 });
    res.json(salesmen);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch salesmen' });
  }
});

app.patch('/api/admin/salesmen/:id', authenticateToken, adminAuth, async (req, res) => {
  try {
    const { isActive } = req.body;
    if (typeof isActive !== 'boolean') return res.status(400).json({ error: 'isActive must be a boolean' });

    const salesman = await User.findByIdAndUpdate(req.params.id, { isActive }, { new: true }).select('-password');
    if (!salesman) return res.status(404).json({ error: 'Salesman not found' });

    res.json({ message: `Salesman ${isActive ? 'enabled' : 'disabled'}`, salesman });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update salesman status' });
  }
});

app.get('/api/salesman/customers', authenticateToken, salesmanAuth, async (req, res) => {
  try {
    const { search } = req.query;
    if (!search) return res.json([]);

    const customers = await User.find({
      role: 'customer',
      $or: [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } }
      ]
    }).select('name email phone addresses');

    res.json(customers);
  } catch (error) {
    res.status(500).json({ error: 'Search failed' });
  }
});

const createCustomerBySalesmanSchema = z.object({
  body: z.object({
    name: z.string().min(1),
    email: z.string().email(),
    phone: z.string().min(10),
    address: z.string().optional(),
    pincode: z.string().regex(/^\d{6}$/, "Pincode must be 6 digits").optional().or(z.literal(''))
  })
});

app.post('/api/salesman/customers', authenticateToken, salesmanAuth, validate(createCustomerBySalesmanSchema), async (req, res) => {
  try {
    const { name, email, phone, address, pincode } = req.body;

    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Customer with this email or phone already exists' });
    }

    const password = crypto.randomBytes(8).toString('hex');
    const customer = new User({
      name,
      email,
      phone,
      password,
      role: 'customer',
      isEmailVerified: true
    });

    if (address && pincode) {
      customer.addresses.push({
        name,
        mobileNumber: phone,
        street: address,
        city: 'N/A', // Defaulting as it is required in schema but not asked
        zipCode: pincode,
        country: 'India'
      });
    }

    await customer.save();

    res.status(201).json({ message: 'Customer created successfully', customer: { _id: customer._id, name: customer.name, email: customer.email, phone: customer.phone } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create customer' });
  }
});

// --- Salesman Order Routes ---

const salesmanOrderSchema = z.object({
  body: z.object({
    customerPhone: z.string().min(10),
    items: z.array(z.object({
      productId: z.string(),
      quantity: z.number().min(1),
      finalPrice: z.number().min(0)
    })).min(1),
    shippingAddress: z.object({
      name: z.string().optional(),
      mobileNumber: z.string().optional(),
      street: z.string().optional(),
      city: z.string().optional(),
      state: z.string().optional(),
      zipCode: z.string().optional(),
      country: z.string().optional()
    }).optional()
  })
});

app.post('/api/salesman/orders', authenticateToken, salesmanAuth, validate(salesmanOrderSchema), async (req, res) => {
  try {
    const { customerPhone, items, shippingAddress } = req.body;

    // 1. Find or Create Customer
    let customer = await User.findOne({ phone: customerPhone });
    if (!customer) {
      const generatedEmail = `${customerPhone}@guest.Yash Agency.in`; // Dummy email
      const generatedPassword = crypto.randomBytes(8).toString('hex');
      customer = new User({
        name: `Guest ${customerPhone}`,
        email: generatedEmail,
        phone: customerPhone,
        password: generatedPassword,
        role: 'customer',
        isEmailVerified: true
      });
      await customer.save();
    }

    // 2. Validate Items and Prices
    let total = 0;
    const orderItems = [];

    for (const item of items) {
      const product = await Product.findById(item.productId);
      if (!product) return res.status(404).json({ error: `Product not found: ${item.productId}` });

      // Price Protection Check
      if (item.finalPrice < (product.minSellPrice || 0)) {
        return res.status(400).json({ error: `Price for ${product.name} cannot be less than ${product.minSellPrice}` });
      }

      total += item.finalPrice * item.quantity;
      orderItems.push({
        productId: product._id,
        name: product.name,
        price: item.finalPrice, // Store the salesman's custom price
        quantity: item.quantity
      });
    }

    // 3. Create Order
    const now = new Date();
    const dateStr = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}`;
    const counter = await Counter.findOneAndUpdate(
      { date: dateStr },
      { $inc: { count: 1 } },
      { upsert: true, new: true }
    );
    const orderNumber = `${dateStr}${String(counter.count).padStart(4, '0')}`;

    const order = new Order({
      orderNumber,
      userId: customer._id,
      items: orderItems,
      total,
      shippingAddress,
      orderBy: 'salesman',
      status: 'pending',
      paymentMethod: 'cod',
      orderSource: 'salesman',
      salesmanId: req.user._id,
      salesmanName: req.user.name
    });

    await order.save();

    res.status(201).json({ message: 'Order placed successfully', orderId: order._id, orderNumber: order.orderNumber });

  } catch (error) {
    console.error('Salesman order error:', error);
    res.status(500).json({ error: 'Failed to place order' });
  }
});

app.get('/api/salesman/orders', authenticateToken, salesmanAuth, async (req, res) => {
  try {
    const orders = await Order.find({ salesmanId: req.user._id })
      .sort({ createdAt: -1 })
      .populate('userId', 'name phone email');
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// --- Delivery Area Routes ---

// Public route to check if a pincode is deliverable
app.get('/api/check-pincode/:pincode', async (req, res) => {
  try {
    const { pincode } = req.params;
    if (!/^\d{6}$/.test(pincode)) {
      return res.status(400).json({ deliverable: false, message: 'Invalid pincode format.' });
    }

    const area = await Pincode.findOne({ pincode: parseInt(pincode, 10), deliverable: true });

    if (area) {
      res.json({ deliverable: true, message: `Delivery available to pincode ${pincode} in ${area.districtName}, ${area.stateName}`});
    } else {
      res.status(404).json({ deliverable: false, message: 'Sorry, we do not deliver to this pincode yet.' });
    }
  } catch (error) {
    console.error('Pincode check error:', error);
    res.status(500).json({ deliverable: false, message: 'Error checking pincode availability.' });
  }
});

// Admin route to get all delivery areas for management
app.get('/api/admin/delivery-areas', authenticateToken, adminAuth, async (req, res) => {
  try {
    const stateDistrictMap = await StateDistrictMap.find({}).sort({ stateName: 1 });

    res.json({
      // The frontend will now receive a structured map instead of flat lists.
      // Example: [{ stateName: "Maharashtra", districts: ["Mumbai", "Pune"] }]
      stateDistrictMap: stateDistrictMap,
      pincodes: [] // Pincodes will be fetched on demand
    });

  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch delivery areas.' });
  }
});

// NEW: Admin route to fetch pincodes based on filters
app.get('/api/admin/pincodes/search', authenticateToken, adminAuth, async (req, res) => {
  try {
    const { state, district, pincode } = req.query;
    const query = {};

    if (state) query.stateName = state;
    if (district) query.districtName = district;
    // Corrected: Handle pincode as a number.
    // The regex approach works for strings, but the schema has pincode as a Number.
    if (pincode && /^\d+$/.test(pincode)) {
      query.pincode = parseInt(pincode, 10);
    }

    // Only execute query if at least one filter is provided
    if (Object.keys(query).length === 0) {
      return res.json([]);
    }

    const pincodes = await Pincode.find(query).limit(500).sort({ pincode: 1 }); // Limit to 500 results for performance
    res.json(pincodes);
  } catch (error) {
    res.status(500).json({ error: 'Failed to search for pincodes.' });
  }
});

// Admin route to update a pincode's deliverable status
app.patch('/api/admin/pincodes/:pincode', authenticateToken, adminAuth, async (req, res) => {
  try {
    const { deliverable } = req.body;
    await Pincode.updateMany({ pincode: req.params.pincode }, { $set: { deliverable } });
    res.json({ message: `Pincode ${req.params.pincode} status updated.` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update pincode status.' });
  }
});

// Admin route for bulk updating pincodes by state/district
app.patch('/api/admin/delivery-areas/bulk-update', authenticateToken, adminAuth, async (req, res) => {
  try {
    const { stateName, districtName, deliverable } = req.body;

    if (!stateName || typeof deliverable !== 'boolean') {
      return res.status(400).json({ error: 'State name and deliverable status are required.' });
    }

    const filter = { stateName };
    if (districtName) {
      filter.districtName = districtName;
    }

    const result = await Pincode.updateMany(filter, { $set: { deliverable } });

    res.json({ message: `Successfully updated ${result.modifiedCount} pincodes.`, result });
  } catch (error) {
    console.error('Bulk pincode update error:', error);
    res.status(500).json({ error: 'Failed to perform bulk update on pincodes.' });
  }
});

// --- Push Notification Subscription ---
app.post('/api/subscribe', authenticateToken, async (req, res) => {
  const subscription = req.body;
  try {
    // Check if subscription already exists to avoid duplicates
    const user = await User.findById(req.user._id);
    const exists = user.pushSubscriptions.some(sub => sub.endpoint === subscription.endpoint);

    if (!exists) {
      await User.updateOne(
        { _id: req.user._id },
        { $push: { pushSubscriptions: subscription } }
      );
    }
    res.status(201).json({ message: 'Subscription saved.' });
  } catch (error) {
    console.error('Error saving subscription:', error);
    res.status(500).json({ error: 'Failed to save subscription.' });
  }
});

app.get('/api/vapidPublicKey', (req, res) => {
  res.send(process.env.VAPID_PUBLIC_KEY);
});
// --- Notification Routes ---

// Get user notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const notifications = await Notification.find({ userId: req.user._id, deleted: { $ne: true } })
      .sort({ createdAt: -1 })
      .limit(20); // Limit to recent 20
    res.json(notifications);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

// Mark a single notification as read
app.patch('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const notification = await Notification.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { read: true },
      { new: true }
    );
    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    res.json({ message: 'Notification marked as read' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update notification' });
  }
});

// Mark all notifications as read
app.patch('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    await Notification.updateMany({ userId: req.user._id, read: false }, { $set: { read: true } });
    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to mark all notifications as read' });
  }
});

// Soft-delete all notifications for a user
app.delete('/api/notifications/clear-all', authenticateToken, async (req, res) => {
  try {
    // To handle potential data inconsistencies where userId might be stored as a string,
    // we query for both ObjectId and its string representation.
    const userIdToUpdate = req.user._id;
    const result = await Notification.updateMany(
      { userId: { $in: [userIdToUpdate, userIdToUpdate.toString()] } },
      { $set: { deleted: true } }
    );
    res.json({ message: 'All notifications cleared successfully', modifiedCount: result.modifiedCount });
  } catch (error) {
    console.error('Error clearing notifications:', error);
    res.status(500).json({ error: 'Failed to clear notifications' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

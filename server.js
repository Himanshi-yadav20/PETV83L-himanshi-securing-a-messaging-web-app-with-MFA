const express = require('express');
const bodyParser = require('body-parser');           // ake sure this is here
const session = require('express-session');
const cors = require('cors');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();                               // Must be defined before app.use()
app.use(cors({
  origin: 'http://127.0.0.1:5500',
  credentials: true
}));

app.use(bodyParser.json());     



// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-just-for-testing', // ✅ fallback value
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

console.log("Session secret loaded:", !!process.env.SESSION_SECRET);

// Database mock (replace with real DB)
const users = {};
const tempSecrets = {};
const verificationCodes = {};

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Routes

// 1. Registration Endpoint
app.post('/register', async (req, res) => {
  console.log("📨 /register hit");
  console.log("Request body:", req.body); // log what frontend sends

  const { email, password } = req.body;

  if (users[email]) {
    return res.status(400).json({ error: 'User already exists' });
  }
  // Store user (in real app, hash the password!)
  users[email] = { email, password, mfaEnabled: false };
  
  // Generate MFA secret and QR code
  const secret = speakeasy.generateSecret({
    name: "Secure Messaging App",
    issuer: "SecureApp Inc",
    length: 32
  });
  
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
  
  // Store secret temporarily
  tempSecrets[email] = secret.base32;
  
  res.json({
    success: true,
    qrCodeUrl,
    manualSecret: secret.base32
  });
});

// 2. Verify MFA Setup
app.post('/verify-mfa-setup', (req, res) => {
  const { email, mfaCode } = req.body;
  const secret = tempSecrets[email];
  
  if (!secret) {
    return res.status(400).json({ error: 'No MFA setup in progress' });
  }
  
  const verified = speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token: mfaCode,
    window: 1
  });
  
  if (verified) {
    // Store secret permanently with user
    users[email].mfaSecret = secret;
    users[email].mfaEnabled = true;
    delete tempSecrets[email];
    
    // Send verification email
    sendVerificationEmail(email);
    
    return res.json({ success: true });
  } else {
    return res.status(400).json({ error: 'Invalid MFA code' });
  }
});

// 3. Send Verification Email
async function sendVerificationEmail(email) {
  const code = crypto.randomInt(100000, 999999).toString();
  verificationCodes[email] = {
    code,
    expires: Date.now() + 600000 // 10 minutes
  };
  
  await transporter.sendMail({
    from: '"Secure App" <no-reply@secureapp.com>',
    to: email,
    subject: 'Your Verification Code',
    text: `Your verification code is: ${code}`,
    html: `<p>Your verification code is: <strong>${code}</strong></p>`
  });
}

app.post('/send-verification-email', (req, res) => {
  const { email } = req.body;
  sendVerificationEmail(email);
  res.json({ success: true });
});

// 4. Verify Email Code
app.post('/verify-email', (req, res) => {
  const { email, code } = req.body;
  const record = verificationCodes[email];
  
  if (!record || record.expires < Date.now()) {
    return res.status(400).json({ error: 'Invalid or expired code' });
  }
  
  if (record.code === code) {
    users[email].emailVerified = true;
    delete verificationCodes[email];
    return res.json({ success: true });
  } else {
    return res.status(400).json({ error: 'Invalid code' });
  }
});

// 5. Login with MFA and Email Verification
app.post('/login', (req, res) => {
  const { email, password, mfaCode, emailCode } = req.body;
  const user = users[email];
  
  // 1. Verify credentials
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // 2. Verify MFA if enabled
  if (user.mfaEnabled) {
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: mfaCode,
      window: 1
    });
    
    if (!verified) {
      return res.status(401).json({ error: 'Invalid MFA code' });
    }
  }
  
  // 3. Verify email code if not verified
  if (!user.emailVerified) {
    const record = verificationCodes[email];
    if (!record || record.code !== emailCode) {
      return res.status(401).json({ error: 'Invalid email verification code' });
    }
    user.emailVerified = true;
  }
  
  // Create session
  req.session.user = { email };
  res.json({ success: true });
});

// Start server
app.listen(3000, () => {
  console.log('Server running on port 3000');
});
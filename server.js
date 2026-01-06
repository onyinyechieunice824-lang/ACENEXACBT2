import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import axios from 'axios';
import fs from 'fs';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// --------------------- CORS ---------------------
const allowedOrigins = [
  'https://acenexacbt-2.vercel.app',      // REAL frontend URL
  'https://acenexacbt.onrender.com',    // optional backend calls
  'http://localhost:5173',
  'http://localhost:3000'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      return callback(null, true); // permissive fallback
    }
    return callback(null, true);
  }
}));

app.use(express.json({ limit: '50mb' }));

// ----------------- SUPABASE CLIENT -----------------
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error("CRITICAL: Missing Supabase credentials.");
}

const supabase = createClient(supabaseUrl, supabaseKey, { auth: { persistSession: false } });

// ----------------- HELPERS -----------------
const generateTokenCode = (prefix = 'ACE') => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const length = 12;
  const randomBytes = crypto.randomBytes(length);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[randomBytes[i] % chars.length];
  }
  return `${prefix}-${result.slice(0,4)}-${result.slice(4,8)}-${result.slice(8,12)}`;
};

const getRemainingDays = (expiresAt) => {
  if (!expiresAt) return null;
  const now = new Date();
  const expiry = new Date(expiresAt);
  const diffTime = expiry - now;
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
};

// ----------------- HEALTH CHECK -----------------
app.get('/health', (req, res) => res.send('OK'));

// ----------------- PAYSTACK PAYMENT VERIFICATION -----------------
app.post('/api/payments/verify-paystack', async (req, res) => {
  const { reference, email, fullName, phoneNumber, examType } = req.body;
  if (!reference) return res.status(400).json({ error: "Missing reference." });

  try {
    const { data: existingToken } = await supabase
      .from('access_tokens')
      .select('token_code, is_active')
      .eq('metadata->>payment_ref', reference)
      .single();

    if (existingToken) {
      return res.json({ success: true, token: existingToken.token_code, message: "Existing access code retrieved." });
    }

    const paystackUrl = `https://api.paystack.co/transaction/verify/${reference}`;
    const verifyRes = await axios.get(paystackUrl, {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
    });

    const data = verifyRes.data.data;
    if (data.status !== 'success') return res.status(400).json({ error: "Payment failed." });

    // Minimum amount check (adjust if needed)
    if (data.amount < 150000) return res.status(400).json({ error: "Invalid amount." });

    const tokenCode = generateTokenCode('ACE');
    const finalExamType = examType || 'BOTH';

    const { data: dbData, error } = await supabase
      .from('access_tokens')
      .insert([{
        token_code: tokenCode,
        is_active: true,
        device_fingerprint: null,
        expires_at: new Date(new Date().setFullYear(new Date().getFullYear() + 1)),
        metadata: {
          payment_ref: reference,
          amount_paid: data.amount / 100,
          exam_type: finalExamType,
          full_name: fullName,
          phone_number: phoneNumber,
          email: email,
          paystack_id: data.id,
          verified_at: new Date().toISOString()
        }
      }])
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, token: dbData.token_code });

  } catch (err) {
    console.error('Payment verification error:', err.response?.data || err.message);
    res.status(500).json({ error: "Could not verify payment." });
  }
});

// ----------------- ADMIN LOGIN -----------------
app.post('/api/auth/admin-login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .eq('role', 'admin')
      .single();

    if (error || !user || user.password !== password) return res.status(401).json({ error: 'Invalid credentials' });

    const { password: _, ...adminInfo } = user;
    res.json(adminInfo);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ----------------- STUDENT TOKEN LOGIN -----------------
app.post('/api/auth/login-with-token', async (req, res) => {
  const { token, deviceFingerprint, confirm_binding } = req.body;

  try {
    const { data: tokenData, error } = await supabase
      .from('access_tokens')
      .select('*')
      .eq('token_code', token)
      .single();

    if (error || !tokenData) return res.status(401).json({ error: 'Invalid Access Token.' });
    if (!tokenData.is_active) return res.status(403).json({ error: 'This token is deactivated.' });

    // Bind device if needed
    if (!tokenData.device_fingerprint) {
      if (!confirm_binding) return res.json({ requires_binding: true });
      const { error: bindError } = await supabase
        .from('access_tokens')
        .update({ device_fingerprint: deviceFingerprint })
        .eq('id', tokenData.id);
      if (bindError) throw bindError;
    } else if (tokenData.device_fingerprint !== deviceFingerprint) {
      return res.status(403).json({ error: 'Access code locked to another device.' });
    }

    const remainingDays = getRemainingDays(tokenData.expires_at);
    const expiryMsg = remainingDays ? `${remainingDays} days remaining` : 'Lifetime';

    res.json({
      username: tokenData.token_code,
      role: 'student',
      fullName: tokenData.metadata?.full_name || 'Student',
      regNumber: tokenData.token_code,
      isTokenLogin: true,
      allowedExamType: tokenData.metadata?.exam_type || 'BOTH',
      remainingDays,
      expiresAt: tokenData.expires_at,
      expiryMessage: expiryMsg
    });

  } catch (err) {
    console.error('Token login error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ----------------- FRONTEND BUILD -----------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distPath = path.join(__dirname, 'dist');

if (fs.existsSync(distPath)) {
  app.use(express.static(distPath));
  app.get('*', (req, res) => res.sendFile(path.join(distPath, 'index.html')));
} else {
  app.get('*', (req, res) => res.status(503).send('<h1>Frontend not built</h1>'));
}

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

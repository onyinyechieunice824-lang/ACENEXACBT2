import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import axios from 'axios';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// --------------------- CORS ---------------------
const allowedOrigins = [
  'https://acenexacb-tupdate.vercel.app',
  'https://acenexacbt.onrender.com',
  'http://localhost:5173',
  'http://localhost:3000'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      return callback(null, true);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['Set-Cookie']
}));

app.use(express.json({ limit: '50mb' }));

// ----------------- SUPABASE CLIENT -----------------
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error("CRITICAL: Missing Supabase credentials.");
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey, { 
  auth: { persistSession: false } 
});

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
app.get('/', (req, res) => res.json({ 
  status: 'OK', 
  service: 'ACENEXA CBT API',
  timestamp: new Date().toISOString() 
}));

app.get('/health', (req, res) => res.json({ 
  status: 'OK', 
  timestamp: new Date().toISOString() 
}));

app.get('/api/health', (req, res) => res.json({ 
  status: 'OK', 
  timestamp: new Date().toISOString() 
}));

// ----------------- AUTH ENDPOINTS -----------------

// Unified Login Endpoint
app.post('/api/auth/login', async (req, res) => {
  const { username, password, role } = req.body;

  try {
    if (role === 'admin') {
      const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('username', username)
        .eq('role', 'admin')
        .single();

      if (error || !user || user.password !== password) {
        return res.status(401).json({ message: 'Invalid admin credentials' });
      }

      const { password: _, ...adminInfo } = user;
      return res.json({ 
        user: {
          username: adminInfo.username,
          fullName: adminInfo.full_name || 'Admin',
          regNumber: 'ADMIN',
          role: 'admin',
          allowedExamType: 'BOTH'
        }
      });
    } else {
      const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('username', username)
        .eq('role', 'student')
        .single();

      if (error || !user || user.password !== password) {
        return res.status(401).json({ message: 'Invalid student credentials' });
      }

      const { password: _, ...studentInfo } = user;
      return res.json({ 
        user: {
          username: studentInfo.username,
          fullName: studentInfo.full_name || studentInfo.username,
          regNumber: studentInfo.reg_number || studentInfo.username,
          role: 'student',
          allowedExamType: studentInfo.allowed_exam_type || 'BOTH'
        }
      });
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: err.message });
  }
});

// Token Login
app.post('/api/auth/token-login', async (req, res) => {
  const { token, forceBinding } = req.body;

  const userAgent = req.headers['user-agent'] || '';
  const deviceFingerprint = crypto.createHash('md5')
    .update(userAgent + (req.ip || 'unknown'))
    .digest('hex');

  try {
    const { data: tokenData, error } = await supabase
      .from('access_tokens')
      .select('*')
      .eq('token_code', token)
      .single();

    if (error || !tokenData) {
      return res.status(401).json({ message: 'Invalid Access Token.' });
    }

    if (!tokenData.is_active) {
      return res.status(403).json({ message: 'This token is deactivated.' });
    }

    if (tokenData.expires_at && new Date(tokenData.expires_at) < new Date()) {
      return res.status(403).json({ message: 'This token has expired.' });
    }

    if (!tokenData.device_fingerprint) {
      if (!forceBinding) {
        return res.status(200).json({ message: 'BINDING_REQUIRED' });
      }
      
      const { error: bindError } = await supabase
        .from('access_tokens')
        .update({ device_fingerprint: deviceFingerprint })
        .eq('id', tokenData.id);
      
      if (bindError) throw bindError;
    } else if (tokenData.device_fingerprint !== deviceFingerprint) {
      return res.status(403).json({ message: 'Access code locked to another device.' });
    }

    const remainingDays = getRemainingDays(tokenData.expires_at);

    res.json({
      user: {
        username: tokenData.token_code,
        fullName: tokenData.metadata?.full_name || 'Student',
        regNumber: tokenData.token_code,
        role: 'student',
        allowedExamType: tokenData.metadata?.exam_type || 'BOTH',
        isTokenLogin: true,
        remainingDays,
        expiresAt: tokenData.expires_at
      }
    });
  } catch (err) {
    console.error('Token login error:', err);
    res.status(500).json({ message: err.message });
  }
});

// Get Current User
app.get('/api/auth/me', async (req, res) => {
  res.json({ user: null });
});

// Logout
app.post('/api/auth/logout', async (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

// Change Password
app.post('/api/auth/change-password', async (req, res) => {
  const { username, oldPassword, newPassword, role } = req.body;

  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .eq('role', role)
      .single();

    if (error || !user || user.password !== oldPassword) {
      return res.status(401).json({ message: 'Invalid current password' });
    }

    const { error: updateError } = await supabase
      .from('users')
      .update({ password: newPassword })
      .eq('username', username);

    if (updateError) throw updateError;

    res.json({ success: true, message: 'Password changed successfully' });
  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ message: err.message });
  }
});

// ----------------- PAYSTACK PAYMENT -----------------
app.post('/api/payments/verify-paystack', async (req, res) => {
  const { reference, email, fullName, phoneNumber, examType } = req.body;
  
  if (!reference) {
    return res.status(400).json({ error: "Missing reference." });
  }

  try {
    const { data: existingToken } = await supabase
      .from('access_tokens')
      .select('token_code')
      .eq('metadata->>payment_ref', reference)
      .single();

    if (existingToken) {
      return res.json({ token: existingToken.token_code });
    }

    const paystackUrl = `https://api.paystack.co/transaction/verify/${reference}`;
    const verifyRes = await axios.get(paystackUrl, {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
    });

    const data = verifyRes.data.data;
    if (data.status !== 'success') {
      return res.status(400).json({ error: "Payment failed." });
    }

    if (data.amount < 150000) {
      return res.status(400).json({ error: "Invalid amount." });
    }

    const tokenCode = generateTokenCode('ACE');

    const { data: dbData, error } = await supabase
      .from('access_tokens')
      .insert([{
        token_code: tokenCode,
        is_active: true,
        device_fingerprint: null,
        expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
        metadata: {
          payment_ref: reference,
          amount_paid: data.amount / 100,
          exam_type: examType || 'BOTH',
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
    res.json({ token: dbData.token_code });

  } catch (err) {
    console.error('Payment error:', err.response?.data || err.message);
    res.status(500).json({ error: "Could not verify payment." });
  }
});

// ----------------- SUBJECTS -----------------
app.get('/api/subjects', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('subjects')
      .select('*')
      .order('name');

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Get subjects error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ----------------- ADMIN ENDPOINTS -----------------

// Stats
app.get('/api/admin/stats', async (req, res) => {
  try {
    const { data: questions, error } = await supabase
      .from('questions')
      .select('subject, exam_type');

    if (error) throw error;

    const stats = {};
    questions.forEach(q => {
      if (!stats[q.subject]) {
        stats[q.subject] = { JAMB: 0, WAEC: 0 };
      }
      if (q.exam_type === 'JAMB') stats[q.subject].JAMB++;
      if (q.exam_type === 'WAEC') stats[q.subject].WAEC++;
    });

    res.json(stats);
  } catch (err) {
    console.error('Get stats error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Get Questions
app.get('/api/admin/questions', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('questions')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Get questions error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Add Question
app.post('/api/admin/questions', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('questions')
      .insert([req.body])
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('Add question error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Bulk Add
app.post('/api/admin/questions/bulk', async (req, res) => {
  try {
    const { questions } = req.body;
    const { data, error } = await supabase
      .from('questions')
      .insert(questions)
      .select();

    if (error) throw error;
    res.json({ count: data.length });
  } catch (err) {
    console.error('Bulk add error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Delete Question
app.delete('/api/admin/questions/:id', async (req, res) => {
  try {
    const { error } = await supabase
      .from('questions')
      .delete()
      .eq('id', req.params.id);

    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    console.error('Delete question error:', err);
    res.status(500).json({ error: err.message });
  }
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start Server
app.listen(PORT, () => {
  console.log(`✅ ACENEXA Backend running on port ${PORT}`);
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

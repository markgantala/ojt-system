require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

// ---------- AUTH ----------
function signToken(user) {
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}

async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(authHeader.substring(7), JWT_SECRET);
    const { data: profile } = await supabase
      .from('profiles').select('*').eq('id', decoded.id).single();
    if (!profile) return res.status(401).json({ error: 'Profile not found' });
    req.user = profile;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function requireCoordinator(req, res, next) {
  if (req.user.role !== 'coordinator') return res.status(403).json({ error: 'Coordinator only' });
  next();
}

// ---------- AUTH ROUTES ----------
app.post('/api/auth/login', async (req, res) => {
  const { student_number, password } = req.body;
  if (!student_number || !password) return res.status(400).json({ error: 'Missing credentials' });

  const { data: profile, error } = await supabase
    .from('profiles').select('*').eq('student_number', student_number).single();
  if (error || !profile) return res.status(401).json({ error: 'Invalid student number or password' });

  const ok = await bcrypt.compare(password, profile.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid student number or password' });

  const { password_hash, ...safe } = profile;
  res.json({ token: signToken(profile), user: safe });
});

app.post('/api/auth/register', async (req, res) => {
  const { student_number, full_name, campus, password } = req.body;
  if (!student_number || !full_name || !password) return res.status(400).json({ error: 'Missing fields' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });

  const { data: existing } = await supabase
    .from('profiles').select('id').eq('student_number', student_number).single();
  if (existing) return res.status(400).json({ error: 'Student number already registered' });

  const hash = await bcrypt.hash(password, 10);
  const { data: profile, error } = await supabase.from('profiles').insert({
    student_number,
    password_hash: hash,
    full_name,
    campus: campus || '',
    role: 'student',
  }).select().single();
  if (error) return res.status(400).json({ error: error.message });

  const { password_hash, ...safe } = profile;
  res.json({ token: signToken(profile), user: safe });
});

// ---------- STUDENT ROUTES ----------
app.get('/api/student/steps', authMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from('student_steps').select('*')
    .eq('student_id', req.user.id).order('step_number');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/student/steps/:num/complete', authMiddleware, async (req, res) => {
  const num = parseInt(req.params.num);
  if (num !== 1) return res.status(403).json({ error: 'Only step 1 can be self-completed' });
  const { data, error } = await supabase.from('student_steps')
    .update({ status: 'approved', updated_at: new Date().toISOString() })
    .eq('student_id', req.user.id).eq('step_number', num).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/student/steps/:num/submit', authMiddleware, async (req, res) => {
  const num = parseInt(req.params.num);
  if (num < 2 || num > 12) return res.status(403).json({ error: 'Only steps 2-12 can be submitted for approval' });
  const { data, error } = await supabase.from('student_steps')
    .update({ status: 'completed', updated_at: new Date().toISOString() })
    .eq('student_id', req.user.id).eq('step_number', num).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ---------- SHARED ----------
app.get('/api/events', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('schedule_events').select('*').order('start_date');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ---------- COORDINATOR ROUTES ----------
app.get('/api/coordinator/students', authMiddleware, requireCoordinator, async (req, res) => {
  const { data, error } = await supabase.from('profiles')
    .select('id, student_number, full_name, campus, role, created_at')
    .eq('role', 'student').order('full_name');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/coordinator/all-steps', authMiddleware, requireCoordinator, async (req, res) => {
  const { data, error } = await supabase.from('student_steps').select('*');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/coordinator/students/:id/steps', authMiddleware, requireCoordinator, async (req, res) => {
  const { data, error } = await supabase.from('student_steps').select('*')
    .eq('student_id', req.params.id).order('step_number');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/coordinator/steps/:sid/:num/approve', authMiddleware, requireCoordinator, async (req, res) => {
  const num = parseInt(req.params.num);
  if (num < 2 || num > 12) return res.status(403).json({ error: 'Coordinator can only approve steps 2-12' });
  const { data, error } = await supabase.from('student_steps')
    .update({ status: 'approved', coordinator_note: req.body.note || null, updated_at: new Date().toISOString() })
    .eq('student_id', req.params.sid).eq('step_number', num).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/coordinator/steps/:sid/:num/reject', authMiddleware, requireCoordinator, async (req, res) => {
  const num = parseInt(req.params.num);
  if (num < 2 || num > 12) return res.status(403).json({ error: 'Coordinator can only reject steps 2-12' });
  const { data, error } = await supabase.from('student_steps')
    .update({ status: 'rejected', coordinator_note: req.body.note || null, updated_at: new Date().toISOString() })
    .eq('student_id', req.params.sid).eq('step_number', num).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/coordinator/steps/:sid/:num/reset', authMiddleware, requireCoordinator, async (req, res) => {
  const num = parseInt(req.params.num);
  if (num < 2 || num > 12) return res.status(403).json({ error: 'Only steps 2-12' });
  const { data, error } = await supabase.from('student_steps')
    .update({ status: 'pending', coordinator_note: null, updated_at: new Date().toISOString() })
    .eq('student_id', req.params.sid).eq('step_number', num).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/coordinator/events', authMiddleware, requireCoordinator, async (req, res) => {
  const { title, description, start_date, end_date } = req.body;
  if (!title || !start_date || !end_date) return res.status(400).json({ error: 'Missing fields' });
  const { data, error } = await supabase.from('schedule_events').insert({
    title, description: description || '', start_date, end_date, created_by: req.user.id,
  }).select();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.delete('/api/coordinator/events/:id', authMiddleware, requireCoordinator, async (req, res) => {
  const { error } = await supabase.from('schedule_events').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ---------- SPA FALLBACK ----------
// Catch-all for SPA (Express 5 compatible)
app.use((req, res, next) => {
  // If the request is for an API route, let it fall through to a 404
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  // For all other routes, send the frontend app
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
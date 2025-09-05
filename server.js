
// Run: node server.js

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const HOST = process.env.HOST || '0.0.0.0';
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const BOOKINGS_FILE = path.join(DATA_DIR, 'bookings.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';
const SESSION_COOKIE = 'sid';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// Rate limiting
const RATE_LIMITS = new Map(); // IP -> { attempts: number, resetTime: number }
const LOGIN_ATTEMPTS_LIMIT = 3;
const LOGIN_ATTEMPTS_WINDOW = 5 * 60 * 1000; // 5 minutes
const API_RATE_LIMIT = 100; // requests per minute
const API_RATE_WINDOW = 60 * 1000; // 1 minute

// Utilities
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 1e6) req.connection.destroy();
    });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function send(res, code, payload, headers={}) {
  const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(body);
}

function notFound(res) { send(res, 404, { error: 'Not found' }); }
function badRequest(res, msg) { send(res, 400, { error: msg || 'Bad request' }); }
function unauthorized(res) { send(res, 401, { error: 'Unauthorized' }); }
function forbidden(res) { send(res, 403, { error: 'Forbidden' }); }

function hashPassword(password, salt) {
  const s = salt || crypto.randomBytes(16).toString('hex');
  const h = crypto.createHash('sha256').update(password + s).digest('hex');
  return `${s}$${h}`;
}
function verifyPassword(password, stored) {
  const [s, h] = String(stored).split('$');
  const calc = crypto.createHash('sha256').update(password + s).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(h), Buffer.from(calc));
}

function sign(value) {
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('hex');
  return `${value}.${sig}`;
}
function verifySigned(signed) {
  const i = signed.lastIndexOf('.');
  if (i < 0) return null;
  const value = signed.slice(0, i);
  const sig = signed.slice(i + 1);
  const calc = crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(calc))) return null;
  return value;
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx > -1) out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1));
  });
  return out;
}

function setCookie(res, name, value, opts={}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (opts.path) parts.push(`Path=${opts.path}`); else parts.push('Path=/');
  if (opts.httpOnly !== false) parts.push('HttpOnly');
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`); else parts.push('SameSite=Lax');
  if (opts.maxAge) parts.push(`Max-Age=${Math.floor(opts.maxAge/1000)}`);
  if (opts.secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function ensureData() {
  console.log('Checking data directory:', DATA_DIR);
  console.log('Current working directory:', process.cwd());
  
  if (!fs.existsSync(DATA_DIR)) {
    console.log('Creating data directory...');
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  
  if (!fs.existsSync(USERS_FILE)) {
    console.log('Creating users file...');
    const admin = { username: 'Semral_boss', role: 'admin', password: hashPassword('aerw3232'), balance: 0 };
    fs.writeFileSync(USERS_FILE, JSON.stringify({ users: { [admin.username]: admin } }, null, 2));
    console.log('Admin user created:', admin.username);
  } else {
    console.log('Users file exists, reading...');
    const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    console.log('Existing users:', Object.keys(users.users || {}));
  }
  
  if (!fs.existsSync(BOOKINGS_FILE)) {
    console.log('Creating bookings file...');
    fs.writeFileSync(BOOKINGS_FILE, JSON.stringify({ bookings: [] }, null, 2));
  }
  
  if (!fs.existsSync(CONFIG_FILE)) {
    console.log('Creating config file...');
    fs.writeFileSync(CONFIG_FILE, JSON.stringify({ rate: 22.0765 }, null, 2));
  }
}
function readUsers() { ensureData(); return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
function writeUsers(data) { fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2)); }
function readBookings() { ensureData(); return JSON.parse(fs.readFileSync(BOOKINGS_FILE, 'utf8')); }
function writeBookings(data) { fs.writeFileSync(BOOKINGS_FILE, JSON.stringify(data, null, 2)); }
function readConfig() { ensureData(); return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); }
function writeConfig(data) { fs.writeFileSync(CONFIG_FILE, JSON.stringify(data, null, 2)); }

function getSessionUser(req) {
  const cookies = parseCookies(req);
  const raw = cookies[SESSION_COOKIE];
  if (!raw) return null;
  const value = verifySigned(raw);
  if (!value) return null;
  const [username, expStr] = value.split('|');
  const exp = Number(expStr);
  if (!username || !exp || Date.now() > exp) return null;
  const { users } = readUsers();
  return users[username] || null;
}

function createSession(username) {
  const exp = Date.now() + SESSION_TTL_MS;
  const value = `${username}|${exp}`;
  return sign(value);
}

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || 
         req.headers['x-real-ip'] || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         '127.0.0.1';
}

function checkRateLimit(ip, isLogin = false) {
  const now = Date.now();
  const limit = isLogin ? LOGIN_ATTEMPTS_LIMIT : API_RATE_LIMIT;
  const window = isLogin ? LOGIN_ATTEMPTS_WINDOW : API_RATE_WINDOW;
  
  const key = `${ip}:${isLogin ? 'login' : 'api'}`;
  const current = RATE_LIMITS.get(key);
  
  if (!current || now > current.resetTime) {
    RATE_LIMITS.set(key, { attempts: 1, resetTime: now + window });
    return { allowed: true, remaining: limit - 1 };
  }
  
  if (current.attempts >= limit) {
    return { allowed: false, remaining: 0, resetTime: current.resetTime };
  }
  
  current.attempts++;
  RATE_LIMITS.set(key, current);
  return { allowed: true, remaining: limit - current.attempts };
}

function tooManyRequests(res, resetTime) {
  const retryAfter = Math.ceil((resetTime - Date.now()) / 1000);
  res.setHeader('Retry-After', retryAfter);
  send(res, 429, { error: 'Too many requests', retryAfter });
}

function serveStatic(req, res, url) {
  let filePath = path.join(__dirname, decodeURIComponent(url.pathname));
  if (url.pathname === '/') filePath = path.join(__dirname, 'index.html');
  if (!filePath.startsWith(__dirname)) return notFound(res);
  fs.readFile(filePath, (err, data) => {
    if (err) return notFound(res);
    const ext = path.extname(filePath).toLowerCase();
    const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.png': 'image/png' };
    res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const clientIP = getClientIP(req);
    
    
    if (url.pathname.startsWith('/api/')) {
      const rateLimit = checkRateLimit(clientIP, false);
      if (!rateLimit.allowed) {
        return tooManyRequests(res, rateLimit.resetTime);
      }
    }
    
    // API routes
    if (url.pathname === '/api/login' && req.method === 'POST') {
      
      const loginRateLimit = checkRateLimit(clientIP, true);
      if (!loginRateLimit.allowed) {
        return tooManyRequests(res, loginRateLimit.resetTime);
      }
      const body = await readBody(req);
      const { username, password } = body;
      console.log(`Login attempt for user: ${username}`);
      
      if (!username || !password) return badRequest(res, 'username and password required');
      const { users } = readUsers();
      console.log('Available users:', Object.keys(users));
      
      const u = users[username];
      if (!u) {
        console.log(`User not found: ${username}`);
        return unauthorized(res);
      }
      
      const passwordValid = verifyPassword(password, u.password);
      console.log(`Password valid for ${username}: ${passwordValid}`);
      
      if (!passwordValid) {
        console.log(`Failed login attempt from ${clientIP} for user: ${username}`);
        return unauthorized(res);
      }
      const sid = createSession(u.username);
      setCookie(res, SESSION_COOKIE, sid, { httpOnly: true, maxAge: SESSION_TTL_MS, sameSite: 'Lax' });
      console.log(`Successful login from ${clientIP} for user: ${u.username}`);
      return send(res, 200, { ok: true, user: { username: u.username, role: u.role, balance: u.balance } });
    }

    if (url.pathname === '/api/logout' && req.method === 'POST') {
      setCookie(res, SESSION_COOKIE, '', { httpOnly: true, maxAge: 0, sameSite: 'Lax' });
      return send(res, 200, { ok: true });
    }

    if (url.pathname === '/api/me' && req.method === 'GET') {
      const user = getSessionUser(req);
      if (!user) return unauthorized(res);
      return send(res, 200, { user: { username: user.username, role: user.role, balance: user.balance } });
    }

    // Admin: create user
    if (url.pathname === '/api/users' && req.method === 'POST') {
      const user = getSessionUser(req);
      if (!user || user.role !== 'admin') return forbidden(res);
      const body = await readBody(req);
      const { username, password } = body;
      if (!username || !password) return badRequest(res, 'username and password required');
      const data = readUsers();
      if (data.users[username]) return badRequest(res, 'user exists');
      data.users[username] = { username, role: 'user', password: hashPassword(password), balance: 0 };
      writeUsers(data);
      return send(res, 200, { ok: true });
    }

    // Emergency admin creation endpoint (no auth required)
    if (url.pathname === '/api/init-admin' && req.method === 'POST') {
      const body = await readBody(req);
      const { secret, username, password } = body;
      
      // Simple secret check to prevent abuse
      if (secret !== 'init123') return unauthorized(res);
      
      const data = readUsers();
      if (data.users[username]) return badRequest(res, 'user exists');
      
      data.users[username] = { 
        username, 
        role: 'admin', 
        password: hashPassword(password), 
        balance: 0 
      };
      writeUsers(data);
      console.log(`Emergency admin created: ${username}`);
      return send(res, 200, { ok: true, message: 'Admin created successfully' });
    }

    // Admin: list users
    if (url.pathname === '/api/users' && req.method === 'GET') {
      const user = getSessionUser(req);
      if (!user || user.role !== 'admin') return forbidden(res);
      const data = readUsers();
      const list = Object.values(data.users).map(u => ({ username: u.username, role: u.role, balance: u.balance }));
      return send(res, 200, { users: list });
    }

    // Admin: delete user
    if (url.pathname.startsWith('/api/users/') && req.method === 'DELETE') {
      const user = getSessionUser(req);
      if (!user || user.role !== 'admin') return forbidden(res);
      const targetUsername = decodeURIComponent(url.pathname.split('/')[3]);
      if (!targetUsername) return badRequest(res, 'username required');
      
      
      if (targetUsername === user.username) return badRequest(res, 'cannot delete yourself');
      
      const data = readUsers();
      if (!data.users[targetUsername]) return badRequest(res, 'user not found');
      
      
      if (data.users[targetUsername].role === 'admin') return badRequest(res, 'cannot delete admin users');
      
      delete data.users[targetUsername];
      writeUsers(data);
      console.log(`User ${targetUsername} deleted by admin ${user.username}`);
      return send(res, 200, { ok: true });
    }

    // Admin: top up wallet
    if (url.pathname.startsWith('/api/users/') && url.pathname.endsWith('/topup') && req.method === 'POST') {
      const user = getSessionUser(req);
      if (!user || user.role !== 'admin') return forbidden(res);
      const target = decodeURIComponent(url.pathname.split('/')[3]);
      const body = await readBody(req);
      const amount = Number(body.amount);
      if (!Number.isFinite(amount) || amount <= 0) return badRequest(res, 'amount must be positive');
      const data = readUsers();
      if (!data.users[target]) return badRequest(res, 'user not found');
      data.users[target].balance = Number((Number(data.users[target].balance || 0) + amount).toFixed(2));
      writeUsers(data);
      return send(res, 200, { ok: true, balance: data.users[target].balance });
    }

    // Admin: decrease wallet
    if (url.pathname.startsWith('/api/users/') && url.pathname.endsWith('/decrease') && req.method === 'POST') {
      const user = getSessionUser(req);
      if (!user || user.role !== 'admin') return forbidden(res);
      const target = decodeURIComponent(url.pathname.split('/')[3]);
      const body = await readBody(req);
      const amount = Number(body.amount);
      if (!Number.isFinite(amount) || amount <= 0) return badRequest(res, 'amount must be positive');
      const data = readUsers();
      if (!data.users[target]) return badRequest(res, 'user not found');
      const currentBalance = Number(data.users[target].balance || 0);
      const newBalance = Math.max(0, currentBalance - amount); // Don't allow negative balance
      data.users[target].balance = Number(newBalance.toFixed(2));
      writeUsers(data);
      return send(res, 200, { ok: true, balance: data.users[target].balance });
    }

    // User: wallet balance
    if (url.pathname === '/api/wallet' && req.method === 'GET') {
      const user = getSessionUser(req);
      if (!user) return unauthorized(res);
      return send(res, 200, { balance: user.balance });
    }

    
    if (url.pathname === '/api/bookings' && req.method === 'POST') {
      const body = await readBody(req);
      const { date, time, name, phone } = body;
      if (!date || !time || !name || !phone) return badRequest(res, 'date,time,name,phone required');
      // naive validation
      if (!/^\d{4}-\d{2}-\d{2}$/.test(String(date)) || !/^\d{2}:\d{2}$/.test(String(time))) return badRequest(res, 'invalid date/time');
      const data = readBookings();
      const id = crypto.randomUUID();
      data.bookings.push({ id, date, time, name, phone, createdAt: new Date().toISOString() });
      writeBookings(data);
      return send(res, 200, { ok: true, id });
    }

    
    if (url.pathname === '/api/bookings' && req.method === 'GET') {
      const user = getSessionUser(req);
      if (!user || user.role !== 'admin') return forbidden(res);
      
      const nowUtc = Date.now();
      const ekbOffsetMs = 5 * 60 * 60 * 1000;
      const ekbNow = new Date(nowUtc + ekbOffsetMs);
      const ekbTodayStartUtc = Date.UTC(ekbNow.getUTCFullYear(), ekbNow.getUTCMonth(), ekbNow.getUTCDate()) - ekbOffsetMs;
      const ekbYesterdayStartUtc = ekbTodayStartUtc - 24*60*60*1000;
      const cutoffYmd = (d => `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}-${String(d.getUTCDate()).padStart(2,'0')}`)(new Date(ekbYesterdayStartUtc));

      const data = readBookings();
      const list = data.bookings
        .filter(b => b.date >= cutoffYmd)
        .sort((a,b) => (a.date+a.time).localeCompare(b.date+b.time));
      return send(res, 200, { bookings: list });
    }

    // Admin: delete booking
    if (url.pathname.startsWith('/api/bookings/') && req.method === 'DELETE') {
      const user = getSessionUser(req);
      if (!user || user.role !== 'admin') return forbidden(res);
      const bookingId = decodeURIComponent(url.pathname.split('/')[3]);
      if (!bookingId) return badRequest(res, 'booking ID required');
      
      const data = readBookings();
      const bookingIndex = data.bookings.findIndex(b => b.id === bookingId);
      if (bookingIndex === -1) return badRequest(res, 'booking not found');
      
      data.bookings.splice(bookingIndex, 1);
      writeBookings(data);
      console.log(`Booking ${bookingId} deleted by admin ${user.username}`);
      return send(res, 200, { ok: true });
    }

    // Rate API
    if (url.pathname === '/api/rate' && req.method === 'GET') {
      const cfg = readConfig();
      return send(res, 200, { rate: cfg.rate });
    }
    if (url.pathname === '/api/rate' && req.method === 'POST') {
      const user = getSessionUser(req);
      if (!user || user.role !== 'admin') return forbidden(res);
      const body = await readBody(req);
      const rate = Number(body.rate);
      if (!Number.isFinite(rate) || rate <= 0) return badRequest(res, 'rate must be positive');
      const cfg = readConfig();
      cfg.rate = Number(rate);
      writeConfig(cfg);
      return send(res, 200, { ok: true, rate: cfg.rate });
    }

    // Static files
    return serveStatic(req, res, url);
  } catch (err) {
    console.error(err);
    send(res, 500, { error: 'Internal error' });
  }
});

server.listen(PORT, HOST, () => {
  ensureData();
  
  // Always ensure admin exists
  const data = readUsers();
  const adminUsername = 'Semral_boss';
  const adminPassword = 'aerw3232';
  
  if (!data.users[adminUsername]) {
    console.log('Creating admin user...');
    data.users[adminUsername] = { 
      username: adminUsername, 
      role: 'admin', 
      password: hashPassword(adminPassword), 
      balance: 0 
    };
    writeUsers(data);
    console.log(`Admin created: ${adminUsername} / ${adminPassword}`);
  } else {
    console.log(`Admin exists: ${adminUsername}`);
  }
  
  console.log(`Server running on http://${HOST}:${PORT}`);
  console.log(`Admin login: ${adminUsername} / ${adminPassword}`);
});



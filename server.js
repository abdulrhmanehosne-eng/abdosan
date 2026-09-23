/**
 * خزينة الحسابات | Account Vault - Backend Server
 * خادم متعدد المستخدمين مع حفظ سحابي ومركزي للبيانات والصور
 * مبني باستخدام حزم Node.js المدمجة (بدون أي متطلبات تثبيت خارجية)
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const ACCOUNTS_FILE = path.join(DATA_DIR, 'accounts_store.json');

// التأكد من وجود مجلد البيانات
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// قراءة وكتابة ملفات JSON بأمان
function readJson(file, defaultValue = {}) {
  try {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, JSON.stringify(defaultValue, null, 2), 'utf-8');
      return defaultValue;
    }
    const data = fs.readFileSync(file, 'utf-8');
    return JSON.parse(data || '{}');
  } catch (err) {
    console.error(`Error reading ${file}:`, err);
    return defaultValue;
  }
}

function writeJson(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf-8');
    return true;
  } catch (err) {
    console.error(`Error writing ${file}:`, err);
    return false;
  }
}

// معالجة تشفير كلمات المرور
function hashPassword(password, salt = null) {
  if (!salt) {
    salt = crypto.randomBytes(16).toString('hex');
  }
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return { hash, salt };
}

function verifyPassword(password, hash, salt) {
  const check = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return check === hash;
}

// إدارة الجلسات ومصادقة المستخدمين
function createSession(userId) {
  const sessions = readJson(SESSIONS_FILE, {});
  const token = crypto.randomBytes(32).toString('hex');
  sessions[token] = {
    userId,
    createdAt: Date.now()
  };
  writeJson(SESSIONS_FILE, sessions);
  return token;
}

function getUserIdFromToken(token) {
  if (!token) return null;
  const sessions = readJson(SESSIONS_FILE, {});
  const session = sessions[token];
  if (!session) return null;
  return session.userId;
}

function deleteSession(token) {
  if (!token) return;
  const sessions = readJson(SESSIONS_FILE, {});
  delete sessions[token];
  writeJson(SESSIONS_FILE, sessions);
}

// الحصول على عنوان IP المحلي لمشاركته مع الجوال والأجهزة الأخرى
function getLocalIp() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return 'localhost';
}

// أنواع الملفات المدعومة
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

// إنشاء خادم HTTP
const server = http.createServer(async (req, res) => {
  // CORS Headers لدعم كافة الاتصالات
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsedUrl.pathname;

  // استخراج رمز التوثيق من الترويسة
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : '';
  const currentUserId = getUserIdFromToken(token);

  // دالة مساعدة لقراءة جسم الطلب (Body)
  const readBody = () => {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', chunk => {
        body += chunk;
        if (body.length > 50 * 1024 * 1024) { // حد 50 ميغابايت للصور الكبيرة
          reject(new Error('Request body too large'));
        }
      });
      req.on('end', () => {
        try {
          resolve(body ? JSON.parse(body) : {});
        } catch (e) {
          resolve({});
        }
      });
      req.on('error', err => reject(err));
    });
  };

  // إرجاع رد JSON
  const sendJson = (statusCode, data) => {
    res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(data));
  };

  // 0. معلومات السيرفر والشبكة المحلية (Server Info & Local IP for Mobile)
  if (req.method === 'GET' && pathname === '/api/info') {
    const localIp = getLocalIp();
    return sendJson(200, {
      status: 'online',
      port: PORT,
      localIp: localIp,
      networkUrl: `http://${localIp}:${PORT}`,
      version: '2.0.0'
    });
  }

  // 1. تسجيل مستخدم جديد
  if (req.method === 'POST' && pathname === '/api/register') {
    try {
      const { username, password, fullName } = await readBody();
      if (!username || !password) {
        return sendJson(400, { error: 'اسم المستخدم وكلمة المرور مطلوبان' });
      }

      const cleanUsername = username.trim().toLowerCase();
      if (cleanUsername.length < 3) {
        return sendJson(400, { error: 'اسم المستخدم يجب أن يكون 3 أحرف على الأقل' });
      }
      if (password.length < 4) {
        return sendJson(400, { error: 'كلمة المرور يجب أن تكون 4 أحرف على الأقل' });
      }

      const users = readJson(USERS_FILE, {});
      if (users[cleanUsername]) {
        return sendJson(400, { error: 'اسم المستخدم هذا مسجل مسبقاً، يرجى اختيار اسم آخر أو تسجيل الدخول' });
      }

      const { hash, salt } = hashPassword(password);
      const userId = 'usr_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');

      users[cleanUsername] = {
        id: userId,
        username: cleanUsername,
        fullName: (fullName || username).trim(),
        hash,
        salt,
        createdAt: Date.now()
      };

      writeJson(USERS_FILE, users);

      const sessionToken = createSession(userId);
      return sendJson(201, {
        message: 'تم إنشاء الحساب بنجاح',
        token: sessionToken,
        user: { id: userId, username: cleanUsername, fullName: users[cleanUsername].fullName }
      });
    } catch (err) {
      console.error(err);
      return sendJson(500, { error: 'حدث خطأ في الخادم أثناء إنشاء الحساب' });
    }
  }

  // 2. تسجيل الدخول
  if (req.method === 'POST' && pathname === '/api/login') {
    try {
      const { username, password } = await readBody();
      if (!username || !password) {
        return sendJson(400, { error: 'يرجى إدخال اسم المستخدم وكلمة المرور' });
      }

      const cleanUsername = username.trim().toLowerCase();
      const users = readJson(USERS_FILE, {});
      const user = users[cleanUsername];

      if (!user || !verifyPassword(password, user.hash, user.salt)) {
        return sendJson(401, { error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
      }

      const sessionToken = createSession(user.id);
      return sendJson(200, {
        message: 'تم تسجيل الدخول بنجاح',
        token: sessionToken,
        user: { id: user.id, username: user.username, fullName: user.fullName }
      });
    } catch (err) {
      console.error(err);
      return sendJson(500, { error: 'حدث خطأ أثناء تسجيل الدخول' });
    }
  }

  // 3. التحقق من المستخدم الحالي (Me)
  if (req.method === 'GET' && pathname === '/api/me') {
    if (!currentUserId) {
      return sendJson(401, { error: 'غير مسجل الدخول' });
    }
    const users = readJson(USERS_FILE, {});
    const user = Object.values(users).find(u => u.id === currentUserId);
    if (!user) {
      return sendJson(404, { error: 'المستخدم غير موجود' });
    }
    return sendJson(200, {
      user: { id: user.id, username: user.username, fullName: user.fullName }
    });
  }

  // 4. تسجيل الخروج
  if (req.method === 'POST' && pathname === '/api/logout') {
    if (token) deleteSession(token);
    return sendJson(200, { message: 'تم تسجيل الخروج بنجاح' });
  }

  // 5. جلب حسابات المستخدم الحالي فقط (Protected)
  if (req.method === 'GET' && pathname === '/api/accounts') {
    if (!currentUserId) {
      return sendJson(401, { error: 'يرجى تسجيل الدخول للوصول لحساباتك' });
    }
    const store = readJson(ACCOUNTS_FILE, {});
    const userAccounts = store[currentUserId] || [];
    return sendJson(200, { accounts: userAccounts });
  }

  // 6. إضافة أو تحديث حساب للمستخدم الحالي (Protected)
  if (req.method === 'POST' && pathname === '/api/accounts') {
    if (!currentUserId) {
      return sendJson(401, { error: 'يرجى تسجيل الدخول' });
    }
    try {
      const accountData = await readBody();
      if (!accountData.title || !accountData.username || !accountData.password) {
        return sendJson(400, { error: 'الحقول الإلزامية غير مكتملة' });
      }

      const store = readJson(ACCOUNTS_FILE, {});
      let userAccounts = store[currentUserId] || [];

      if (!accountData.id) {
        accountData.id = 'acc_' + Date.now() + '_' + crypto.randomBytes(3).toString('hex');
        accountData.createdAt = Date.now();
        accountData.updatedAt = Date.now();
        userAccounts.unshift(accountData);
      } else {
        const index = userAccounts.findIndex(a => a.id === accountData.id);
        accountData.updatedAt = Date.now();
        if (index >= 0) {
          userAccounts[index] = { ...userAccounts[index], ...accountData };
        } else {
          accountData.createdAt = Date.now();
          userAccounts.unshift(accountData);
        }
      }

      store[currentUserId] = userAccounts;
      writeJson(ACCOUNTS_FILE, store);

      return sendJson(200, { message: 'تم حفظ الحساب بنجاح', account: accountData });
    } catch (err) {
      console.error(err);
      return sendJson(500, { error: 'حدث خطأ أثناء حفظ الحساب' });
    }
  }

  // 7. حذف حساب خاص بالمستخدم الحالي
  if (req.method === 'DELETE' && pathname.startsWith('/api/accounts/')) {
    if (!currentUserId) {
      return sendJson(401, { error: 'يرجى تسجيل الدخول' });
    }
    const accId = pathname.replace('/api/accounts/', '');
    const store = readJson(ACCOUNTS_FILE, {});
    let userAccounts = store[currentUserId] || [];
    userAccounts = userAccounts.filter(a => a.id !== accId);
    store[currentUserId] = userAccounts;
    writeJson(ACCOUNTS_FILE, store);
    return sendJson(200, { message: 'تم حذف الحساب بنجاح' });
  }

  // 8. تصدير كافة بيانات المستخدم الحالي
  if (req.method === 'GET' && pathname === '/api/export') {
    if (!currentUserId) {
      return sendJson(401, { error: 'يرجى تسجيل الدخول' });
    }
    const store = readJson(ACCOUNTS_FILE, {});
    const userAccounts = store[currentUserId] || [];
    return sendJson(200, {
      exportedAt: new Date().toISOString(),
      version: '2.0',
      accounts: userAccounts
    });
  }

  // 9. استيراد حسابات للمستخدم الحالي
  if (req.method === 'POST' && pathname === '/api/import') {
    if (!currentUserId) {
      return sendJson(401, { error: 'يرجى تسجيل الدخول' });
    }
    try {
      const { accounts } = await readBody();
      if (!Array.isArray(accounts)) {
        return sendJson(400, { error: 'صيغة البيانات غير صحيحة' });
      }

      const store = readJson(ACCOUNTS_FILE, {});
      let userAccounts = store[currentUserId] || [];

      for (const item of accounts) {
        if (item.title && item.username && item.password) {
          const existingIdx = userAccounts.findIndex(a => a.id === item.id);
          if (existingIdx >= 0) {
            userAccounts[existingIdx] = { ...userAccounts[existingIdx], ...item };
          } else {
            userAccounts.push({
              ...item,
              id: item.id || ('acc_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6)),
              createdAt: item.createdAt || Date.now()
            });
          }
        }
      }

      store[currentUserId] = userAccounts;
      writeJson(ACCOUNTS_FILE, store);
      return sendJson(200, { message: 'تم استيراد الحسابات بنجاح', count: accounts.length });
    } catch (err) {
      console.error(err);
      return sendJson(500, { error: 'حدث خطأ أثناء استيراد البيانات' });
    }
  }

  // ==========================================
  // خدمة الملفات الثابتة (Static Files)
  // ==========================================
  let filePath = path.join(__dirname, pathname === '/' ? 'index.html' : pathname);
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('الملف غير موجود 404');
      } else {
        res.writeHead(500);
        res.end(`Server Error: ${err.code}`);
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    }
  });
});

// بدء تشغيل الخادم
server.listen(PORT, '0.0.0.0', () => {
  const localIp = getLocalIp();
  console.log('========================================================');
  console.log(`🔐 خزينة الحسابات السحابية تعمل بنجاح!`);
  console.log(`💻 على هذا الجهاز:     http://localhost:${PORT}`);
  console.log(`📱 من الجوال / الأجهزة الأخرى على نفس الشبكة:`);
  console.log(`   http://${localIp}:${PORT}`);
  console.log('========================================================');
});

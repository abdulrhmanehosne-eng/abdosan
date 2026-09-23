/**
 * خزينة الحسابات السحابية المتعددة | Account Vault
 * تطبيق وخادم متكامل لحفظ وإدارة ومزامنة الحسابات والصور بين الأجهزة مع عزل تام لبيانات كل مستخدم
 */

// ==========================================
// 0. محرك المزامنة السحابية والـ API (Vault Cloud API Engine)
// ==========================================
const API_BASE = window.location.origin;
const TOKEN_KEY = 'vault_cloud_session_token';
const USER_KEY = 'vault_cloud_user_profile';

class VaultAPI {
  static getToken() {
    return localStorage.getItem(TOKEN_KEY) || '';
  }

  static setToken(token) {
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  }

  static async request(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const token = this.getToken();
    const headers = {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...(options.headers || {})
    };

    const res = await fetch(url, { ...options, headers });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || `خطأ في الاتصال بالخادم (${res.status})`);
    }
    return data;
  }

  static async getInfo() {
    return this.request('/api/info');
  }

  static async register(username, password, fullName) {
    return this.request('/api/register', {
      method: 'POST',
      body: JSON.stringify({ username, password, fullName })
    });
  }

  static async login(username, password) {
    return this.request('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });
  }

  static async me() {
    return this.request('/api/me');
  }

  static async logout() {
    try {
      await this.request('/api/logout', { method: 'POST' });
    } catch (e) {
      // تجاهل إذا كان الخادم غير متصل
    }
    this.setToken('');
    localStorage.removeItem(USER_KEY);
  }

  static async getAccounts() {
    const res = await this.request('/api/accounts');
    return res.accounts || [];
  }

  static async saveAccount(account) {
    const res = await this.request('/api/accounts', {
      method: 'POST',
      body: JSON.stringify(account)
    });
    return res.account || account;
  }

  static async deleteAccount(accountId) {
    return this.request(`/api/accounts/${encodeURIComponent(accountId)}`, {
      method: 'DELETE'
    });
  }

  static async exportData() {
    return this.request('/api/export');
  }

  static async importData(accounts) {
    return this.request('/api/import', {
      method: 'POST',
      body: JSON.stringify({ accounts })
    });
  }
}

// ==========================================
// 1. محرك التخزين المحلي الآمن (IndexedDB Fallback & Cache)
// ==========================================
const DB_NAME = 'LocalAccountVaultDB_v2';
const DB_VERSION = 1;

class LocalDB {
  static open() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = (e) => {
        const db = e.target.result;

        // متجر المستخدمين
        if (!db.objectStoreNames.contains('users')) {
          const userStore = db.createObjectStore('users', { keyPath: 'id' });
          userStore.createIndex('username', 'username', { unique: true });
        }

        // متجر الحسابات
        if (!db.objectStoreNames.contains('accounts')) {
          const accStore = db.createObjectStore('accounts', { keyPath: 'id' });
          accStore.createIndex('userId', 'userId', { unique: false });
          accStore.createIndex('title', 'title', { unique: false });
        }
      };

      request.onsuccess = (e) => resolve(e.target.result);
      request.onerror = (e) => reject(e.target.error);
    });
  }

  // --- دوال المستخدمين ---
  static async getUserByUsername(username) {
    const db = await this.open();
    return new Promise((resolve) => {
      const tx = db.transaction('users', 'readonly');
      const store = tx.objectStore('users');
      const index = store.index('username');
      const req = index.get(username.toLowerCase().trim());
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => resolve(null);
    });
  }

  static async getUserById(id) {
    const db = await this.open();
    return new Promise((resolve) => {
      const tx = db.transaction('users', 'readonly');
      const store = tx.objectStore('users');
      const req = store.get(id);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => resolve(null);
    });
  }

  static async saveUser(user) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('users', 'readwrite');
      const store = tx.objectStore('users');
      const req = store.put(user);
      req.onsuccess = () => resolve(user);
      req.onerror = () => reject(req.error);
    });
  }

  // --- دوال الحسابات التابعة للمستخدم الحالي فقط ---
  static async getAccountsForUser(userId) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('accounts', 'readonly');
      const store = tx.objectStore('accounts');
      const index = store.index('userId');
      const req = index.getAll(userId);
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
  }

  static async saveAccount(account) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('accounts', 'readwrite');
      const store = tx.objectStore('accounts');
      const req = store.put(account);
      req.onsuccess = () => resolve(account);
      req.onerror = () => reject(req.error);
    });
  }

  static async deleteAccount(accountId) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('accounts', 'readwrite');
      const store = tx.objectStore('accounts');
      const req = store.delete(accountId);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }
}

// دالة تشفير وتجزئة كلمات المرور محلياً عبر Web Crypto API
async function hashPassword(string) {
  const utf8 = new TextEncoder().encode(string + '_vault_salt_secure_2026');
  const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ==========================================
// 2. حالة التطبيق والمستخدم
// ==========================================
let currentUser = null;
let accountsList = [];
let currentCategory = 'all';
let currentSearch = '';
let currentSort = 'newest';
let currentAvatarData = null;
let isPasswordVisibleInForm = false;

// ==========================================
// 3. عناصر واجهة المستخدم (DOM Elements)
// ==========================================
const authScreen = document.getElementById('authScreen');
const tabLogin = document.getElementById('tabLogin');
const tabRegister = document.getElementById('tabRegister');
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const loginUsernameInput = document.getElementById('loginUsername');
const loginPasswordInput = document.getElementById('loginPassword');
const regFullNameInput = document.getElementById('regFullName');
const regUsernameInput = document.getElementById('regUsername');
const regPasswordInput = document.getElementById('regPassword');
const authErrorMessage = document.getElementById('authErrorMessage');

// الشريط العلوي وبطاقة المستخدم
const userDisplayName = document.getElementById('userDisplayName');
const userDisplayUsername = document.getElementById('userDisplayUsername');
const userAvatarText = document.getElementById('userAvatarText');
const logoutBtn = document.getElementById('logoutBtn');

// شبكة الحسابات وعناصر التحكم
const accountsGrid = document.getElementById('accountsGrid');
const emptyState = document.getElementById('emptyState');
const searchInput = document.getElementById('searchInput');
const clearSearchBtn = document.getElementById('clearSearchBtn');
const categoryPills = document.getElementById('categoryPills');
const sortSelect = document.getElementById('sortSelect');

// الإحصائيات
const totalAccountsCount = document.getElementById('totalAccountsCount');
const socialAccountsCount = document.getElementById('socialAccountsCount');
const workAccountsCount = document.getElementById('workAccountsCount');
const financeAccountsCount = document.getElementById('financeAccountsCount');
const countAll = document.getElementById('countAll');

// نافذة إضافة وتعديل الحساب
const accountModal = document.getElementById('accountModal');
const modalTitle = document.getElementById('modalTitle');
const accountForm = document.getElementById('accountForm');
const accountIdInput = document.getElementById('accountId');
const accountTitleInput = document.getElementById('accountTitle');
const accountCategorySelect = document.getElementById('accountCategory');
const accountUsernameInput = document.getElementById('accountUsername');
const accountPasswordInput = document.getElementById('accountPassword');
const accountUrlInput = document.getElementById('accountUrl');
const accountNotesTextarea = document.getElementById('accountNotes');
const addAccountBtn = document.getElementById('addAccountBtn');
const emptyStateAddBtn = document.getElementById('emptyStateAddBtn');
const closeAccountModalBtn = document.getElementById('closeAccountModalBtn');
const cancelAccountBtn = document.getElementById('cancelAccountBtn');

// صورة الحساب
const avatarFileInput = document.getElementById('avatarFileInput');
const avatarPreviewImg = document.getElementById('avatarPreviewImg');
const avatarFallback = document.getElementById('avatarFallback');
const removeAvatarBtn = document.getElementById('removeAvatarBtn');
const presetLogoButtons = document.querySelectorAll('.preset-logo-btn');

// أدوات كلمة المرور
const togglePasswordVisibilityBtn = document.getElementById('togglePasswordVisibility');
const generatePasswordBtn = document.getElementById('generatePasswordBtn');
const strengthBar = document.getElementById('strengthBar');
const strengthText = document.getElementById('strengthText');

// النسخ الاحتياطي
const backupModalBtn = document.getElementById('backupModalBtn');
const backupModal = document.getElementById('backupModal');
const closeBackupModalBtn = document.getElementById('closeBackupModalBtn');
const exportDataBtn = document.getElementById('exportDataBtn');
const importFileInput = document.getElementById('importFileInput');

// نافذة عرض التفاصيل
const viewModal = document.getElementById('viewModal');
const closeViewModalBtn = document.getElementById('closeViewModalBtn');
const viewModalContent = document.getElementById('viewModalContent');

// حاوية التوست
const toastContainer = document.getElementById('toastContainer');

// ==========================================
// 4. تهيئة التطبيق والتحقق من الجلسة
// ==========================================
document.addEventListener('DOMContentLoaded', async () => {
  setupEventListeners();
  setupAuthTabs();
  initNetworkInfo();

  // فحص الجلسة السحابية الحالية عبر السيرفر
  const savedToken = VaultAPI.getToken();
  if (savedToken) {
    try {
      const res = await VaultAPI.me();
      if (res && res.user) {
        currentUser = res.user;
        localStorage.setItem(USER_KEY, JSON.stringify(currentUser));
        hideAuthScreen();
        updateUserHeader();
        await loadAccounts();
        return;
      }
    } catch (err) {
      console.warn('Session expired or invalid:', err);
      VaultAPI.setToken('');
      localStorage.removeItem(USER_KEY);
    }
  }

  // في حال كان هناك مستخدم محلي سابق ولم نكن متصلين بالسيرفر
  const savedUserId = localStorage.getItem('local_vault_active_user_id');
  if (savedUserId && !savedToken) {
    try {
      const user = await LocalDB.getUserById(savedUserId);
      if (user) {
        currentUser = user;
        hideAuthScreen();
        updateUserHeader();
        await loadAccounts();
        return;
      }
    } catch (e) {}
  }

  showAuthScreen();
});

async function initNetworkInfo() {
  const networkInfoText = document.getElementById('networkInfoText');
  if (!networkInfoText) return;

  try {
    const info = await VaultAPI.getInfo();
    if (info && info.status === 'online') {
      networkInfoText.innerHTML = `
        <i class="fa-solid fa-cloud-arrow-up text-emerald"></i>
        <span>متزامن سحابياً</span>
        <span class="mobile-ip-badge" id="mobileIpBadge" title="انقر لنسخ رابط الدخول من الجوال">
          <i class="fa-solid fa-mobile-screen"></i> ${info.networkUrl}
          <i class="fa-regular fa-copy"></i>
        </span>
      `;
      const badge = document.getElementById('mobileIpBadge');
      if (badge) {
        badge.addEventListener('click', () => {
          copyToClipboard(info.networkUrl, `تم نسخ رابط الدخول من الجوال: ${info.networkUrl}`);
        });
      }
    }
  } catch (err) {
    networkInfoText.innerHTML = `<i class="fa-solid fa-hard-drive"></i> وضع الخزينة`;
  }
}

function showAuthScreen() {
  authScreen.classList.remove('hidden');
  clearAuthErrors();
  setTimeout(() => loginUsernameInput.focus(), 100);
}

function hideAuthScreen() {
  authScreen.classList.add('hidden');
}

function updateUserHeader() {
  if (!currentUser) return;
  userDisplayName.textContent = currentUser.fullName || currentUser.username;
  userDisplayUsername.textContent = '@' + currentUser.username;
  const initial = (currentUser.fullName || currentUser.username).trim().charAt(0).toUpperCase();
  userAvatarText.textContent = initial;
}

// ==========================================
// 5. إدارة تسجيل الدخول وإنشاء الحساب محلياً
// ==========================================
function setupAuthTabs() {
  tabLogin.addEventListener('click', () => {
    tabLogin.classList.add('active');
    tabRegister.classList.remove('active');
    loginForm.classList.remove('hidden');
    registerForm.classList.add('hidden');
    clearAuthErrors();
    loginUsernameInput.focus();
  });

  tabRegister.addEventListener('click', () => {
    tabRegister.classList.add('active');
    tabLogin.classList.remove('active');
    registerForm.classList.remove('hidden');
    loginForm.classList.add('hidden');
    clearAuthErrors();
    regFullNameInput.focus();
  });

  // إظهار/إخفاء كلمة المرور في شاشة التسجيل
  document.querySelectorAll('.toggle-auth-pwd').forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.target;
      const input = document.getElementById(targetId);
      if (input) {
        const isShown = input.type === 'text';
        input.type = isShown ? 'password' : 'text';
        btn.innerHTML = isShown
          ? '<i class="fa-solid fa-eye"></i>'
          : '<i class="fa-solid fa-eye-slash"></i>';
      }
    });
  });

  // نموذج إنشاء حساب جديد (حفظ ومزامنة سحابية)
  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearAuthErrors();

    const fullName = regFullNameInput.value.trim();
    const rawUsername = regUsernameInput.value.trim().toLowerCase();
    const password = regPasswordInput.value;

    if (!rawUsername || !password) {
      showAuthError('يرجى ملء جميع الحقول المطلوبة');
      return;
    }

    if (rawUsername.length < 3) {
      showAuthError('اسم المستخدم يجب أن يكون 3 أحرف على الأقل');
      return;
    }

    if (password.length < 4) {
      showAuthError('كلمة المرور يجب أن تكون 4 خانات على الأقل');
      return;
    }

    const submitBtn = document.getElementById('regSubmitBtn');
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> جاري إنشاء الحساب...';
    }

    try {
      const res = await VaultAPI.register(rawUsername, password, fullName);
      if (res && res.token && res.user) {
        VaultAPI.setToken(res.token);
        currentUser = res.user;
        localStorage.setItem(USER_KEY, JSON.stringify(currentUser));
        hideAuthScreen();
        updateUserHeader();
        await loadAccounts();
        showToast(`تم إنشاء حسابك وحفظه سحابياً بنجاح يا ${res.user.fullName || res.user.username}! 🎉`, 'success');
        registerForm.reset();
      }
    } catch (err) {
      console.error(err);
      showAuthError(err.message || 'حدث خطأ أثناء إنشاء الحساب على السيرفر');
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fa-solid fa-user-check"></i> إنشاء الحساب وحفظ البيانات';
      }
    }
  });

  // نموذج تسجيل الدخول (مصادقة ومزامنة سحابية)
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearAuthErrors();

    const rawUsername = loginUsernameInput.value.trim().toLowerCase();
    const password = loginPasswordInput.value;

    if (!rawUsername || !password) {
      showAuthError('يرجى إدخال اسم المستخدم وكلمة المرور');
      return;
    }

    const submitBtn = document.getElementById('loginSubmitBtn');
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> جاري تسجيل الدخول...';
    }

    try {
      const res = await VaultAPI.login(rawUsername, password);
      if (res && res.token && res.user) {
        VaultAPI.setToken(res.token);
        currentUser = res.user;
        localStorage.setItem(USER_KEY, JSON.stringify(currentUser));
        hideAuthScreen();
        updateUserHeader();
        await loadAccounts();
        showToast(`مرحباً بك مجدداً يا ${res.user.fullName || res.user.username}! 👋`, 'success');
        loginForm.reset();
      }
    } catch (err) {
      console.error(err);
      showAuthError(err.message || 'اسم المستخدم أو كلمة المرور غير صحيحة');
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fa-solid fa-shield-halved"></i> دخول الخزينة';
      }
    }
  });
}

function showAuthError(msg) {
  authErrorMessage.textContent = msg;
  authErrorMessage.classList.remove('hidden');
}

function clearAuthErrors() {
  authErrorMessage.textContent = '';
  authErrorMessage.classList.add('hidden');
}

async function handleLogout() {
  try {
    await VaultAPI.logout();
  } catch (e) {}
  currentUser = null;
  accountsList = [];
  VaultAPI.setToken('');
  localStorage.removeItem(USER_KEY);
  localStorage.removeItem('local_vault_active_user_id');
  showAuthScreen();
  renderAccounts();
  updateStats();
  showToast('تم تسجيل الخروج بنجاح', 'info');
}

logoutBtn.addEventListener('click', () => {
  if (confirm('هل ترغب بتسجيل الخروج من خزينتك الشخصية؟')) {
    handleLogout();
  }
});

// ==========================================
// 6. تحميل وعرض حسابات المستخدم الحالي فقط
// ==========================================
async function loadAccounts() {
  if (!currentUser) return;
  try {
    accountsList = await VaultAPI.getAccounts();
    // Cache to LocalDB
    try {
      for (const acc of accountsList) {
        await LocalDB.saveAccount(acc);
      }
    } catch (e) {}
    updateStats();
    renderAccounts();
  } catch (err) {
    console.error('Error fetching accounts from server:', err);
    try {
      accountsList = await LocalDB.getAccountsForUser(currentUser.id);
      updateStats();
      renderAccounts();
      showToast('تم تحميل الحسابات من الذاكرة الاحتياطية', 'warning');
    } catch (dbErr) {
      showToast('حدث خطأ أثناء تحميل بيانات الحسابات', 'error');
    }
  }
}

function renderAccounts() {
  accountsGrid.innerHTML = '';

  // التصفية والبحث
  let filtered = accountsList.filter((acc) => {
    const matchesCat = currentCategory === 'all' || acc.category === currentCategory;
    const term = currentSearch.toLowerCase();
    const matchesSearch =
      !term ||
      acc.title.toLowerCase().includes(term) ||
      acc.username.toLowerCase().includes(term) ||
      (acc.notes && acc.notes.toLowerCase().includes(term)) ||
      (acc.url && acc.url.toLowerCase().includes(term));
    return matchesCat && matchesSearch;
  });

  // الترتيب
  filtered.sort((a, b) => {
    if (currentSort === 'newest') return b.createdAt - a.createdAt;
    if (currentSort === 'oldest') return a.createdAt - b.createdAt;
    if (currentSort === 'nameAsc') return a.title.localeCompare(b.title, 'ar');
    if (currentSort === 'nameDesc') return b.title.localeCompare(a.title, 'ar');
    return 0;
  });

  if (filtered.length === 0) {
    emptyState.classList.remove('hidden');
    accountsGrid.classList.add('hidden');
    return;
  }

  emptyState.classList.add('hidden');
  accountsGrid.classList.remove('hidden');

  filtered.forEach((acc) => {
    const card = createAccountCard(acc);
    accountsGrid.appendChild(card);
  });
}

function createAccountCard(acc) {
  const card = document.createElement('div');
  card.className = 'account-card';
  card.dataset.id = acc.id;

  const categoryLabels = {
    social: { text: 'تواصل اجتماعي', class: 'cat-social', icon: 'fa-share-nodes' },
    work: { text: 'عمل ودراسة', class: 'cat-work', icon: 'fa-briefcase' },
    finance: { text: 'مالية وبنوك', class: 'cat-finance', icon: 'fa-wallet' },
    gaming: { text: 'ألعاب', class: 'cat-gaming', icon: 'fa-gamepad' },
    entertainment: { text: 'ترفيه وميديا', class: 'cat-entertainment', icon: 'fa-film' },
    personal: { text: 'شخصي', class: 'cat-personal', icon: 'fa-user' },
    other: { text: 'أخرى', class: 'cat-other', icon: 'fa-tag' }
  };

  const catInfo = categoryLabels[acc.category] || categoryLabels.other;
  const avatarHtml = getAvatarMarkup(acc.avatar, acc.title);

  card.innerHTML = `
    <div class="card-header">
      <div class="card-avatar-wrapper">
        <div class="account-avatar">
          ${avatarHtml}
        </div>
        <div class="card-title-group">
          <h3 title="${escapeHtml(acc.title)}">${escapeHtml(acc.title)}</h3>
          <span class="category-tag ${catInfo.class}">
            <i class="fa-solid ${catInfo.icon}"></i> ${catInfo.text}
          </span>
        </div>
      </div>
      <div class="card-actions-quick">
        <button class="action-btn-sm view-btn" title="عرض التفاصيل" data-id="${acc.id}">
          <i class="fa-regular fa-eye"></i>
        </button>
        <button class="action-btn-sm edit-btn" title="تعديل الحساب" data-id="${acc.id}">
          <i class="fa-solid fa-pen-to-square"></i>
        </button>
        <button class="action-btn-sm delete-btn" title="حذف الحساب" data-id="${acc.id}">
          <i class="fa-solid fa-trash-can"></i>
        </button>
      </div>
    </div>

    <div class="card-body">
      <!-- اسم المستخدم -->
      <div class="field-row">
        <div class="field-info">
          <i class="fa-solid fa-user-tag field-icon"></i>
          <span class="field-value" title="${escapeHtml(acc.username)}">${escapeHtml(acc.username)}</span>
        </div>
        <button class="copy-btn copy-username" data-text="${escapeHtml(acc.username)}" title="نسخ اسم المستخدم">
          <i class="fa-regular fa-copy"></i>
        </button>
      </div>

      <!-- كلمة المرور -->
      <div class="field-row">
        <div class="field-info">
          <i class="fa-solid fa-key field-icon"></i>
          <span class="field-value password-value" id="pwd-${acc.id}">••••••••••••</span>
        </div>
        <div style="display: flex; gap: 0.3rem;">
          <button class="copy-btn toggle-card-pwd" data-id="${acc.id}" data-pwd="${escapeHtml(acc.password)}" title="إظهار/إخفاء">
            <i class="fa-regular fa-eye"></i>
          </button>
          <button class="copy-btn copy-password" data-text="${escapeHtml(acc.password)}" title="نسخ كلمة المرور">
            <i class="fa-solid fa-copy"></i>
          </button>
        </div>
      </div>
    </div>

    <div class="card-footer">
      ${
        acc.url
          ? `
        <a href="${escapeHtml(acc.url)}" target="_blank" rel="noopener noreferrer" class="site-link">
          <i class="fa-solid fa-arrow-up-right-from-square"></i> فتح الموقع
        </a>
      `
          : `<span><i class="fa-regular fa-clock"></i> ${formatDate(acc.createdAt)}</span>`
      }

      ${
        acc.notes
          ? `
        <span title="يحتوي على ملاحظات إضافية" style="color: var(--accent-cyan);">
          <i class="fa-solid fa-file-lines"></i> ملاحظات
        </span>
      `
          : ''
      }
    </div>
  `;

  // ربط الأحداث داخل البطاقة
  card.querySelector('.view-btn').addEventListener('click', () => showViewModal(acc));
  card.querySelector('.edit-btn').addEventListener('click', () => openEditAccountModal(acc));
  card.querySelector('.delete-btn').addEventListener('click', () => confirmDeleteAccount(acc));

  // نسخ اسم المستخدم
  card.querySelector('.copy-username').addEventListener('click', (e) => {
    e.stopPropagation();
    copyToClipboard(acc.username, 'تم نسخ اسم المستخدم!');
  });

  // نسخ كلمة المرور
  card.querySelector('.copy-password').addEventListener('click', (e) => {
    e.stopPropagation();
    copyToClipboard(acc.password, 'تم نسخ كلمة المرور بنجاح! 🔒');
  });

  // إظهار/إخفاء كلمة المرور في البطاقة
  const togglePwdBtn = card.querySelector('.toggle-card-pwd');
  const pwdField = card.querySelector(`#pwd-${acc.id}`);
  let isCardPwdShown = false;
  togglePwdBtn.addEventListener('click', () => {
    isCardPwdShown = !isCardPwdShown;
    if (isCardPwdShown) {
      pwdField.textContent = acc.password;
      pwdField.classList.remove('password-value');
      togglePwdBtn.innerHTML = '<i class="fa-regular fa-eye-slash"></i>';
    } else {
      pwdField.textContent = '••••••••••••';
      pwdField.classList.add('password-value');
      togglePwdBtn.innerHTML = '<i class="fa-regular fa-eye"></i>';
    }
  });

  return card;
}

// توليد صورة أو أيقونة الحساب
function getAvatarMarkup(avatar, title) {
  if (avatar && avatar.startsWith('data:image/')) {
    return `<img src="${avatar}" alt="${escapeHtml(title)}">`;
  }

  const presetIcons = {
    'preset:google': '<i class="fa-brands fa-google" style="color: #ea4335;"></i>',
    'preset:facebook': '<i class="fa-brands fa-facebook" style="color: #1877f2;"></i>',
    'preset:twitter': '<i class="fa-brands fa-x-twitter" style="color: #ffffff;"></i>',
    'preset:instagram': '<i class="fa-brands fa-instagram" style="color: #e1306c;"></i>',
    'preset:tiktok': '<i class="fa-brands fa-tiktok" style="color: #00f2fe;"></i>',
    'preset:github': '<i class="fa-brands fa-github" style="color: #ffffff;"></i>',
    'preset:discord': '<i class="fa-brands fa-discord" style="color: #5865f2;"></i>',
    'preset:telegram': '<i class="fa-brands fa-telegram" style="color: #24a1de;"></i>',
    'preset:whatsapp': '<i class="fa-brands fa-whatsapp" style="color: #25d366;"></i>',
    'preset:apple': '<i class="fa-brands fa-apple" style="color: #ffffff;"></i>',
    'preset:microsoft': '<i class="fa-brands fa-microsoft" style="color: #00a4ef;"></i>',
    'preset:youtube': '<i class="fa-brands fa-youtube" style="color: #ff0000;"></i>',
    'preset:netflix': '<i class="fa-solid fa-tv" style="color: #e50914;"></i>',
    'preset:spotify': '<i class="fa-brands fa-spotify" style="color: #1db954;"></i>',
    'preset:steam': '<i class="fa-brands fa-steam" style="color: #66c0f4;"></i>',
    'preset:bank': '<i class="fa-solid fa-building-columns" style="color: #f59e0b;"></i>'
  };

  if (avatar && presetIcons[avatar]) {
    return presetIcons[avatar];
  }

  const initial = title ? title.trim().charAt(0).toUpperCase() : '?';
  return `<span style="font-weight: 800; font-size: 1.25rem; color: #fff;">${escapeHtml(initial)}</span>`;
}

// تحديث لوحة الإحصائيات
function updateStats() {
  const total = accountsList.length;
  const social = accountsList.filter((a) => a.category === 'social').length;
  const work = accountsList.filter((a) => a.category === 'work').length;
  const finance = accountsList.filter((a) => a.category === 'finance').length;

  totalAccountsCount.textContent = total;
  socialAccountsCount.textContent = social;
  workAccountsCount.textContent = work;
  financeAccountsCount.textContent = finance;
  countAll.textContent = total;
}

// ==========================================
// 7. إدارة الحسابات مع منع تكرار الأسماء
// ==========================================
function openAddAccountModal() {
  accountForm.reset();
  accountIdInput.value = '';
  modalTitle.innerHTML = '<i class="fa-solid fa-circle-plus"></i> إضافة حساب جديد';
  currentAvatarData = null;
  resetAvatarPreview();
  resetPasswordStrength();
  accountModal.classList.remove('hidden');
  setTimeout(() => accountTitleInput.focus(), 100);
}

function openEditAccountModal(acc) {
  accountForm.reset();
  modalTitle.innerHTML = '<i class="fa-solid fa-pen-to-square"></i> تعديل بيانات الحساب';
  accountIdInput.value = acc.id;
  accountTitleInput.value = acc.title;
  accountCategorySelect.value = acc.category;
  accountUsernameInput.value = acc.username;
  accountPasswordInput.value = acc.password;
  accountUrlInput.value = acc.url || '';
  accountNotesTextarea.value = acc.notes || '';

  currentAvatarData = acc.avatar || null;
  updateAvatarPreview(currentAvatarData);
  checkPasswordStrength(acc.password);

  accountModal.classList.remove('hidden');
  setTimeout(() => accountTitleInput.focus(), 100);
}

function closeAccountModal() {
  accountModal.classList.add('hidden');
}

// حفظ الحساب مع التحقق الدقيق من منع تكرار اسم الحساب
accountForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  if (!currentUser) {
    showToast('يرجى تسجيل الدخول أولاً', 'error');
    return;
  }

  const title = accountTitleInput.value.trim();
  const category = accountCategorySelect.value;
  const username = accountUsernameInput.value.trim();
  const password = accountPasswordInput.value;
  const url = accountUrlInput.value.trim();
  const notes = accountNotesTextarea.value.trim();
  const existingId = accountIdInput.value;

  if (!title || !username || !password) {
    showToast('يرجى ملء كافة الحقول الإلزامية المطلوبة', 'error');
    return;
  }

  // منع تكرار اسم الحساب لنفس المستخدم (Case-insensitive)
  const isDuplicateTitle = accountsList.some(
    (acc) =>
      acc.id !== existingId &&
      acc.title.trim().toLowerCase() === title.toLowerCase()
  );

  if (isDuplicateTitle) {
    showToast(`عذراً، لديك حساب مسجل مسبقاً باسم "${title}"! يرجى اختيار اسم مختلف.`, 'error');
    accountTitleInput.focus();
    accountTitleInput.classList.add('shake');
    setTimeout(() => accountTitleInput.classList.remove('shake'), 400);
    return;
  }

  const accountData = {
    id: existingId || 'acc_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
    userId: currentUser.id,
    title,
    category,
    username,
    password,
    url,
    notes,
    avatar: currentAvatarData,
    createdAt: existingId
      ? accountsList.find((a) => a.id === existingId)?.createdAt || Date.now()
      : Date.now(),
    updatedAt: Date.now()
  };

  try {
    await VaultAPI.saveAccount(accountData);
    try { await LocalDB.saveAccount(accountData); } catch (e) {}
    await loadAccounts();
    closeAccountModal();
    showToast(
      existingId
        ? 'تم تحديث بيانات الحساب وحفظها سحابياً بنجاح! ✨'
        : 'تم حفظ الحساب وصورته سحابياً بنجاح! 🎉',
      'success'
    );
  } catch (err) {
    console.error('Error saving account:', err);
    showToast(err.message || 'حدث خطأ أثناء حفظ الحساب على السيرفر', 'error');
  }
});

// حذف حساب
async function confirmDeleteAccount(acc) {
  if (confirm(`هل أنت متأكد من رغبتك في حذف حساب "${acc.title}"؟ لا يمكن التراجع عن هذه الخطوة.`)) {
    try {
      await VaultAPI.deleteAccount(acc.id);
      try { await LocalDB.deleteAccount(acc.id); } catch (e) {}
      await loadAccounts();
      showToast('تم حذف الحساب بنجاح من السيرفر', 'info');
    } catch (err) {
      console.error('Error deleting account:', err);
      showToast(err.message || 'تعذر حذف الحساب من السيرفر', 'error');
    }
  }
}

// ==========================================
// 8. معالجة ورفع وضغط صورة الحساب
// ==========================================
avatarFileInput.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (!file) return;

  if (!file.type.startsWith('image/')) {
    showToast('يرجى اختيار ملف صورة صالح (PNG, JPG, WebP)', 'error');
    return;
  }

  const reader = new FileReader();
  reader.onload = (event) => {
    compressImage(event.target.result, 320, 320, 0.85, (compressedDataUrl) => {
      currentAvatarData = compressedDataUrl;
      updateAvatarPreview(currentAvatarData);
      showToast('تم إرفاق صورة الحساب بنجاح! 📸', 'success');
    });
  };
  reader.readAsDataURL(file);
});

function compressImage(base64Str, maxWidth, maxHeight, quality, callback) {
  const img = new Image();
  img.src = base64Str;
  img.onload = () => {
    const canvas = document.createElement('canvas');
    let width = img.width;
    let height = img.height;

    if (width > height) {
      if (width > maxWidth) {
        height = Math.round((height * maxWidth) / width);
        width = maxWidth;
      }
    } else {
      if (height > maxHeight) {
        width = Math.round((width * maxHeight) / height);
        height = maxHeight;
      }
    }

    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0, width, height);

    const dataUrl = canvas.toDataURL('image/webp', quality);
    callback(dataUrl);
  };
}

function updateAvatarPreview(avatar) {
  if (!avatar) {
    resetAvatarPreview();
    return;
  }

  if (avatar.startsWith('data:image/')) {
    avatarPreviewImg.src = avatar;
    avatarPreviewImg.classList.remove('hidden');
    avatarFallback.classList.add('hidden');
    removeAvatarBtn.classList.remove('hidden');
  } else if (avatar.startsWith('preset:')) {
    avatarPreviewImg.classList.add('hidden');
    avatarFallback.innerHTML = getAvatarMarkup(avatar, '');
    avatarFallback.classList.remove('hidden');
    removeAvatarBtn.classList.remove('hidden');
  }
}

function resetAvatarPreview() {
  currentAvatarData = null;
  avatarPreviewImg.src = '';
  avatarPreviewImg.classList.add('hidden');
  avatarFallback.innerHTML = '<i class="fa-solid fa-camera"></i><span>اختر صورة</span>';
  avatarFallback.classList.remove('hidden');
  removeAvatarBtn.classList.add('hidden');
  avatarFileInput.value = '';
}

removeAvatarBtn.addEventListener('click', () => {
  resetAvatarPreview();
});

presetLogoButtons.forEach((btn) => {
  btn.addEventListener('click', () => {
    const preset = btn.dataset.preset;
    currentAvatarData = `preset:${preset}`;
    updateAvatarPreview(currentAvatarData);
  });
});

// ==========================================
// 9. أدوات وتوليد كلمات المرور وفحص قوتها
// ==========================================
togglePasswordVisibilityBtn.addEventListener('click', () => {
  isPasswordVisibleInForm = !isPasswordVisibleInForm;
  accountPasswordInput.type = isPasswordVisibleInForm ? 'text' : 'password';
  togglePasswordVisibilityBtn.innerHTML = isPasswordVisibleInForm
    ? '<i class="fa-solid fa-eye-slash"></i>'
    : '<i class="fa-solid fa-eye"></i>';
});

generatePasswordBtn.addEventListener('click', () => {
  const length = 16;
  const uppercase = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lowercase = 'abcdefghijkmnpqrstuvwxyz';
  const numbers = '23456789';
  const symbols = '!@#$%^&*()_+~|}{[]:?><';
  const allChars = uppercase + lowercase + numbers + symbols;

  let pwd = '';
  pwd += uppercase[Math.floor(Math.random() * uppercase.length)];
  pwd += lowercase[Math.floor(Math.random() * lowercase.length)];
  pwd += numbers[Math.floor(Math.random() * numbers.length)];
  pwd += symbols[Math.floor(Math.random() * symbols.length)];

  for (let i = 4; i < length; i++) {
    pwd += allChars[Math.floor(Math.random() * allChars.length)];
  }

  pwd = pwd.split('').sort(() => 0.5 - Math.random()).join('');

  accountPasswordInput.value = pwd;
  accountPasswordInput.type = 'text';
  isPasswordVisibleInForm = true;
  togglePasswordVisibilityBtn.innerHTML = '<i class="fa-solid fa-eye-slash"></i>';
  checkPasswordStrength(pwd);
  showToast('تم توليد كلمة مرور قوية جداً!', 'success');
});

accountPasswordInput.addEventListener('input', (e) => {
  checkPasswordStrength(e.target.value);
});

function checkPasswordStrength(pwd) {
  if (!pwd) {
    resetPasswordStrength();
    return;
  }

  let score = 0;
  if (pwd.length >= 8) score++;
  if (pwd.length >= 12) score++;
  if (/[A-Z]/.test(pwd)) score++;
  if (/[a-z]/.test(pwd)) score++;
  if (/[0-9]/.test(pwd)) score++;
  if (/[^A-Za-z0-9]/.test(pwd)) score++;

  if (score <= 2) {
    strengthBar.style.width = '25%';
    strengthBar.style.backgroundColor = '#f43f5e';
    strengthText.textContent = 'ضعيفة ⚠️';
    strengthText.style.color = '#f43f5e';
  } else if (score <= 4) {
    strengthBar.style.width = '60%';
    strengthBar.style.backgroundColor = '#f59e0b';
    strengthText.textContent = 'متوسطة ⚡';
    strengthText.style.color = '#f59e0b';
  } else {
    strengthBar.style.width = '100%';
    strengthBar.style.backgroundColor = '#10b981';
    strengthText.textContent = 'قوية جداً 🛡️';
    strengthText.style.color = '#10b981';
  }
}

function resetPasswordStrength() {
  strengthBar.style.width = '0%';
  strengthText.textContent = 'قوة كلمة المرور';
  strengthText.style.color = 'var(--text-dim)';
}

// ==========================================
// 10. نافذة عرض التفاصيل الكاملة
// ==========================================
function showViewModal(acc) {
  const avatarHtml = getAvatarMarkup(acc.avatar, acc.title);
  viewModalContent.innerHTML = `
    <div class="view-header">
      <div class="account-avatar view-avatar">
        ${avatarHtml}
      </div>
      <div class="view-title-group">
        <h2>${escapeHtml(acc.title)}</h2>
        <span class="category-tag cat-${acc.category}">${escapeHtml(acc.category)}</span>
      </div>
    </div>

    <div class="view-fields">
      <div class="view-row">
        <span class="view-row-label">اسم المستخدم / الإيميل:</span>
        <div class="view-row-value">
          <span>${escapeHtml(acc.username)}</span>
          <button class="copy-btn copy-view-user" title="نسخ"><i class="fa-regular fa-copy"></i></button>
        </div>
      </div>

      <div class="view-row">
        <span class="view-row-label">كلمة المرور:</span>
        <div class="view-row-value">
          <span id="viewPwdText">${escapeHtml(acc.password)}</span>
          <button class="copy-btn copy-view-pwd" title="نسخ كلمة المرور"><i class="fa-solid fa-copy"></i></button>
        </div>
      </div>

      ${
        acc.url
          ? `
        <div class="view-row">
          <span class="view-row-label">رابط الموقع:</span>
          <div class="view-row-value">
            <a href="${escapeHtml(acc.url)}" target="_blank" class="site-link">
              ${escapeHtml(acc.url)} <i class="fa-solid fa-arrow-up-right-from-square"></i>
            </a>
          </div>
        </div>
      `
          : ''
      }

      ${
        acc.notes
          ? `
        <div class="view-row">
          <span class="view-row-label">ملاحظات ومعلومات إضافية:</span>
          <div class="view-notes-box">${escapeHtml(acc.notes)}</div>
        </div>
      `
          : ''
      }

      <div class="view-row">
        <span class="view-row-label">تاريخ الإضافة:</span>
        <span style="font-size: 0.85rem; color: var(--text-muted);">${formatDate(acc.createdAt)}</span>
      </div>
    </div>
  `;

  viewModalContent.querySelector('.copy-view-user').addEventListener('click', () => {
    copyToClipboard(acc.username, 'تم نسخ اسم المستخدم!');
  });
  viewModalContent.querySelector('.copy-view-pwd').addEventListener('click', () => {
    copyToClipboard(acc.password, 'تم نسخ كلمة المرور!');
  });

  viewModal.classList.remove('hidden');
}

// ==========================================
// 11. النسخ الاحتياطي والاستعادة ونقل البيانات بين الأجهزة
// ==========================================
exportDataBtn.addEventListener('click', async () => {
  if (!currentUser) return;
  try {
    let backupObj;
    try {
      const res = await VaultAPI.exportData();
      backupObj = {
        version: '2.0_cloud',
        exportedAt: res.exportedAt || new Date().toISOString(),
        user: {
          username: currentUser.username,
          fullName: currentUser.fullName
        },
        accounts: res.accounts || accountsList
      };
    } catch (apiErr) {
      backupObj = {
        version: '2.0_local',
        exportedAt: new Date().toISOString(),
        user: {
          username: currentUser.username,
          fullName: currentUser.fullName
        },
        accounts: accountsList
      };
    }

    const dataStr =
      'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(backupObj, null, 2));
    const downloadAnchor = document.createElement('a');
    const dateStr = new Date().toISOString().slice(0, 10);
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute(
      'download',
      `AccountVault_${currentUser.username}_${dateStr}.json`
    );
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();

    showToast('تم تحميل نسخة بياناتك وصورك بنجاح! 💾', 'success');
    backupModal.classList.add('hidden');
  } catch (err) {
    console.error('Backup error:', err);
    showToast('حدث خطأ أثناء تصدير البيانات', 'error');
  }
});

importFileInput.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (!file || !currentUser) return;

  const reader = new FileReader();
  reader.onload = async (event) => {
    try {
      const parsed = JSON.parse(event.target.result);
      const importedAccounts = parsed.accounts || (Array.isArray(parsed) ? parsed : null);

      if (!importedAccounts || !Array.isArray(importedAccounts)) {
        showToast('ملف النسخة الاحتياطية غير صالح أو تالف', 'error');
        return;
      }

      if (
        confirm(
          `تم العثور على (${importedAccounts.length}) حساب. هل ترغب باستيرادها ومزامنتها مع حسابك (${currentUser.fullName})؟`
        )
      ) {
        try {
          const res = await VaultAPI.importData(importedAccounts);
          await loadAccounts();
          backupModal.classList.add('hidden');
          showToast(`تم استيراد ومزامنة (${res.count || importedAccounts.length}) حساب بنجاح! 🎉`, 'success');
        } catch (apiErr) {
          // محاولة حفظ فردية
          for (const item of importedAccounts) {
            if (item.title && item.username && item.password) {
              await VaultAPI.saveAccount({
                ...item,
                userId: currentUser.id
              }).catch(() => {});
            }
          }
          await loadAccounts();
          backupModal.classList.add('hidden');
          showToast(`تم استيراد الحسابات بنجاح! 🎉`, 'success');
        }
      }
    } catch (err) {
      console.error('Import error:', err);
      showToast('فشل استيراد النسخة الاحتياطية', 'error');
    } finally {
      importFileInput.value = '';
    }
  };
  reader.readAsText(file);
});

// ==========================================
// 12. ربط الأحداث العامة والبحث والفلترة
// ==========================================
function setupEventListeners() {
  addAccountBtn.addEventListener('click', openAddAccountModal);
  emptyStateAddBtn.addEventListener('click', openAddAccountModal);
  closeAccountModalBtn.addEventListener('click', closeAccountModal);
  cancelAccountBtn.addEventListener('click', closeAccountModal);

  backupModalBtn.addEventListener('click', () => backupModal.classList.remove('hidden'));
  closeBackupModalBtn.addEventListener('click', () => backupModal.classList.add('hidden'));

  closeViewModalBtn.addEventListener('click', () => viewModal.classList.add('hidden'));

  window.addEventListener('click', (e) => {
    if (e.target === accountModal) closeAccountModal();
    if (e.target === backupModal) backupModal.classList.add('hidden');
    if (e.target === viewModal) viewModal.classList.add('hidden');
  });

  searchInput.addEventListener('input', (e) => {
    currentSearch = e.target.value.trim();
    clearSearchBtn.classList.toggle('hidden', !currentSearch);
    renderAccounts();
  });

  clearSearchBtn.addEventListener('click', () => {
    searchInput.value = '';
    currentSearch = '';
    clearSearchBtn.classList.add('hidden');
    renderAccounts();
    searchInput.focus();
  });

  categoryPills.addEventListener('click', (e) => {
    const pill = e.target.closest('.pill');
    if (!pill) return;

    categoryPills.querySelectorAll('.pill').forEach((p) => p.classList.remove('active'));
    pill.classList.add('active');

    currentCategory = pill.dataset.category;
    renderAccounts();
  });

  sortSelect.addEventListener('change', (e) => {
    currentSort = e.target.value;
    renderAccounts();
  });
}

// ==========================================
// 13. أدوات مساعدة عامة (Helper Utilities)
// ==========================================
function copyToClipboard(text, successMessage) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard
      .writeText(text)
      .then(() => {
        showToast(successMessage, 'success');
      })
      .catch(() => fallbackCopy(text, successMessage));
  } else {
    fallbackCopy(text, successMessage);
  }
}

function fallbackCopy(text, successMessage) {
  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.style.position = 'fixed';
  textArea.style.opacity = '0';
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    document.execCommand('copy');
    showToast(successMessage, 'success');
  } catch (err) {
    showToast('تعذر النسخ تلقائياً', 'error');
  }
  document.body.removeChild(textArea);
}

function showToast(message, type = 'success') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;

  const iconClass =
    type === 'success'
      ? 'fa-circle-check'
      : type === 'error'
      ? 'fa-circle-xmark'
      : 'fa-circle-info';

  toast.innerHTML = `
    <i class="fa-solid ${iconClass}"></i>
    <span>${escapeHtml(message)}</span>
  `;

  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3400);
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function formatDate(timestamp) {
  if (!timestamp) return '';
  const date = new Date(timestamp);
  return date.toLocaleDateString('ar-EG', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
}

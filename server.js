import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import fs from 'fs';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

// Загрузка .env
dotenv.config();

const app = express();

// Доверие к прокси (Nginx) — обязательно для rate-limit и X-Forwarded-For
app.set('trust proxy', 1);

const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = parseInt(process.env.PORT) || 3000;
const IS_PRODUCTION = NODE_ENV === 'production';

// Всегда используем HTTP сервер (Nginx обрабатывает HTTPS)
const server = http.createServer(app);

console.log(`Запуск в режиме: ${NODE_ENV}`);
console.log(`Порт: ${PORT}`);

// CORS — разрешённые origins
const allowedOrigins = [
  'https://browsermessage.run.place',
  'https://www.browsermessage.run.place',
  ...(!IS_PRODUCTION ? [
    'http://localhost:3000',
    'http://127.0.0.1:3000'
  ] : []),
  ...(process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
    : [])
];

console.log('Разрешённые origins:', allowedOrigins);

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn('CORS отклонён:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'X-File-Name',
    'X-File-Mime',
    'X-File-Size',
    'X-File-Version',
    'X-File-Salt',
    'X-File-Iv',
    'X-File-Mac',
    'X-File-Time'
  ]
};

const io = new Server(server, {
  cors: corsOptions,
  transports: ['websocket', 'polling'],
  maxHttpBufferSize: 64 * 1024,
  pingInterval: 25000,
  pingTimeout: 60000
});

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_SECRET_MIN_LENGTH = 32;
const DEFAULT_INSECURE_JWT_SECRETS = new Set([
  'your-super-secret-jwt-key-min-32-chars-change-me',
  'changeme',
  'change-me',
  'secret',
  'default',
  'jwt-secret'
]);

function isStrongSecret(value, minLength = JWT_SECRET_MIN_LENGTH) {
  if (typeof value !== 'string') {
    return false;
  }

  const normalized = value.trim();
  if (normalized.length < minLength) {
    return false;
  }

  return !DEFAULT_INSECURE_JWT_SECRETS.has(normalized.toLowerCase());
}

if (!isStrongSecret(JWT_SECRET)) {
  console.error(`JWT_SECRET не задан или слишком слабый. Укажите секрет длиной не менее ${JWT_SECRET_MIN_LENGTH} символов.`);
  process.exit(1);
}

const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const AUTH_COOKIE_NAME = 'chat_session';
const AUTH_COOKIE_MAX_AGE = 30 * 24 * 60 * 60 * 1000;
const COOKIE_SECURE = IS_PRODUCTION;
const MAX_MESSAGE_CIPHER_LENGTH = 8192;
const MAX_TIME_LABEL_LENGTH = 16;
const MAX_CHAT_TITLE_LENGTH = 60;
const MAX_FILENAME_LENGTH = 120;
const MAX_MIME_LENGTH = 120;
const MAX_FILE_UPLOAD_BYTES = 8 * 1024 * 1024;
const MESSAGE_EVENT_LIMIT = { max: 30, windowMs: 10_000 };
const CHAT_EVENT_LIMIT = { max: 60, windowMs: 10_000 };
const minPasswordLengthRaw = parseInt(process.env.MIN_PASSWORD_LENGTH || '6', 10);
const MIN_PASSWORD_LENGTH = Number.isFinite(minPasswordLengthRaw) && minPasswordLengthRaw >= 6
  ? minPasswordLengthRaw
  : 6;
const blockedPasswords = ['ChangeMe123!', 'Password123!', 'Qwerty123!', 'Admin123!', '12345678'];
const blockedPasswordSet = new Set(blockedPasswords);

const passwordPolicyRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).+$/;

function validatePasswordPolicy(password) {
  if (typeof password !== 'string') {
    return 'Пароль должен быть строкой';
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Пароль: минимум ${MIN_PASSWORD_LENGTH} символов`;
  }
  if (!passwordPolicyRegex.test(password)) {
    return 'Пароль должен содержать строчные, заглавные, цифру и спецсимвол';
  }
  if (blockedPasswordSet.has(password)) {
    return 'Этот пароль запрещён: выберите более уникальный';
  }
  return null;
}

function getValidAdminBootstrapPassword() {
  const password = typeof ADMIN_PASSWORD === 'string' ? ADMIN_PASSWORD : '';
  const validationError = validatePasswordPolicy(password);

  if (validationError) {
    return { ok: false, error: validationError };
  }

  return { ok: true, password };
}

function normalizeTimeLabel(value) {
  const normalized = String(value || '')
    .replace(/[\r\n\t]/g, ' ')
    .trim();

  if (!normalized || normalized.length > MAX_TIME_LABEL_LENGTH) {
    return null;
  }

  return normalized;
}

function decodeHeaderComponent(value, fallback = '') {
  const normalized = String(value || '').trim();
  if (!normalized) {
    return fallback;
  }

  try {
    return decodeURIComponent(normalized);
  } catch {
    return fallback;
  }
}

function parseCookieHeader(cookieHeader) {
  if (typeof cookieHeader !== 'string' || !cookieHeader.trim()) {
    return {};
  }

  return cookieHeader
    .split(';')
    .map(part => part.trim())
    .filter(Boolean)
    .reduce((cookies, part) => {
      const separatorIndex = part.indexOf('=');
      if (separatorIndex === -1) {
        return cookies;
      }

      const key = part.slice(0, separatorIndex).trim();
      const value = part.slice(separatorIndex + 1).trim();
      if (!key) {
        return cookies;
      }

      try {
        cookies[key] = decodeURIComponent(value);
      } catch {
        cookies[key] = value;
      }
      return cookies;
    }, {});
}

function getTokenFromRequest(req) {
  const cookies = parseCookieHeader(req.headers.cookie);
  return cookies[AUTH_COOKIE_NAME] || '';
}

function isValidSessionVersion(value) {
  return Number.isInteger(value) && value >= 1;
}

function ensureUserSecurityFields(user) {
  if (!user || typeof user !== 'object') {
    return false;
  }

  let changed = false;

  if (!isValidSessionVersion(user.sessionVersion)) {
    user.sessionVersion = 1;
    changed = true;
  }

  if (!Number.isInteger(user.passwordChangedAt) || user.passwordChangedAt <= 0) {
    user.passwordChangedAt = Date.now();
    changed = true;
  }

  return changed;
}

function getCookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'strict',
    secure: COOKIE_SECURE,
    path: '/',
    maxAge: AUTH_COOKIE_MAX_AGE
  };
}

function setAuthCookie(res, token) {
  res.cookie(AUTH_COOKIE_NAME, token, getCookieOptions());
}

function clearAuthCookie(res) {
  res.clearCookie(AUTH_COOKIE_NAME, {
    httpOnly: true,
    sameSite: 'strict',
    secure: COOKIE_SECURE,
    path: '/'
  });
}

function signSessionToken(user) {
  return jwt.sign(
    { username: user.username, sessionVersion: user.sessionVersion },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function getAuthorizedUser(req) {
  const token = getTokenFromRequest(req);
  if (!token) {
    return { status: 401, error: 'Нет токена' };
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = findUserByUsername(payload.username);
    if (!user) {
      return { status: 401, error: 'Недействительный токен' };
    }
    if (!isValidSessionVersion(payload.sessionVersion) || payload.sessionVersion !== user.sessionVersion) {
      return { status: 401, error: 'Сессия устарела' };
    }
    return { status: 200, user };
  } catch {
    return { status: 401, error: 'Недействительный токен' };
  }
}

// Helmet + CSP вЂ” СЂР°Р·СЂРµС€Р°РµРј РІСЃС‘ РЅРµРѕР±С…РѕРґРёРјРѕРµ
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    scriptSrcAttr: ["'none'"],
    styleSrc: [
      "'self'",
      "'unsafe-inline'"
    ],
    fontSrc: [
      "'self'",
      "data:"
    ],
    imgSrc: ["'self'", "data:", "https:", "blob:"],
    connectSrc: [
      "'self'",
      "wss:", "ws:",
      "https://browsermessage.run.place"
    ],
    objectSrc: ["'none'"],
    frameSrc: ["'none'"],
    mediaSrc: ["'self'", "https:"],
    upgradeInsecureRequests: []
  }
}));

app.use(cors(corsOptions));
app.use(express.json({ limit: '64kb' }));
app.use(express.static('public', {
  dotfiles: 'deny',
  etag: false,
  setHeaders: (res, filePath) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (String(filePath).toLowerCase().endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
      return;
    }

    res.setHeader('Cache-Control', 'public, max-age=3600');
  }
}));

// Р”Р°РЅРЅС‹Рµ
let users = [];
let chats = [];
let allMessages = [];

import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const USERS_FILE = path.join(__dirname, 'users.json');
const CHATS_FILE = path.join(__dirname, 'chats.json');
const MESSAGES_FILE = path.join(__dirname, 'messages.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

const normalizeUsername = (value) => (
  typeof value === 'string' ? value.trim() : ''
);

const findUserByUsername = (value) => {
  const normalized = normalizeUsername(value).toLowerCase();
  if (!normalized) return null;
  return users.find(u => u.username.toLowerCase() === normalized) || null;
};

function uniqueUsernames(values) {
  return Array.from(
    new Set(
      (Array.isArray(values) ? values : [])
        .map((value) => normalizeUsername(value))
        .filter(Boolean)
    )
  );
}

function directChatIdFor(userA, userB) {
  return [userA, userB].sort().join('-');
}

function isLegacyDirectChatId(chatId) {
  if (typeof chatId !== 'string') return false;
  const parts = chatId.split('-');
  return parts.length === 2 && parts[0] && parts[1];
}

function ensureUploadsDir() {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

function normalizeChatRecord(rawChat) {
  if (!rawChat || typeof rawChat !== 'object') {
    return null;
  }

  const type = rawChat.type === 'group' ? 'group' : 'direct';
  const members = uniqueUsernames(rawChat.members);
  if (type === 'direct' && members.length !== 2) {
    return null;
  }
  if (type === 'group' && members.length < 2) {
    return null;
  }

  const id = normalizeUsername(rawChat.id) || (type === 'direct'
    ? directChatIdFor(members[0], members[1])
    : `group:${crypto.randomUUID()}`);
  const title = type === 'group'
    ? String(rawChat.title || 'Новая группа').trim().slice(0, MAX_CHAT_TITLE_LENGTH)
    : '';

  return {
    id,
    type,
    title,
    members,
    createdAt: Number.isFinite(rawChat.createdAt) ? rawChat.createdAt : Date.now(),
    createdBy: normalizeUsername(rawChat.createdBy) || members[0]
  };
}

function createDirectChat(userA, userB, createdBy = userA) {
  const members = uniqueUsernames([userA, userB]);
  return normalizeChatRecord({
    id: directChatIdFor(members[0], members[1]),
    type: 'direct',
    members,
    createdAt: Date.now(),
    createdBy
  });
}

function getChatById(chatId) {
  const normalized = normalizeUsername(chatId);
  if (!normalized) return null;
  return chats.find((chat) => chat.id === normalized) || null;
}

function ensureDirectChat(userA, userB, { persist = false } = {}) {
  const chatId = directChatIdFor(userA, userB);
  let chat = getChatById(chatId);
  let created = false;

  if (!chat) {
    chat = createDirectChat(userA, userB, userA);
    chats.push(chat);
    created = true;
    if (persist) {
      saveChats();
    }
  }

  return { chat, created };
}

function userCanAccessChat(chat, username) {
  return !!chat && chat.members.includes(username);
}

function getLastMessageForChat(chatId) {
  const matching = allMessages
    .filter((message) => message.chatId === chatId)
    .sort((left, right) => (right.timestamp || 0) - (left.timestamp || 0));
  return matching[0] || null;
}

function getChatSummary(chat, currentUsername) {
  if (!chat) return null;

  const otherUsername = chat.type === 'direct'
    ? chat.members.find((member) => member !== currentUsername) || chat.members[0]
    : null;
  const title = chat.type === 'group'
    ? chat.title
    : otherUsername;
  const lastMessage = getLastMessageForChat(chat.id);

  return {
    id: chat.id,
    type: chat.type,
    title,
    members: [...chat.members],
    memberCount: chat.members.length,
    canDelete: chat.type === 'direct',
    createdAt: chat.createdAt,
    lastTimestamp: lastMessage?.timestamp || chat.createdAt,
    otherUsername
  };
}

function getVisibleChatsForUser(username) {
  return chats
    .filter((chat) => userCanAccessChat(chat, username))
    .map((chat) => getChatSummary(chat, username))
    .filter(Boolean)
    .sort((left, right) => {
      const timestampDiff = (right.lastTimestamp || 0) - (left.lastTimestamp || 0);
      if (timestampDiff !== 0) return timestampDiff;
      return String(left.title).localeCompare(String(right.title), 'ru', { sensitivity: 'base' });
    });
}

function sanitizeFilename(value) {
  const fallback = 'file.bin';
  const normalized = String(value || '').trim();
  if (!normalized) return fallback;

  const cleaned = normalized
    .replace(/[\\/:*?"<>|]/g, '_')
    .replace(/\s+/g, ' ')
    .slice(0, MAX_FILENAME_LENGTH)
    .trim();

  return cleaned || fallback;
}

function sanitizeMimeType(value) {
  const normalized = String(value || '').trim().slice(0, MAX_MIME_LENGTH);
  if (!normalized || /[\r\n]/.test(normalized)) {
    return 'application/octet-stream';
  }
  return normalized;
}

function parsePositiveInt(value) {
  const parsed = Number.parseInt(String(value || ''), 10);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

function sanitizeBase64Token(value, maxLength = 256) {
  const normalized = String(value || '').trim();
  if (!normalized || normalized.length > maxLength) return null;
  if (!/^[A-Za-z0-9+/=]+$/.test(normalized)) return null;
  return normalized;
}

function buildFileStorageName(fileId) {
  return `${fileId}.bin`;
}

function getUserRoom(username) {
  return `user:${username}`;
}

function broadcastChatsChanged(usernames) {
  uniqueUsernames(usernames).forEach((username) => {
    io.to(getUserRoom(username)).emit('chats-changed');
  });
}

function removeStoredFilesForMessages(messages) {
  (Array.isArray(messages) ? messages : []).forEach((message) => {
    const storageName = message?.file?.storageName;
    if (!storageName) return;
    const filePath = path.join(UPLOADS_DIR, storageName);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  });
}

function findFileMessageById(fileId) {
  const normalized = normalizeUsername(fileId);
  if (!normalized) return null;
  return allMessages.find((message) => message?.kind === 'file' && message?.file?.id === normalized) || null;
}


function loadData() {
  try {
    if (fs.existsSync(USERS_FILE)) users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    if (fs.existsSync(CHATS_FILE)) chats = JSON.parse(fs.readFileSync(CHATS_FILE, 'utf8'));
    if (fs.existsSync(MESSAGES_FILE)) allMessages = JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8'));
    ensureUploadsDir();

    let usersChanged = false;
    let chatsChanged = false;
    users = Array.isArray(users) ? users : [];
    users.forEach((user) => {
      if (ensureUserSecurityFields(user)) {
        usersChanged = true;
      }
    });

    const originalChatsLength = Array.isArray(chats) ? chats.length : 0;
    chats = (Array.isArray(chats) ? chats : [])
      .map((chat) => normalizeChatRecord(chat))
      .filter(Boolean);
    if (chats.length !== originalChatsLength) {
      chatsChanged = true;
    }

    allMessages = Array.isArray(allMessages) ? allMessages : [];
    allMessages.forEach((message) => {
      if (!message || typeof message !== 'object' || typeof message.chatId !== 'string') {
        return;
      }

      if (getChatById(message.chatId)) {
        return;
      }

      if (isLegacyDirectChatId(message.chatId)) {
        const [leftUser, rightUser] = message.chatId.split('-');
        if (findUserByUsername(leftUser) && findUserByUsername(rightUser)) {
          chats.push(createDirectChat(leftUser, rightUser, leftUser));
          chatsChanged = true;
        }
      }
    });

    allMessages = allMessages.filter((message) => {
      if (!message || typeof message !== 'object' || typeof message.chatId !== 'string') {
        return false;
      }

      const chat = getChatById(message.chatId);
      if (!chat) {
        return false;
      }

      if (message.kind === 'file') {
        return !!(message.file?.id && message.file?.storageName);
      }

      return typeof message.cipher === 'string' && !!message.cipher.trim();
    });

    if (usersChanged) {
      saveUsers();
    }
    if (chatsChanged) {
      saveChats();
    }
  } catch (e) {
    console.error('Ошибка загрузки данных:', e);
  }
}

function saveUsers() { 
  const tempFile = `${USERS_FILE}.tmp`;
  fs.writeFileSync(tempFile, JSON.stringify(users, null, 2));
  fs.renameSync(tempFile, USERS_FILE);
}

function saveChats() {
  const tempFile = `${CHATS_FILE}.tmp`;
  fs.writeFileSync(tempFile, JSON.stringify(chats, null, 2));
  fs.renameSync(tempFile, CHATS_FILE);
}

let messageSaveTimer = null;
let messageSaveChain = Promise.resolve();

function saveMessagesSoon() {
  if (messageSaveTimer) {
    clearTimeout(messageSaveTimer);
  }

  messageSaveTimer = setTimeout(() => {
    messageSaveTimer = null;
    const snapshot = JSON.stringify(allMessages, null, 2);
    const tempFile = `${MESSAGES_FILE}.tmp`;

    messageSaveChain = messageSaveChain
      .catch(() => {})
      .then(async () => {
        await fs.promises.writeFile(tempFile, snapshot);
        await fs.promises.rename(tempFile, MESSAGES_FILE);
      })
      .catch((err) => {
        console.error('Ошибка сохранения messages.json:', err);
      });
  }, 150);
}

async function buildAdminBackupSnapshot() {
  const fileMessages = allMessages.filter((message) => message?.kind === 'file' && message?.file?.storageName);
  const files = [];

  for (const message of fileMessages) {
    const storagePath = path.join(UPLOADS_DIR, message.file.storageName);
    const exists = fs.existsSync(storagePath);
    const fileEntry = {
      id: message.file.id,
      storageName: message.file.storageName,
      name: message.file.name,
      mimeType: message.file.mimeType,
      size: message.file.size,
      encryptedSize: message.file.encryptedSize,
      crypto: message.file.crypto,
      missing: !exists
    };

    if (exists) {
      const buffer = await fs.promises.readFile(storagePath);
      fileEntry.dataBase64 = buffer.toString('base64');
    }

    files.push(fileEntry);
  }

  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    users: users.map((user) => ({
      username: user.username
    })),
    chats,
    messages: allMessages,
    files
  };
}

async function resetAllApplicationData(nextAdminSessionVersion = 2) {
  const adminPassword = getValidAdminBootstrapPassword();
  if (!adminPassword.ok) {
    throw new Error(`ADMIN_PASSWORD не подходит для сброса данных: ${adminPassword.error}`);
  }

  if (messageSaveTimer) {
    clearTimeout(messageSaveTimer);
    messageSaveTimer = null;
  }

  await messageSaveChain.catch(() => {});

  if (fs.existsSync(UPLOADS_DIR)) {
    const entries = await fs.promises.readdir(UPLOADS_DIR);
    await Promise.all(entries.map((entry) =>
      fs.promises.rm(path.join(UPLOADS_DIR, entry), { recursive: true, force: true })
    ));
  }
  ensureUploadsDir();

  users = [{
    username: ADMIN_USERNAME,
    passwordHash: bcrypt.hashSync(adminPassword.password, 12),
    sessionVersion: nextAdminSessionVersion,
    passwordChangedAt: Date.now()
  }];
  chats = [];
  allMessages = [];

  saveUsers();
  saveChats();
  fs.writeFileSync(MESSAGES_FILE, JSON.stringify(allMessages, null, 2));
}

loadData();

const existingAdmin = findUserByUsername(ADMIN_USERNAME);
if (existingAdmin) {
  const hasWeakAdminPassword = blockedPasswords.some((candidate) =>
    bcrypt.compareSync(candidate, existingAdmin.passwordHash)
  );
  if (hasWeakAdminPassword) {
    const rotateError = validatePasswordPolicy(ADMIN_PASSWORD);
    if (rotateError) {
      console.error('Обнаружен заблокированный пароль админа.');
      console.error(`Для авто-ротации укажите новый ADMIN_PASSWORD в .env: ${rotateError}`);
      process.exit(1);
    }
    existingAdmin.passwordHash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
    existingAdmin.passwordChangedAt = Date.now();
    existingAdmin.sessionVersion += 1;
    saveUsers();
    console.log('Пароль админа автоматически обновлён из ADMIN_PASSWORD.');
  }
}

// Создаём админа по умолчанию
if (users.length === 0) {
  const adminPassword = getValidAdminBootstrapPassword();
  if (!adminPassword.ok) {
    console.error('users.json пуст, но ADMIN_PASSWORD невалиден.');
    console.error(`Ошибка ADMIN_PASSWORD: ${adminPassword.error}`);
    console.error('Задайте ADMIN_PASSWORD в .env и перезапустите сервер.');
    process.exit(1);
  }

  users.push({
    username: ADMIN_USERNAME,
    passwordHash: bcrypt.hashSync(adminPassword.password, 12),
    sessionVersion: 1,
    passwordChangedAt: Date.now()
  });
  saveUsers();
  console.log(`Создан начальный администратор: ${ADMIN_USERNAME}`);
}

// Rate limiting РґР»СЏ Р»РѕРіРёРЅР°
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 РјРёРЅСѓС‚
  max: 10,
  message: { error: 'РЎР»РёС€РєРѕРј РјРЅРѕРіРѕ РїРѕРїС‹С‚РѕРє РІС…РѕРґР°. РџРѕРґРѕР¶РґРёС‚Рµ 15 РјРёРЅСѓС‚.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const accountMutationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'РЎР»РёС€РєРѕРј РјРЅРѕРіРѕ Р·Р°РїСЂРѕСЃРѕРІ. РџРѕРґРѕР¶РґРёС‚Рµ 15 РјРёРЅСѓС‚.' },
  standardHeaders: true,
  legacyHeaders: false
});

const encryptedFileUploadParser = express.raw({
  type: 'application/octet-stream',
  limit: '8mb'
});

// РћР±СЂР°Р±РѕС‚РєР° РѕС€РёР±РѕРє rate-limit (РІСЃРµРіРґР° JSON)
app.use((err, req, res, next) => {
  if (err.status === 429) {
    return res.status(429).json({ error: 'РЎР»РёС€РєРѕРј РјРЅРѕРіРѕ РїРѕРїС‹С‚РѕРє. РџРѕРґРѕР¶РґРёС‚Рµ 15 РјРёРЅСѓС‚.' });
  }
  next(err);
});

// в”Ђв”Ђв”Ђ API в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

app.post('/api/login', loginLimiter, (req, res) => {
  const username = normalizeUsername(req.body?.username);
  const password = req.body?.password;
  if (!username || !password) {
    return res.status(400).json({ error: 'Р’РІРµРґРёС‚Рµ Р»РѕРіРёРЅ Рё РїР°СЂРѕР»СЊ' });
  }

  const user = findUserByUsername(username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'РќРµРІРµСЂРЅС‹Р№ Р»РѕРіРёРЅ РёР»Рё РїР°СЂРѕР»СЊ' });
  }

  const token = signSessionToken(user);
  setAuthCookie(res, token);
  res.json({ username: user.username });
});

app.get('/api/me', (req, res) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate'); // РѕС‚РєР»СЋС‡Р°РµРј РєСЌС€
  const auth = getAuthorizedUser(req);
  if (!auth.user) {
    clearAuthCookie(res);
    return res.status(auth.status).json({ error: auth.error });
  }
  return res.json({ username: auth.user.username });
});

app.post('/api/logout', (req, res) => {
  clearAuthCookie(res);
  return res.json({ success: true });
});

app.post('/api/create-user', accountMutationLimiter, (req, res) => {
  try {
    const auth = getAuthorizedUser(req);
    if (!auth.user) {
      return res.status(auth.status).json({ error: auth.error });
    }
    if (auth.user.username !== ADMIN_USERNAME) {
      return res.status(403).json({ error: 'Только администратор может создавать пользователей' });
    }

    const username = normalizeUsername(req.body?.username);
    const password = req.body?.password;

    if (!username || !password) return res.status(400).json({ error: 'Р—Р°РїРѕР»РЅРёС‚Рµ РїРѕР»СЏ' });

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({ error: 'Р›РѕРіРёРЅ: 3-20 СЃРёРјРІРѕР»РѕРІ (Р±СѓРєРІС‹, С†РёС„СЂС‹, _)' });
    }

    const passwordError = validatePasswordPolicy(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    if (findUserByUsername(username)) {
      return res.status(400).json({ error: 'РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ СѓР¶Рµ СЃСѓС‰РµСЃС‚РІСѓРµС‚' });
    }

    const newUser = {
      username,
      passwordHash: bcrypt.hashSync(password, 12),
      sessionVersion: 1,
      passwordChangedAt: Date.now()
    };

    users.push(newUser);

    try {
      saveUsers();
    } catch (saveErr) {
      // Roll back in-memory state if persistence failed.
      users = users.filter(u => u.username !== username);
      throw saveErr;
    }

    return res.json({ success: true, message: `РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ ${username} СЃРѕР·РґР°РЅ` });
  } catch (err) {
    console.error('РћС€РёР±РєР° /api/create-user:', err);
    if (err && err.code === 'EACCES') {
      return res.status(500).json({ error: 'РќРµС‚ РїСЂР°РІ РЅР° Р·Р°РїРёСЃСЊ users.json. РџСЂРѕРІРµСЂСЊС‚Рµ РІР»Р°РґРµР»СЊС†Р°/РїСЂР°РІР° РїР°РїРєРё РїСЂРёР»РѕР¶РµРЅРёСЏ.' });
    }
    return res.status(500).json({ error: 'Р’РЅСѓС‚СЂРµРЅРЅСЏСЏ РѕС€РёР±РєР° СЃРµСЂРІРµСЂР° РїСЂРё СЃРѕР·РґР°РЅРёРё РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ' });
  }
});

app.get('/api/users', (req, res) => {
  const auth = getAuthorizedUser(req);
  if (!auth.user) {
    return res.status(auth.status).json({ error: auth.error });
  }

  if (auth.user.username !== ADMIN_USERNAME) {
    return res.status(403).json({ error: 'РўРѕР»СЊРєРѕ Р°РґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂ РјРѕР¶РµС‚ РІРёРґРµС‚СЊ СЃРїРёСЃРѕРє' });
  }

  res.json(users.map(u => ({ username: u.username })));
});

app.get('/api/directory', (req, res) => {
  const auth = getAuthorizedUser(req);
  if (!auth.user) {
    return res.status(auth.status).json({ error: auth.error });
  }

  return res.json(
    users
      .map((user) => user.username)
      .sort((left, right) => left.localeCompare(right, 'ru', { sensitivity: 'base' }))
  );
});

app.get('/api/admin/export-all', async (req, res) => {
  const auth = getAuthorizedUser(req);
  if (!auth.user) {
    return res.status(auth.status).json({ error: auth.error });
  }
  if (auth.user.username !== ADMIN_USERNAME) {
    return res.status(403).json({ error: 'Только администратор может сохранять архив' });
  }

  try {
    const snapshot = await buildAdminBackupSnapshot();
    const fileName = `messenger-backup-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    return res.send(JSON.stringify(snapshot, null, 2));
  } catch (error) {
    console.error('Ошибка экспорта данных:', error);
    return res.status(500).json({ error: 'Не удалось сохранить архив' });
  }
});

app.post('/api/admin/reset-all', accountMutationLimiter, async (req, res) => {
  const auth = getAuthorizedUser(req);
  if (!auth.user) {
    return res.status(auth.status).json({ error: auth.error });
  }
  if (auth.user.username !== ADMIN_USERNAME) {
    return res.status(403).json({ error: 'Только администратор может очищать данные' });
  }

  try {
    const nextAdminSessionVersion = (Number(auth.user.sessionVersion) || 1) + 1;
    await resetAllApplicationData(nextAdminSessionVersion);
    clearAuthCookie(res);
    io.emit('chat-deleted', '__all__');
    io.emit('chats-changed');
    return res.json({
      success: true,
      message: 'Все данные очищены. Войдите заново.',
      reauthRequired: true
    });
  } catch (error) {
    console.error('Ошибка полного сброса данных:', error);
    return res.status(500).json({ error: 'Не удалось очистить данные' });
  }
});

app.post('/api/groups', accountMutationLimiter, (req, res) => {
  const auth = getAuthorizedUser(req);
  if (!auth.user) {
    return res.status(auth.status).json({ error: auth.error });
  }

  const title = String(req.body?.title || '').trim();
  if (title.length < 3 || title.length > MAX_CHAT_TITLE_LENGTH) {
    return res.status(400).json({ error: `Название группы: 3-${MAX_CHAT_TITLE_LENGTH} символов` });
  }

  const requestedMembers = uniqueUsernames(req.body?.members);
  const members = uniqueUsernames([auth.user.username, ...requestedMembers]);
  if (members.length < 2) {
    return res.status(400).json({ error: 'Добавьте хотя бы одного участника' });
  }

  const missingUsers = members.filter((member) => !findUserByUsername(member));
  if (missingUsers.length > 0) {
    return res.status(400).json({ error: `Пользователи не найдены: ${missingUsers.join(', ')}` });
  }

  const chat = normalizeChatRecord({
    id: `group:${crypto.randomUUID()}`,
    type: 'group',
    title,
    members,
    createdAt: Date.now(),
    createdBy: auth.user.username
  });

  chats.push(chat);
  saveChats();
  broadcastChatsChanged(chat.members);

  return res.json({ success: true, chat: getChatSummary(chat, auth.user.username) });
});

app.post('/api/chats/:chatId/files', accountMutationLimiter, encryptedFileUploadParser, async (req, res) => {
  const auth = getAuthorizedUser(req);
  if (!auth.user) {
    return res.status(auth.status).json({ error: auth.error });
  }

  const chatId = String(req.params.chatId || '').trim();
  const chat = getChatById(chatId);
  if (!chat) {
    return res.status(404).json({ error: 'Чат не найден' });
  }
  if (!userCanAccessChat(chat, auth.user.username)) {
    return res.status(403).json({ error: 'Нет доступа к чату' });
  }

  if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).json({ error: 'Файл не передан' });
  }
  if (req.body.length > MAX_FILE_UPLOAD_BYTES) {
    return res.status(400).json({ error: 'Файл слишком большой' });
  }

  const decodedFileName = decodeHeaderComponent(req.headers['x-file-name'], 'file.bin');
  const fileName = sanitizeFilename(decodedFileName);
  const mimeType = sanitizeMimeType(req.headers['x-file-mime']);
  const originalSize = parsePositiveInt(req.headers['x-file-size']);
  const cryptoVersion = parsePositiveInt(req.headers['x-file-version']);
  const salt = sanitizeBase64Token(req.headers['x-file-salt']);
  const iv = sanitizeBase64Token(req.headers['x-file-iv']);
  const mac = sanitizeBase64Token(req.headers['x-file-mac']);
  const providedTime = normalizeTimeLabel(req.headers['x-file-time']);
  const time = providedTime
    ? providedTime
    : new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });

  if (originalSize === null || originalSize <= 0) {
    return res.status(400).json({ error: 'Невалидный размер файла' });
  }
  if (cryptoVersion !== 2 || !salt || !iv || !mac) {
    return res.status(400).json({ error: 'Невалидные крипто-параметры файла' });
  }

  const fileId = `file_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
  const storageName = buildFileStorageName(fileId);
  const storagePath = path.join(UPLOADS_DIR, storageName);

  await fs.promises.writeFile(storagePath, req.body);

  const message = {
    id: crypto.randomUUID(),
    chatId: chat.id,
    from: auth.user.username,
    kind: 'file',
    time,
    timestamp: Date.now(),
    file: {
      id: fileId,
      storageName,
      name: fileName,
      mimeType,
      size: originalSize,
      encryptedSize: req.body.length,
      crypto: {
        v: cryptoVersion,
        s: salt,
        iv,
        mac
      }
    }
  };

  allMessages.push(message);
  saveMessagesSoon();
  io.to(chat.id).emit('new-message', message);
  broadcastChatsChanged(chat.members);

  return res.json({ success: true, message });
});

app.get('/api/files/:fileId', (req, res) => {
  const auth = getAuthorizedUser(req);
  if (!auth.user) {
    return res.status(auth.status).json({ error: auth.error });
  }

  const fileId = String(req.params.fileId || '').trim();
  const message = findFileMessageById(fileId);
  if (!message) {
    return res.status(404).json({ error: 'Файл не найден' });
  }

  const chat = getChatById(message.chatId);
  if (!chat || !userCanAccessChat(chat, auth.user.username)) {
    return res.status(403).json({ error: 'Нет доступа к файлу' });
  }

  const storagePath = path.join(UPLOADS_DIR, message.file.storageName);
  if (!fs.existsSync(storagePath)) {
    return res.status(404).json({ error: 'Файл не найден на диске' });
  }

  res.set('Cache-Control', 'no-store');
  res.set('Content-Type', 'application/octet-stream');
  res.set('Content-Length', String(message.file.encryptedSize || fs.statSync(storagePath).size));
  return res.sendFile(storagePath);
});

app.post('/api/change-password', accountMutationLimiter, (req, res) => {
  const auth = getAuthorizedUser(req);
  if (!auth.user) {
    return res.status(auth.status).json({ error: auth.error });
  }
  const currentUsername = auth.user.username;

  const { oldPassword, newPassword } = req.body;
  const targetUsername = normalizeUsername(req.body?.targetUsername);
  const target = targetUsername || currentUsername;

  if (currentUsername !== ADMIN_USERNAME && target !== currentUsername) {
    return res.status(403).json({ error: 'РњРѕР¶РЅРѕ РјРµРЅСЏС‚СЊ С‚РѕР»СЊРєРѕ СЃРІРѕР№ РїР°СЂРѕР»СЊ' });
  }

  if (currentUsername !== ADMIN_USERNAME && !oldPassword) {
    return res.status(400).json({ error: 'РўСЂРµР±СѓРµС‚СЃСЏ СЃС‚Р°СЂС‹Р№ РїР°СЂРѕР»СЊ' });
  }

  if (!newPassword) {
    return res.status(400).json({ error: 'РўСЂРµР±СѓРµС‚СЃСЏ РЅРѕРІС‹Р№ РїР°СЂРѕР»СЊ' });
  }

  const passwordError = validatePasswordPolicy(newPassword);
  if (passwordError) {
    return res.status(400).json({ error: passwordError });
  }

  const user = findUserByUsername(target);
  if (!user) return res.status(404).json({ error: 'РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ РЅРµ РЅР°Р№РґРµРЅ' });

  if (currentUsername !== ADMIN_USERNAME) {
    if (!bcrypt.compareSync(oldPassword, user.passwordHash)) {
      return res.status(401).json({ error: 'РЎС‚Р°СЂС‹Р№ РїР°СЂРѕР»СЊ РЅРµРІРµСЂРµРЅ' });
    }
  }

  user.passwordHash = bcrypt.hashSync(newPassword, 12);
  user.passwordChangedAt = Date.now();
  user.sessionVersion += 1;
  saveUsers();

  if (target === currentUsername) {
    clearAuthCookie(res);
    return res.json({ success: true, message: 'РџР°СЂРѕР»СЊ РёР·РјРµРЅС‘РЅ', reauthRequired: true });
  }

  return res.json({ success: true, message: 'РџР°СЂРѕР»СЊ РёР·РјРµРЅС‘РЅ' });
});

// в”Ђв”Ђв”Ђ Socket.IO в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

function isSocketActionAllowed(socket, key, limit) {
  const now = Date.now();
  socket.rateState ??= {};
  const state = socket.rateState[key] || { count: 0, resetAt: now + limit.windowMs };

  if (now > state.resetAt) {
    state.count = 0;
    state.resetAt = now + limit.windowMs;
  }

  state.count += 1;
  socket.rateState[key] = state;
  return state.count <= limit.max;
}

function getSocketToken(socket) {
  const cookieHeader = socket.handshake.headers.cookie || socket.request?.headers?.cookie || '';
  return parseCookieHeader(cookieHeader)[AUTH_COOKIE_NAME] || '';
}

function emitSocketRateError(socket) {
  socket.emit('chat-error', 'РЎР»РёС€РєРѕРј РјРЅРѕРіРѕ Р·Р°РїСЂРѕСЃРѕРІ. РџРѕРґРѕР¶РґРёС‚Рµ.');
}

function resolveChatFromSocketPayload(socketUsername, payload) {
  const normalizedPayload = payload && typeof payload === 'object' ? payload : {};
  const chatId = String(normalizedPayload.chatId || '').trim();
  const username = normalizeUsername(normalizedPayload.username || normalizedPayload.otherUsername || payload);

  if (chatId) {
    const existingChat = getChatById(chatId);
    if (!existingChat) {
      return { error: 'Чат не найден' };
    }
    if (!userCanAccessChat(existingChat, socketUsername)) {
      return { error: 'Нет доступа к чату' };
    }
    return { chat: existingChat };
  }

  if (username) {
    const otherUser = findUserByUsername(username);
    if (!otherUser) {
      return { error: 'Пользователь не найден' };
    }
    if (otherUser.username === socketUsername) {
      return { error: 'Нельзя открыть чат с самим собой' };
    }

    const { chat, created } = ensureDirectChat(socketUsername, otherUser.username, { persist: true });
    if (created) {
      broadcastChatsChanged(chat.members);
    }
    return { chat };
  }

  return { error: 'Невалидный чат' };
}

io.use((socket, next) => {
  const token = getSocketToken(socket);
  if (!token) return next(new Error('Токен отсутствует'));
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = findUserByUsername(payload.username);
    if (!user) return next(new Error('Пользователь не найден'));
    if (!isValidSessionVersion(payload.sessionVersion) || payload.sessionVersion !== user.sessionVersion) {
      return next(new Error('Сессия устарела'));
    }
    socket.username = user.username;
    next();
  } catch {
    next(new Error('Неверный токен'));
  }
});

io.on('connection', (socket) => {
  socket.join(getUserRoom(socket.username));
  console.log(`Подключился: ${socket.username}`);

  socket.on('get-chats', () => {
    if (!isSocketActionAllowed(socket, 'get-chats', CHAT_EVENT_LIMIT)) {
      return emitSocketRateError(socket);
    }
    socket.emit('your-chats', getVisibleChatsForUser(socket.username));
  });

  socket.on('join-chat', (payload, ack) => {
    if (!isSocketActionAllowed(socket, 'join-chat', CHAT_EVENT_LIMIT)) {
      emitSocketRateError(socket);
      if (typeof ack === 'function') {
        ack({ ok: false, error: 'Слишком много запросов' });
      }
      return;
    }

    const { chat, error } = resolveChatFromSocketPayload(socket.username, payload);
    if (!chat) {
      if (typeof ack === 'function') {
        return ack({ ok: false, error: error || 'Чат не найден' });
      }
      return socket.emit('chat-error', error || 'Чат не найден');
    }

    socket.join(chat.id);
    const history = allMessages
      .filter((message) => message.chatId === chat.id)
      .sort((left, right) => (left.timestamp || 0) - (right.timestamp || 0));
    const chatSummary = getChatSummary(chat, socket.username);

    if (typeof ack === 'function') {
      ack({ ok: true, chat: chatSummary });
    }
    socket.emit('chat-history', { chat: chatSummary, messages: history });
  });

  socket.on('send-message', (payload = {}) => {
    if (!isSocketActionAllowed(socket, 'send-message', MESSAGE_EVENT_LIMIT)) {
      return emitSocketRateError(socket);
    }

    const { chat, error } = resolveChatFromSocketPayload(socket.username, payload);
    if (!chat) {
      return socket.emit('chat-error', error || 'Чат не найден');
    }

    const cipher = String(payload.cipher || '');
    const time = normalizeTimeLabel(payload.time);
    if (typeof cipher !== 'string' || !cipher.trim() || cipher.length > MAX_MESSAGE_CIPHER_LENGTH) {
      return socket.emit('chat-error', 'Сообщение слишком большое или невалидное');
    }
    if (!time) {
      return socket.emit('chat-error', 'Невалидная метка времени');
    }

    const msg = {
      id: crypto.randomUUID(),
      chatId: chat.id,
      from: socket.username,
      kind: 'text',
      cipher,
      time,
      timestamp: Date.now()
    };
    allMessages.push(msg);
    saveMessagesSoon();
    io.to(chat.id).emit('new-message', msg);
    broadcastChatsChanged(chat.members);
  });

  socket.on('delete-chat', (payload = {}) => {
    if (!isSocketActionAllowed(socket, 'delete-chat', CHAT_EVENT_LIMIT)) {
      return emitSocketRateError(socket);
    }

    const { chat, error } = resolveChatFromSocketPayload(socket.username, payload);
    if (!chat) {
      return socket.emit('chat-error', error || 'Чат не найден');
    }
    if (chat.type !== 'direct') {
      return socket.emit('chat-error', 'Групповой чат нельзя удалить этой командой');
    }

    const messagesToDelete = allMessages.filter((message) => message.chatId === chat.id);
    removeStoredFilesForMessages(messagesToDelete);
    allMessages = allMessages.filter((message) => message.chatId !== chat.id);
    chats = chats.filter((existingChat) => existingChat.id !== chat.id);
    saveChats();
    saveMessagesSoon();
    io.to(chat.id).emit('chat-deleted', chat.id);
    broadcastChatsChanged(chat.members);
  });

  socket.on('disconnect', () => {
    console.log(`Отключился: ${socket.username}`);
  });
});

// Запуск сервера только на localhost
server.listen(PORT, '127.0.0.1', () => {
  console.log(`Сервер запущен -> http://127.0.0.1:${PORT}`);
  console.log('Ожидаю прокси от Nginx на https://browsermessage.run.place');
});


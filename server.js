import express from 'express';
import https from 'https';
import http from 'http';
import { Server } from 'socket.io';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import fs from 'fs';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const app = express();

// Выбираем HTTP или HTTPS в зависимости от переменной окружения
let server;
const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = process.env.PORT || (NODE_ENV === 'production' ? 3000 : 3000); // Production behind nginx proxy

if (NODE_ENV === 'production') {
  // HTTPS для продакшена (опционально для локального тестирования)
  const sslKeyPath = process.env.SSL_KEY_PATH;
  const sslCertPath = process.env.SSL_CERT_PATH;
  
  if (sslKeyPath && sslCertPath && fs.existsSync(sslKeyPath) && fs.existsSync(sslCertPath)) {
    const options = {
      key: fs.readFileSync(sslKeyPath),
      cert: fs.readFileSync(sslCertPath)
    };
    server = https.createServer(options, app);
    console.log('🔒 HTTPS mode (production with SSL)');
  } else {
    // HTTP режим за nginx reverse proxy (nginx слушает 443 HTTPS)
    server = http.createServer(app);
    console.log('📡 HTTP mode (production behind nginx reverse proxy on port ' + PORT + ')');
  }
} else {
  // HTTP для разработки на локальном хосте
  server = http.createServer(app);
  console.log('📡 HTTP mode (development) - http://localhost:' + PORT);
}

// CORS конфигурация
const protocol = NODE_ENV === 'production' ? 'https' : 'http';
const baseOrigins = [
  `${protocol}://localhost:${PORT}`,
  `${protocol}://localhost:3000`,
  `${protocol}://127.0.0.1:${PORT}`,
  `${protocol}://127.0.0.1:3000`
];

// Парсируем дополнительные origin'ы из .env (список через запятую)
const envOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
  : [];

const allowedOrigins = [...new Set([...baseOrigins, ...envOrigins])]; // Убираем дубликаты

console.log('✅ CORS Allowed origins:', allowedOrigins);

const corsOptions = {
  origin: (origin, callback) => {
    // Разрешаем запросы без origin (локальные приложения, мобильные приложения)
    if (!origin) return callback(null, true);
    
    // Проверяем если origin в списке разрешённых
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    console.warn('⚠️  CORS: отклонен origin:', origin);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

const io = new Server(server, { 
  cors: corsOptions,
  transports: ['websocket', 'polling'],
  pingInterval: 25000,
  pingTimeout: 60000
});

const JWT_SECRET = process.env.JWT_SECRET || (() => {
  console.error('❌ ERROR: JWT_SECRET не установлена в .env файле!');
  process.exit(1);
})();

// 🔐 Helmet with CSP для CDN и inline скриптов
const cspConfig = {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
    scriptSrcAttr: ["'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'", "wss:", "ws:", "https:", "http:"],
    fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
    frameSrc: ["'none'"],
    objectSrc: ["'none'"]
  }
};

// 🔐 Helmet конфигурация с правильными заголовками безопасности
const helmetConfig = {
  contentSecurityPolicy: { directives: cspConfig.directives },
  crossOriginOpenerPolicy: NODE_ENV === 'production' ? { policy: 'same-origin-allow-popups' } : false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
  originAgentCluster: false, // Избегаем конфликтов с origin-keyed agent cluster
  hsts: NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true } : false,
  frameguard: { action: 'deny' },
  xssFilter: true,
  noSniff: true
};

app.use(helmet(helmetConfig));
app.use(cors(corsOptions));
app.use(express.json({ limit: '1mb' })); // Limit payload size
app.use(express.static('public'));

// ──────────────────────────────────────────────
// Данные
// ──────────────────────────────────────────────

let users = [];
let allMessages = [];

const USERS_FILE = 'users.json';
const MESSAGES_FILE = 'messages.json';

function loadData() {
  try {
    if (fs.existsSync(USERS_FILE)) users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    if (fs.existsSync(MESSAGES_FILE)) allMessages = JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8'));
    
    // Очищаем невалидные сообщения
    const beforeClean = allMessages.length;
    allMessages = allMessages.filter(m => {
      const parts = m.chatId.split('-');
      return parts.length === 2 && parts[0] && parts[1]; // Оставляем только валидные chatId
    });
    if (beforeClean > allMessages.length) {
      console.log(`✅ Удалено невалидных сообщений: ${beforeClean - allMessages.length}`);
      saveMessages();
    }
  } catch (e) {
    console.error('Ошибка при загрузке данных:', e);
  }
}

function saveUsers() { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); }
function saveMessages() { fs.writeFileSync(MESSAGES_FILE, JSON.stringify(allMessages, null, 2)); }

// 🔐 Валидация username
function validateUsername(username) {
  const regex = /^[a-zA-Z0-9_]{3,20}$/;
  return regex.test(username);
}

// 🔐 Валидация пароля
function validatePassword(password) {
  if (password.length < 12) return { valid: false, error: 'Пароль должен быть минимум 12 символов' };
  if (!/[A-Z]/.test(password)) return { valid: false, error: 'Пароль должен содержать заглавные буквы' };
  if (!/[a-z]/.test(password)) return { valid: false, error: 'Пароль должен содержать строчные буквы' };
  if (!/\d/.test(password)) return { valid: false, error: 'Пароль должен содержать цифры' };
  return { valid: true };
}

loadData();

// Создаём админа, если его нет
if (users.length === 0) {
  users.push({
    username: "admin",
    passwordHash: bcrypt.hashSync("123456", 10)
  });
  saveUsers();
  console.log('Создан админ: admin / 123456');
}

// ──────────────────────────────────────────────
// API
// ──────────────────────────────────────────────

// 🔐 Rate limiting для login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 5, // максимум 5 попыток
  message: 'Слишком много попыток входа, попробуйте позже',
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Введите логин и пароль' });
  }
  
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username });
});

app.get('/api/me', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Нет токена' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = users.find(u => u.username === payload.username);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json({ username: user.username, avatar: user.avatar });
  } catch (err) {
    res.status(401).json({ error: 'Недействительный токен' });
  }
});

app.post('/api/create-user', (req, res) => {
  const { username, password } = req.body;
  
  // 🔐 Валидация username
  if (!validateUsername(username)) {
    return res.status(400).json({ error: 'Логин: 3-20 символов (буквы, цифры, подчеркивание)' });
  }
  
  // 🔐 Валидация пароля
  const passwordCheck = validatePassword(password);
  if (!passwordCheck.valid) {
    return res.status(400).json({ error: passwordCheck.error });
  }
  
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Пользователь уже существует' });
  }

  const newUser = {
    username,
    passwordHash: bcrypt.hashSync(password, 10)
  };
  users.push(newUser);
  saveUsers();
  res.json({ success: true, message: `Пользователь ${username} создан` });
});

app.get('/api/users', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Нет токена' });
  }
  
  const token = authHeader.split(' ')[1];
  let username;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    username = payload.username;
  } catch (err) {
    return res.status(401).json({ error: 'Недействительный токен' });
  }

  // Только админ может получить список всех пользователей
  if (username !== 'admin') {
    return res.status(403).json({ error: 'Только администратор может просмотреть список пользователей' });
  }

  const userList = users.map(u => ({
    username: u.username,
    avatar: u.avatar
  }));
  res.json(userList);
});

app.post('/api/change-password', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Нет токена' });
  }
  
  const token = authHeader.split(' ')[1];
  let currentUsername;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    currentUsername = payload.username;
  } catch (err) {
    return res.status(401).json({ error: 'Недействительный токен' });
  }

  const { targetUsername, oldPassword, newPassword } = req.body;
  
  // 🔐 Валидация нового пароля
  const passwordCheck = validatePassword(newPassword);
  if (!passwordCheck.valid) {
    return res.status(400).json({ error: passwordCheck.error });
  }
  
  // Определяем целевого пользователя
  const target = targetUsername || currentUsername;
  
  // Если это не админ и пытается менять пароль другому пользователю
  if (currentUsername !== 'admin' && target !== currentUsername) {
    return res.status(403).json({ error: 'Вы можете менять только свой пароль' });
  }

  // Если это не админ, требуется старый пароль
  if (currentUsername !== 'admin' && !oldPassword) {
    return res.status(400).json({ error: 'Требуется старый пароль' });
  }

  if (!newPassword) {
    return res.status(400).json({ error: 'Требуется новый пароль' });
  }

  const user = users.find(u => u.username === target);
  if (!user) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }

  // Если это не админ, проверяем старый пароль
  if (currentUsername !== 'admin') {
    if (!bcrypt.compareSync(oldPassword, user.passwordHash)) {
      return res.status(401).json({ error: 'Старый пароль неверен' });
    }
  }

  user.passwordHash = bcrypt.hashSync(newPassword, 10);
  saveUsers();
  res.json({ success: true, message: `Пароль пользователя ${target} успешно изменён` });
});

// ──────────────────────────────────────────────
// Socket.IO
// ──────────────────────────────────────────────

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Нет токена'));
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.username = payload.username;
    next();
  } catch (err) {
    next(new Error('Неверный токен'));
  }
});

io.on('connection', (socket) => {
  console.log(`👤 ${socket.username} подключился`);

  // Список чатов пользователя
  socket.on('get-chats', () => {
    const chats = new Set();
    allMessages.forEach(m => {
      const parts = m.chatId.split('-');
      if (parts.length !== 2 || !parts[0] || !parts[1]) return; // Пропускаем невалидные chatId
      const [u1, u2] = parts;
      if (u1 === socket.username || u2 === socket.username) {
        const otherUser = u1 === socket.username ? u2 : u1;
        // Проверяем что пользователь еще существует
        if (otherUser && users.find(u => u.username === otherUser)) {
          chats.add(otherUser);
        }
      }
    });
    socket.emit('your-chats', Array.from(chats));
  });

  // Присоединиться к чату
  socket.on('join-chat', (otherUsername) => {
    // Проверяем что пользователь существует
    if (!otherUsername || !users.find(u => u.username === otherUsername)) {
      return socket.emit('error', 'Пользователь не найден');
    }
    const chatId = [socket.username, otherUsername].sort().join('-');
    socket.join(chatId);

    // Отправляем историю
    const history = allMessages.filter(m => m.chatId === chatId);
    socket.emit('chat-history', history);
  });

  // Отправка сообщения
  socket.on('send-message', ({ otherUsername, cipher, time }) => {
    // Проверяем что пользователь существует
    if (!otherUsername || !users.find(u => u.username === otherUsername)) {
      return socket.emit('error', 'Пользователь не найден');
    }
    const chatId = [socket.username, otherUsername].sort().join('-');
    const msg = {
      id: Date.now() + '',
      chatId,
      from: socket.username,
      cipher,
      time,
      timestamp: Date.now() // 🔐 Добавляем временную метку для валидации
    };
    allMessages.push(msg);
    saveMessages();

    io.to(chatId).emit('new-message', msg);
  });

  // Удаление чата - 🔐 только участники могут удалить
  socket.on('delete-chat', (otherUsername) => {
    // Проверяем что пользователь существует
    if (!otherUsername || !users.find(u => u.username === otherUsername)) {
      return socket.emit('error', 'Пользователь не найден');
    }
    
    // Генерируем правильный chatId
    const chatId = [socket.username, otherUsername].sort().join('-');
    console.log(`Удаление чата: ${chatId} инициирован ${socket.username}`);
    
    const before = allMessages.length;
    allMessages = allMessages.filter(m => m.chatId !== chatId);
    const after = allMessages.length;
    console.log(`Удалено сообщений: ${before - after}`);
    saveMessages();
    
    // 🔐 Отправляем только участникам чата
    io.to(chatId).emit('chat-deleted', chatId);
  });

  socket.on('disconnect', () => {
    console.log(`❌ ${socket.username} отключился`);
  });
});

// 🔐 HTTPS редирект в production
if (NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
      res.redirect(`https://${req.header('host')}${req.url}`);
    } else {
      next();
    }
  });
}

server.listen(PORT, '0.0.0.0', () => {
  if (NODE_ENV === 'production') {
    console.log(`🔒 HTTPS сервер запущен на порту ${PORT}`);
  } else {
    console.log(`📡 HTTP сервер запущен на http://localhost:${PORT}`);
    console.log(`Также доступен по http://<ваш-ip>:${PORT} в локальной сети`);
  }
});
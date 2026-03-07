import express from 'express';
import https from 'https';
import http from 'http';
import { Server } from 'socket.io';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import fs from 'fs';
import cors from 'cors';

const app = express();

// Выбираем HTTP или HTTPS в зависимости от переменной окружения
let server;
const PORT = process.env.PORT || 443;

if (process.env.NODE_ENV === 'production') {
  // HTTPS для продакшена
  const options = {
    key: fs.readFileSync('/etc/letsencrypt/live/browsermessage.run.place/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/browsermessage.run.place/fullchain.pem')
  };
  server = https.createServer(options, app);
  console.log('🔒 HTTPS mode');
} else {
  // HTTP для разработки (на локальном компе)
  server = http.createServer(app);
  console.log('📡 HTTP mode (dev)');
}

const io = new Server(server, { cors: { origin: "*" } });

const JWT_SECRET = 'crypto-chat-super-secret-2026-change-this-in-production';

app.use(cors());
app.use(express.json());
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

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
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
  if (users.find(u => u.username === username)) return res.status(400).json({ error: 'Пользователь уже существует' });

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
      time
    };
    allMessages.push(msg);
    saveMessages();

    io.to(chatId).emit('new-message', msg);
  });

  // Удаление чата
  socket.on('delete-chat', (chatId) => {
    console.log(`Удаление чата: ${chatId}`);
    const before = allMessages.length;
    allMessages = allMessages.filter(m => m.chatId !== chatId);
    const after = allMessages.length;
    console.log(`Удалено сообщений: ${before - after}`);
    saveMessages();
    
    io.emit('chat-deleted', chatId);
  });

  socket.on('disconnect', () => {
    console.log(`❌ ${socket.username} отключился`);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  if (process.env.NODE_ENV === 'production') {
    console.log(`🔒 HTTPS сервер запущен на https://browsermessage.run.place`);
  } else {
    console.log(`📡 HTTP сервер запущен на http://localhost:${PORT}`);
    console.log(`Также доступен по http://<ваш-ip>:${PORT} в локальной сети`);
  }
});
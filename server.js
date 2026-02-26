import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import fs from 'fs';
import cors from 'cors';

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const JWT_SECRET = 'crypto-chat-super-secret-2026-change-this-in-production';
const PORT = 3000;

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
  } catch (e) {}
}

function saveUsers() { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); }
function saveMessages() { fs.writeFileSync(MESSAGES_FILE, JSON.stringify(allMessages, null, 2)); }

loadData();

// Создаём админа, если его нет
if (users.length === 0) {
  users.push({
    username: "admin",
    passwordHash: bcrypt.hashSync("123456", 10),
    avatar: "https://i.pravatar.cc/128?u=admin"
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
  res.json({ token, username, avatar: user.avatar });
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
    passwordHash: bcrypt.hashSync(password, 10),
    avatar: `https://i.pravatar.cc/128?u=${username}`
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
      const [u1, u2] = m.chatId.split('-');
      if (u1 === socket.username || u2 === socket.username) {
        chats.add(u1 === socket.username ? u2 : u1);
      }
    });
    socket.emit('your-chats', Array.from(chats));
  });

  // Присоединиться к чату
  socket.on('join-chat', (otherUsername) => {
    const chatId = [socket.username, otherUsername].sort().join('-');
    socket.join(chatId);

    // Отправляем историю
    const history = allMessages.filter(m => m.chatId === chatId);
    socket.emit('chat-history', history);
  });

  // Отправка сообщения
  socket.on('send-message', ({ otherUsername, cipher, time }) => {
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

  socket.on('disconnect', () => {
    console.log(`❌ ${socket.username} отключился`);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Сервер запущен на http://localhost:${PORT}`);
  console.log(`Также доступен по http://<ваш-ip>:${PORT} в локальной сети`);
});
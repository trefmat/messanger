let socket;
let currentUser = null;
let currentChat = null;
let pendingChatId = null;
let chatKeys = {};
let isLoggingIn = false;
let isBootstrapping = false;
let isUploadingFile = false;
let allChats = [];
let chatSearchQuery = '';
let directoryUsers = [];
let selectedGroupMembers = new Set();
let directoryUsersLoadedAt = 0;
let pendingDeleteChat = null;

const DIRECTORY_CACHE_TTL_MS = 60_000;

const CHAT_BACKGROUND_KEY = 'chatBackgroundTheme';
const CHAT_KEYS_STORAGE_KEY = 'sessionChatKeys';
const CHAT_BACKGROUND_THEMES = ['aurora', 'forest', 'lagoon', 'sunset', 'dunes'];
const MIN_PASSWORD_LENGTH = 6;
const BLOCKED_PASSWORDS = new Set(['ChangeMe123!', 'Password123!', 'Qwerty123!', 'Admin123!', '12345678']);
const KDF_ITERATIONS = 120000;
const KDF_KEY_SIZE_WORDS = 16;
const MAX_FILE_SIZE_BYTES = 8 * 1024 * 1024;

function loadChatKeys() {
    let saved = sessionStorage.getItem(CHAT_KEYS_STORAGE_KEY);
    if (!saved) {
        const legacySaved = localStorage.getItem('encryptedChatKeys');
        if (legacySaved) {
            sessionStorage.setItem(CHAT_KEYS_STORAGE_KEY, legacySaved);
            localStorage.removeItem('encryptedChatKeys');
            saved = legacySaved;
        }
    }
    if (!saved) return {};

    try {
        const parsed = JSON.parse(saved);
        return parsed && typeof parsed === 'object' ? parsed : {};
    } catch {
        return {};
    }
}

function saveChatKeys(keys) {
    sessionStorage.setItem(CHAT_KEYS_STORAGE_KEY, JSON.stringify(keys));
}

function clearChatKeys() {
    sessionStorage.removeItem(CHAT_KEYS_STORAGE_KEY);
}

function validatePasswordPolicyClient(password) {
    if (typeof password !== 'string') return 'Пароль должен быть строкой';
    if (password.length < MIN_PASSWORD_LENGTH) {
        return `Пароль: минимум ${MIN_PASSWORD_LENGTH} символов`;
    }
    if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
        return 'Добавьте строчные, заглавные, цифру и спецсимвол';
    }
    if (BLOCKED_PASSWORDS.has(password)) {
        return 'Этот пароль запрещён: выберите более уникальный';
    }
    return null;
}

function notify(message, type = 'info', timeout = 2800) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), timeout);
}

async function parseJsonResponse(response) {
    const raw = await response.text();
    if (!raw) return null;

    try {
        return JSON.parse(raw);
    } catch {
        throw new Error(`Сервер вернул не JSON (HTTP ${response.status})`);
    }
}

async function requestJson(url, options = {}) {
    const init = { credentials: 'same-origin', ...options };
    const headers = new Headers(init.headers || {});
    const hasBody = typeof init.body === 'string';
    if (hasBody && !headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
    }
    init.headers = headers;

    const response = await fetch(url, init);
    const data = await parseJsonResponse(response);

    if (!response.ok) {
        throw new Error((data && data.error) ? data.error : `Ошибка HTTP ${response.status}`);
    }

    return data;
}

async function fetchDirectoryUsers() {
    if (directoryUsers.length > 0 && (Date.now() - directoryUsersLoadedAt) < DIRECTORY_CACHE_TTL_MS) {
        return directoryUsers;
    }

    const directory = await requestJson('/api/directory');
    directoryUsers = uniqueNames(
        (Array.isArray(directory) ? directory : [])
            .filter((username) => username !== currentUser?.username)
    );
    directoryUsersLoadedAt = Date.now();
    return directoryUsers;
}

function uniqueNames(values) {
    return Array.from(
        new Set(
            (Array.isArray(values) ? values : [])
                .map((value) => String(value || '').trim())
                .filter(Boolean)
        )
    );
}

function getDirectChatId(left, right) {
    return [String(left || '').trim(), String(right || '').trim()].sort().join('-');
}

function normalizeChatSummary(raw) {
    if (!raw) return null;

    if (typeof raw === 'string') {
        const title = raw.trim();
        if (!title) return null;
        const members = currentUser ? uniqueNames([currentUser.username, title]) : [title];
        return {
            id: currentUser ? getDirectChatId(currentUser.username, title) : title,
            type: 'direct',
            title,
            members,
            memberCount: members.length,
            canDelete: true,
            createdAt: Date.now(),
            lastTimestamp: Date.now(),
            otherUsername: title
        };
    }

    const type = raw.type === 'group' ? 'group' : 'direct';
    const members = uniqueNames(raw.members);
    const otherUsername = type === 'direct'
        ? String(raw.otherUsername || members.find((member) => member !== currentUser?.username) || '').trim()
        : '';
    const title = String(raw.title || otherUsername || 'Чат').trim();
    const id = String(raw.id || (type === 'direct' && members.length >= 2
        ? getDirectChatId(members[0], members[1])
        : '')).trim();

    if (!id || !title) {
        return null;
    }

    return {
        id,
        type,
        title,
        members,
        memberCount: Number(raw.memberCount) || members.length || 0,
        canDelete: Boolean(raw.canDelete),
        createdAt: Number(raw.createdAt) || Date.now(),
        lastTimestamp: Number(raw.lastTimestamp) || Number(raw.createdAt) || Date.now(),
        otherUsername
    };
}

function updateComposerState() {
    const hasChat = Boolean(currentChat);
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-message-btn');
    const attachButton = document.getElementById('attach-file-btn');
    const keyButton = document.getElementById('open-key-modal-btn');

    if (messageInput) {
        messageInput.disabled = !hasChat;
        messageInput.placeholder = hasChat ? 'Напишите сообщение...' : 'Выберите чат, чтобы писать';
    }

    [sendButton, attachButton, keyButton].forEach((element) => {
        if (!element) return;
        element.disabled = !hasChat;
        element.style.opacity = hasChat ? '1' : '0.45';
        element.style.pointerEvents = hasChat ? 'auto' : 'none';
    });
}

function renderChatHeaderAvatar(chat) {
    const avatar = document.getElementById('chat-header-avatar');
    if (!avatar) return;

    avatar.textContent = '';
    avatar.innerHTML = '';
    avatar.className = 'w-10 h-10 rounded-2xl overflow-hidden ring-2 flex items-center justify-center text-white font-semibold';

    const label = document.createElement('div');
    label.className = 'w-full h-full flex items-center justify-center text-white text-lg font-semibold';

    if (!chat) {
        avatar.style.background = 'linear-gradient(135deg, #10b981, #047857)';
        label.textContent = '?';
        avatar.appendChild(label);
        return;
    }

    const isGroup = chat.type === 'group';
    avatar.style.background = isGroup
        ? 'linear-gradient(135deg, #3b82f6, #1d4ed8)'
        : 'linear-gradient(135deg, #10b981, #047857)';
    label.textContent = String(chat.title || '?').charAt(0).toUpperCase() || '?';
    avatar.appendChild(label);
}

function renderChatHeader(chat) {
    const headerName = document.getElementById('chat-header-name');
    if (!chat) {
        if (headerName) {
            headerName.textContent = 'Выберите чат';
            headerName.title = '';
        }
        renderChatHeaderAvatar(null);
        updateComposerState();
        return;
    }

    if (headerName) {
        const suffix = chat.type === 'group' ? ` (${chat.memberCount} участников)` : '';
        headerName.textContent = `${chat.title}${suffix}`;
        headerName.title = chat.members.join(', ');
    }
    renderChatHeaderAvatar(chat);
    updateComposerState();
}

function clearChatView() {
    currentChat = null;
    pendingChatId = null;

    const messages = document.getElementById('messages');
    const messageInput = document.getElementById('message-input');
    const fileInput = document.getElementById('file-input');

    if (messages) {
        messages.innerHTML = '';
        messages.dataset.empty = 'false';
    }
    if (messageInput) {
        messageInput.value = '';
    }
    if (fileInput) {
        fileInput.value = '';
    }

    renderChatHeader(null);
}

function clearChatList() {
    allChats = [];
    const container = document.getElementById('chats-list');
    if (container) {
        container.innerHTML = '';
    }
}

function showLoginScreen() {
    document.getElementById('login-screen').classList.remove('hidden');
    document.getElementById('chat-screen').classList.add('hidden');
    document.getElementById('admin-btn').classList.add('hidden');
    document.getElementById('my-name').textContent = '';
    clearChatList();
    clearChatView();
    setMobileSidebar(false);
}

function showChatScreen(username) {
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('chat-screen').classList.remove('hidden');
    document.getElementById('my-name').textContent = username;
    document.getElementById('admin-btn').classList.toggle('hidden', username !== 'admin');
    updateComposerState();
}

function setCurrentChat(chat) {
    currentChat = normalizeChatSummary(chat);
    renderChatHeader(currentChat);
    renderChatsList();
}

function resetClientState({ clearKeys = true } = {}) {
    if (socket) {
        socket.removeAllListeners();
        socket.disconnect();
        socket = null;
    }

    currentUser = null;
    currentChat = null;
    pendingChatId = null;
    chatSearchQuery = '';
    isUploadingFile = false;
    directoryUsers = [];
    directoryUsersLoadedAt = 0;
    pendingDeleteChat = null;

    if (clearKeys) {
        clearChatKeys();
        chatKeys = {};
    }

    clearChatList();
    showLoginScreen();
}

async function login() {
    if (isLoggingIn) return;

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) {
        notify('Заполните логин и пароль', 'error');
        return;
    }

    try {
        isLoggingIn = true;
        const data = await requestJson('/api/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });

        currentUser = { username: data.username };
        chatKeys = loadChatKeys();
        showChatScreen(data.username);
        clearChatView();
        initSocket();
        document.getElementById('password').value = '';
    } catch (error) {
        console.error('Ошибка входа:', error);
        notify(`Ошибка входа: ${error.message || 'Неизвестная ошибка'}`, 'error');
    } finally {
        isLoggingIn = false;
    }
}

async function logout({ skipServer = false } = {}) {
    try {
        if (!skipServer) {
            await requestJson('/api/logout', { method: 'POST' });
        }
    } catch (error) {
        console.error('Ошибка выхода:', error);
    } finally {
        resetClientState();
    }
}

function initSocket() {
    if (socket && (socket.connected || socket.active)) {
        return;
    }

    if (socket) {
        socket.removeAllListeners();
        socket.disconnect();
    }

    socket = io({
        withCredentials: true,
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 3000
    });

    socket.on('connect', () => {
        socket.emit('get-chats');
        if (currentChat?.id) {
            pendingChatId = currentChat.id;
            socket.emit('join-chat', { chatId: currentChat.id });
        }
    });

    socket.on('your-chats', (chats) => {
        renderChats(chats);
    });

    socket.on('chats-changed', () => {
        if (socket) {
            socket.emit('get-chats');
        }
    });

    socket.on('chat-history', (payload) => {
        const chat = normalizeChatSummary(
            Array.isArray(payload) ? currentChat : payload?.chat
        );
        const messages = Array.isArray(payload) ? payload : payload?.messages;

        if (!chat) {
            return;
        }

        if (pendingChatId && chat.id !== pendingChatId && chat.id !== currentChat?.id) {
            return;
        }

        if (!pendingChatId && currentChat?.id && chat.id !== currentChat.id) {
            return;
        }

        pendingChatId = null;
        setCurrentChat(chat);
        renderMessages(messages, false);
    });

    socket.on('new-message', (message) => {
        if (!currentChat || message.chatId !== currentChat.id) {
            return;
        }
        renderMessages([message], true);
    });

    socket.on('chat-deleted', (chatId) => {
        if (chatKeys[chatId]) {
            delete chatKeys[chatId];
            saveChatKeys(chatKeys);
        }

        if (currentChat?.id === chatId || pendingChatId === chatId) {
            clearChatView();
            notify('Чат удалён', 'info');
        }

        if (socket) {
            socket.emit('get-chats');
        }
    });

    socket.on('chat-error', (message) => {
        notify(String(message), 'error');
    });

    socket.on('connect_error', (error) => {
        const message = String(error && error.message ? error.message : 'Ошибка соединения с сервером');
        notify(message, 'error');
        if (/сессия|токен/i.test(message)) {
            logout({ skipServer: true });
        }
    });
}

function updateBackgroundOptionsUI(theme) {
    document.querySelectorAll('.background-option[data-bg-theme]').forEach((el) => {
        el.classList.toggle('active', el.dataset.bgTheme === theme);
    });
}

function applyChatBackground(theme, persist = true) {
    const messagesEl = document.getElementById('messages');
    if (!messagesEl) return;
    const normalized = CHAT_BACKGROUND_THEMES.includes(theme) ? theme : 'aurora';
    CHAT_BACKGROUND_THEMES.forEach((key) => messagesEl.classList.remove(`theme-${key}`));
    messagesEl.classList.add(`theme-${normalized}`);
    if (persist) {
        localStorage.setItem(CHAT_BACKGROUND_KEY, normalized);
    }
    updateBackgroundOptionsUI(normalized);
}

function showBackgroundModal() {
    const current = localStorage.getItem(CHAT_BACKGROUND_KEY) || 'aurora';
    updateBackgroundOptionsUI(current);
    document.getElementById('background-modal').classList.remove('hidden');
}

function closeBackgroundModal() {
    document.getElementById('background-modal').classList.add('hidden');
}

function setupBackgroundControls() {
    const current = localStorage.getItem(CHAT_BACKGROUND_KEY) || 'aurora';
    applyChatBackground(current, false);
    document.querySelectorAll('.background-option[data-bg-theme]').forEach((btn) => {
        btn.addEventListener('click', () => {
            const theme = btn.dataset.bgTheme;
            applyChatBackground(theme, true);
        });
    });
}

function renderEmptyChatsState(message) {
    const container = document.getElementById('chats-list');
    if (!container) return;
    container.innerHTML = '';
    const empty = document.createElement('div');
    empty.className = 'px-5 py-4 text-zinc-500';
    empty.textContent = message;
    container.appendChild(empty);
}

function getChatSearchText(chat) {
    return [
        chat.title,
        chat.otherUsername,
        ...(Array.isArray(chat.members) ? chat.members : [])
    ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
}

function getChatSubtitle(chat) {
    if (chat.type === 'group') {
        const others = chat.members.filter((member) => member !== currentUser?.username);
        const preview = others.slice(0, 3).join(', ');
        const rest = others.length > 3 ? ` +${others.length - 3}` : '';
        return `${chat.memberCount} участников${preview ? ` • ${preview}${rest}` : ''}`;
    }

    return chat.otherUsername || chat.title;
}

function createSidebarAvatar(chat) {
    const avatar = document.createElement('div');
    avatar.className = 'w-10 h-10 rounded-2xl flex items-center justify-center text-white font-semibold';
    avatar.style.background = chat.type === 'group'
        ? 'linear-gradient(135deg, #3b82f6, #1d4ed8)'
        : 'linear-gradient(135deg, #10b981, #047857)';
    avatar.textContent = String(chat.title || '?').charAt(0).toUpperCase() || '?';
    return avatar;
}

function renderChatsList() {
    const container = document.getElementById('chats-list');
    if (!container) return;
    container.innerHTML = '';

    const query = chatSearchQuery.toLowerCase();
    const filtered = allChats.filter((chat) => getChatSearchText(chat).includes(query));

    if (filtered.length === 0) {
        renderEmptyChatsState(query ? 'Чаты не найдены' : 'Чатов пока нет');
        return;
    }

    filtered.forEach((chat) => {
        const item = document.createElement('div');
        item.className = `px-5 py-4 hover:bg-zinc-800 flex gap-4 items-center border-b border-zinc-800 group ${currentChat?.id === chat.id ? 'bg-zinc-800' : ''}`;

        const main = document.createElement('div');
        main.className = 'flex-1 cursor-pointer';

        const titleRow = document.createElement('div');
        titleRow.className = 'flex items-center justify-between gap-3';

        const title = document.createElement('div');
        title.className = 'font-medium';
        title.textContent = chat.title;

        const badge = document.createElement('div');
        badge.className = `text-10px ${chat.type === 'group' ? 'text-blue-400' : 'text-emerald-400'}`;
        badge.textContent = chat.type === 'group' ? 'Группа' : 'Личный';

        titleRow.appendChild(title);
        titleRow.appendChild(badge);

        const subtitle = document.createElement('div');
        subtitle.className = 'text-10px text-zinc-500 mt-1';
        subtitle.textContent = getChatSubtitle(chat);
        subtitle.title = chat.members.join(', ');

        main.appendChild(titleRow);
        main.appendChild(subtitle);

        item.appendChild(createSidebarAvatar(chat));
        item.appendChild(main);

        if (chat.canDelete) {
            const deleteBtn = document.createElement('button');
            deleteBtn.type = 'button';
            deleteBtn.className = 'delete-chat-btn text-zinc-500 hover:text-red-400 opacity-0 group-hover:opacity-100 transition';
            deleteBtn.title = 'Удалить чат';
            deleteBtn.innerHTML = '<i class="fa-solid fa-trash"></i>';
            deleteBtn.addEventListener('click', (event) => {
                event.stopPropagation();
                deleteChat(chat);
            });
            item.appendChild(deleteBtn);
        }

        item.addEventListener('click', () => openChat(chat));
        container.appendChild(item);
    });
}

function renderChats(chatSummaries) {
    allChats = (Array.isArray(chatSummaries) ? chatSummaries : [])
        .map((chat) => normalizeChatSummary(chat))
        .filter(Boolean)
        .sort((left, right) => {
            const byTimestamp = (right.lastTimestamp || 0) - (left.lastTimestamp || 0);
            if (byTimestamp !== 0) return byTimestamp;
            return String(left.title).localeCompare(String(right.title), 'ru', { sensitivity: 'base' });
        });

    if (currentChat?.id) {
        const updatedChat = allChats.find((chat) => chat.id === currentChat.id) || null;
        if (updatedChat) {
            currentChat = updatedChat;
            renderChatHeader(currentChat);
        } else {
            clearChatView();
        }
    }

    renderChatsList();
}

function setupChatSearch() {
    const input = document.getElementById('search');
    if (!input) return;
    input.addEventListener('input', () => {
        chatSearchQuery = String(input.value || '').trim().toLowerCase();
        renderChatsList();
    });
}

function buildJoinPayload(target) {
    if (!target) return null;

    if (typeof target === 'string') {
        const username = target.trim();
        return username ? { username } : null;
    }

    if (typeof target === 'object') {
        const chatId = String(target.chatId || target.id || '').trim();
        if (chatId) {
            return { chatId };
        }

        const username = String(target.username || target.otherUsername || '').trim();
        if (username) {
            return { username };
        }
    }

    return null;
}

function openChat(target, { silent = false } = {}) {
    const payload = buildJoinPayload(target);
    if (!payload) {
        if (!silent) notify('Невалидный чат', 'error');
        return;
    }
    if (!socket) {
        notify('Нет соединения с сервером', 'error');
        return;
    }

    pendingChatId = payload.chatId || (payload.username && currentUser
        ? getDirectChatId(currentUser.username, payload.username)
        : null);

    let resolved = false;
    const ackTimeout = setTimeout(() => {
        if (!resolved && !silent) {
            notify('Нет ответа сервера при открытии чата', 'error');
        }
    }, 4000);

    socket.emit('join-chat', payload, (response) => {
        resolved = true;
        clearTimeout(ackTimeout);

        if (!response || !response.ok || !response.chat) {
            pendingChatId = null;
            if (!silent) {
                notify((response && response.error) ? response.error : 'Чат не найден', 'error');
            }
            return;
        }

        setCurrentChat(response.chat);
        pendingChatId = currentChat.id;

        if (window.innerWidth < 768) {
            setMobileSidebar(false);
        }
    });
}

function closeNewChatModal() {
    document.getElementById('new-chat-modal').classList.add('hidden');
}

function closeGroupModal() {
    document.getElementById('group-modal').classList.add('hidden');
    document.getElementById('group-title-input').value = '';
    selectedGroupMembers = new Set();
    renderGroupSelectedUsers();
}

function showDeleteChatModal(chat) {
    pendingDeleteChat = chat || null;
    if (!pendingDeleteChat) return;

    const text = document.getElementById('delete-chat-modal-text');
    if (text) {
        text.textContent = `Удалить чат с ${pendingDeleteChat.title}?`;
    }

    document.getElementById('delete-chat-modal').classList.remove('hidden');
}

function closeDeleteChatModal() {
    pendingDeleteChat = null;
    document.getElementById('delete-chat-modal').classList.add('hidden');
}

function confirmDeleteChat() {
    const chat = pendingDeleteChat;
    if (!socket || !chat?.canDelete) {
        closeDeleteChatModal();
        return;
    }

    socket.emit('delete-chat', { chatId: chat.id });

    if (chatKeys[chat.id]) {
        delete chatKeys[chat.id];
        saveChatKeys(chatKeys);
    }

    if (currentChat?.id === chat.id) {
        clearChatView();
    }

    closeDeleteChatModal();
    socket.emit('get-chats');
}

function renderNewChatOptions(users) {
    const container = document.getElementById('new-chat-users');
    container.innerHTML = '';

    users.forEach((username) => {
        const card = document.createElement('button');
        card.type = 'button';
        card.className = 'selection-card';
        card.innerHTML = `
            <div class="selection-card-title">${username}</div>
            <div class="selection-card-hint">Открыть личный чат</div>
        `;
        card.addEventListener('click', () => {
            closeNewChatModal();
            openChat({ username });
        });
        container.appendChild(card);
    });
}

function renderGroupSelectedUsers() {
    const selected = document.getElementById('group-selected-users');
    const usersContainer = document.getElementById('group-users');
    if (!selected || !usersContainer) return;

    selected.innerHTML = '';

    const members = Array.from(selectedGroupMembers);
    if (members.length === 0) {
        const empty = document.createElement('span');
        empty.className = 'modal-muted';
        empty.textContent = 'Пока никто не выбран';
        selected.appendChild(empty);
    } else {
        members.forEach((username) => {
            const chip = document.createElement('span');
            chip.className = 'selected-user-chip';
            chip.textContent = username;
            selected.appendChild(chip);
        });
    }

    Array.from(usersContainer.children).forEach((card) => {
        const username = card.dataset.username;
        const isActive = selectedGroupMembers.has(username);
        card.classList.toggle('active', isActive);
        const hint = card.querySelector('.selection-card-hint');
        if (hint) {
            hint.textContent = isActive ? 'Участник будет добавлен' : 'Нажмите, чтобы добавить';
        }
    });
}

function renderGroupOptions(users) {
    const container = document.getElementById('group-users');
    container.innerHTML = '';

    users.forEach((username) => {
        const card = document.createElement('button');
        card.type = 'button';
        card.className = 'selection-card';
        card.dataset.username = username;
        card.innerHTML = `
            <div class="selection-card-title">${username}</div>
            <div class="selection-card-hint">Нажмите, чтобы добавить</div>
        `;
        card.addEventListener('click', () => {
            if (selectedGroupMembers.has(username)) {
                selectedGroupMembers.delete(username);
            } else {
                selectedGroupMembers.add(username);
            }
            renderGroupSelectedUsers();
        });
        container.appendChild(card);
    });

    renderGroupSelectedUsers();
}

async function newChatPrompt() {
    if (!currentUser) return;

    try {
        const users = await fetchDirectoryUsers();
        if (users.length === 0) {
            notify('Нет доступных пользователей для нового чата', 'error');
            return;
        }

        renderNewChatOptions(users);
        document.getElementById('new-chat-modal').classList.remove('hidden');
    } catch (error) {
        notify(`Не удалось открыть новый чат: ${error.message}`, 'error');
    }
}

async function createGroupPrompt() {
    if (!currentUser) return;

    try {
        const users = await fetchDirectoryUsers();
        if (users.length === 0) {
            notify('Сначала создайте других пользователей', 'error');
            return;
        }

        selectedGroupMembers = new Set();
        document.getElementById('group-title-input').value = '';
        renderGroupOptions(users);
        document.getElementById('group-modal').classList.remove('hidden');
    } catch (error) {
        notify(`Не удалось открыть форму группы: ${error.message}`, 'error');
    }
}

async function submitGroupModal() {
    const title = String(document.getElementById('group-title-input').value || '').trim();
    const requestedMembers = Array.from(selectedGroupMembers);

    if (!title) {
        notify('Введите название группы', 'error');
        return;
    }
    if (title.length < 3 || title.length > 60) {
        notify('Название группы: от 3 до 60 символов', 'error');
        return;
    }
    if (requestedMembers.length === 0) {
        notify('Добавьте хотя бы одного участника', 'error');
        return;
    }

    try {
        const data = await requestJson('/api/groups', {
            method: 'POST',
            body: JSON.stringify({
                title,
                members: requestedMembers
            })
        });

        closeGroupModal();
        notify('Группа создана', 'success');
        if (socket) {
            socket.emit('get-chats');
        }
        if (data?.chat) {
            openChat(data.chat, { silent: true });
        }
    } catch (error) {
        notify(`Не удалось создать группу: ${error.message}`, 'error');
    }
}

function wordArrayToBase64(wordArray) {
    return CryptoJS.enc.Base64.stringify(wordArray);
}

function base64ToWordArray(value) {
    return CryptoJS.enc.Base64.parse(value);
}

function arrayBufferToWordArray(value) {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
    const words = [];

    for (let index = 0; index < bytes.length; index += 1) {
        words[index >>> 2] = words[index >>> 2] || 0;
        words[index >>> 2] |= bytes[index] << (24 - (index % 4) * 8);
    }

    return CryptoJS.lib.WordArray.create(words, bytes.length);
}

function wordArrayToUint8Array(wordArray) {
    const { words, sigBytes } = wordArray;
    const length = Math.max(sigBytes || 0, 0);
    const bytes = new Uint8Array(length);

    for (let index = 0; index < length; index += 1) {
        bytes[index] = (words[index >>> 2] >>> (24 - (index % 4) * 8)) & 0xff;
    }

    return bytes;
}

function deriveCryptoKeys(passphrase, saltWordArray) {
    const derived = CryptoJS.PBKDF2(passphrase, saltWordArray, {
        keySize: KDF_KEY_SIZE_WORDS,
        iterations: KDF_ITERATIONS,
        hasher: CryptoJS.algo.SHA256
    });

    return {
        encKey: CryptoJS.lib.WordArray.create(derived.words.slice(0, 8), 32),
        macKey: CryptoJS.lib.WordArray.create(derived.words.slice(8, 16), 32)
    };
}

function secureCompareBase64(left, right) {
    if (typeof left !== 'string' || typeof right !== 'string') return false;

    try {
        const leftHex = CryptoJS.enc.Hex.stringify(base64ToWordArray(left));
        const rightHex = CryptoJS.enc.Hex.stringify(base64ToWordArray(right));
        if (leftHex.length !== rightHex.length) return false;

        let diff = 0;
        for (let index = 0; index < leftHex.length; index += 1) {
            diff |= leftHex.charCodeAt(index) ^ rightHex.charCodeAt(index);
        }
        return diff === 0;
    } catch {
        return false;
    }
}

function buildMacInput(version, salt, iv, ciphertextBase64) {
    return `${version}.${salt}.${iv}.${ciphertextBase64}`;
}

function encrypt(text, key) {
    const salt = CryptoJS.lib.WordArray.random(16);
    const iv = CryptoJS.lib.WordArray.random(16);
    const { encKey, macKey } = deriveCryptoKeys(key, salt);
    const encrypted = CryptoJS.AES.encrypt(text, encKey, {
        iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });

    const payload = {
        v: 2,
        s: wordArrayToBase64(salt),
        iv: wordArrayToBase64(iv),
        ct: wordArrayToBase64(encrypted.ciphertext)
    };
    payload.mac = CryptoJS.HmacSHA256(
        buildMacInput(payload.v, payload.s, payload.iv, payload.ct),
        macKey
    ).toString(CryptoJS.enc.Base64);

    return JSON.stringify(payload);
}

function decryptLegacy(cipher, key) {
    try {
        const bytes = CryptoJS.AES.decrypt(cipher, key);
        return bytes.toString(CryptoJS.enc.Utf8) || '[Ошибка]';
    } catch {
        return '[Ошибка расшифровки]';
    }
}

function decrypt(cipher, key) {
    if (typeof cipher !== 'string' || !cipher.trim()) {
        return '[Ошибка расшифровки]';
    }

    let payload = null;
    try {
        payload = JSON.parse(cipher);
    } catch {
        return decryptLegacy(cipher, key);
    }

    if (!payload || payload.v !== 2 || !payload.s || !payload.iv || !payload.ct || !payload.mac) {
        return decryptLegacy(cipher, key);
    }

    try {
        const salt = base64ToWordArray(payload.s);
        const iv = base64ToWordArray(payload.iv);
        const ciphertext = base64ToWordArray(payload.ct);
        const { encKey, macKey } = deriveCryptoKeys(key, salt);
        const expectedMac = CryptoJS.HmacSHA256(
            buildMacInput(payload.v, payload.s, payload.iv, payload.ct),
            macKey
        ).toString(CryptoJS.enc.Base64);

        if (!secureCompareBase64(expectedMac, payload.mac)) {
            return '[Нарушена целостность сообщения]';
        }

        const decrypted = CryptoJS.AES.decrypt(
            CryptoJS.lib.CipherParams.create({ ciphertext }),
            encKey,
            { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
        );
        return decrypted.toString(CryptoJS.enc.Utf8) || '[Ошибка]';
    } catch {
        return '[Ошибка расшифровки]';
    }
}

function encryptBinary(arrayBuffer, key) {
    const version = 2;
    const salt = CryptoJS.lib.WordArray.random(16);
    const iv = CryptoJS.lib.WordArray.random(16);
    const { encKey, macKey } = deriveCryptoKeys(key, salt);
    const plaintext = arrayBufferToWordArray(arrayBuffer);
    const encrypted = CryptoJS.AES.encrypt(plaintext, encKey, {
        iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });

    const saltBase64 = wordArrayToBase64(salt);
    const ivBase64 = wordArrayToBase64(iv);
    const ciphertextBase64 = wordArrayToBase64(encrypted.ciphertext);
    const mac = CryptoJS.HmacSHA256(
        buildMacInput(version, saltBase64, ivBase64, ciphertextBase64),
        macKey
    ).toString(CryptoJS.enc.Base64);

    return {
        bytes: wordArrayToUint8Array(encrypted.ciphertext),
        crypto: {
            v: version,
            s: saltBase64,
            iv: ivBase64,
            mac
        }
    };
}

function decryptBinary(arrayBuffer, key, cryptoMeta) {
    if (!cryptoMeta || Number(cryptoMeta.v) !== 2 || !cryptoMeta.s || !cryptoMeta.iv || !cryptoMeta.mac) {
        throw new Error('Некорректные параметры шифрования файла');
    }

    const salt = base64ToWordArray(cryptoMeta.s);
    const iv = base64ToWordArray(cryptoMeta.iv);
    const ciphertext = arrayBufferToWordArray(arrayBuffer);
    const ciphertextBase64 = wordArrayToBase64(ciphertext);
    const { encKey, macKey } = deriveCryptoKeys(key, salt);
    const expectedMac = CryptoJS.HmacSHA256(
        buildMacInput(2, cryptoMeta.s, cryptoMeta.iv, ciphertextBase64),
        macKey
    ).toString(CryptoJS.enc.Base64);

    if (!secureCompareBase64(expectedMac, cryptoMeta.mac)) {
        throw new Error('Неверный ключ или файл повреждён');
    }

    const decrypted = CryptoJS.AES.decrypt(
        CryptoJS.lib.CipherParams.create({ ciphertext }),
        encKey,
        { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
    );

    return wordArrayToUint8Array(decrypted);
}

function formatFileSize(bytes) {
    const size = Number(bytes) || 0;
    if (size < 1024) return `${size} Б`;
    if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} КБ`;
    return `${(size / (1024 * 1024)).toFixed(2)} МБ`;
}

function renderMessages(messages, append = false) {
    const container = document.getElementById('messages');
    if (!container || !currentChat) return;

    const list = (Array.isArray(messages) ? messages : [])
        .filter((message) => message && message.chatId === currentChat.id)
        .sort((left, right) => (left.timestamp || 0) - (right.timestamp || 0));

    if (!append) {
        container.innerHTML = '';
        container.dataset.empty = 'false';
    } else if (container.dataset.empty === 'true') {
        container.innerHTML = '';
        container.dataset.empty = 'false';
    }

    if (!append && list.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'text-zinc-500 text-center mt-8';
        empty.textContent = 'Сообщений пока нет';
        container.appendChild(empty);
        container.dataset.empty = 'true';
        return;
    }

    const key = chatKeys[currentChat.id];

    list.forEach((message) => {
        const isMe = message.from === currentUser?.username;
        const row = document.createElement('div');
        row.className = `flex ${isMe ? 'justify-end' : 'justify-start'}`;

        const bubble = document.createElement('div');
        bubble.className = `message-bubble ${isMe ? 'me' : 'them'}`;

        if (currentChat.type === 'group' && !isMe) {
            const sender = document.createElement('div');
            sender.className = 'text-10px text-blue-400';
            sender.style.marginBottom = '6px';
            sender.textContent = message.from || 'Участник';
            bubble.appendChild(sender);
        }

        if (message.kind === 'file' && message.file) {
            const title = document.createElement('div');
            title.className = 'text-15px break-words font-medium';
            title.textContent = `Файл: ${message.file.name || 'file.bin'}`;

            const meta = document.createElement('div');
            meta.className = 'text-10px opacity-70 mt-1';
            meta.textContent = `${formatFileSize(message.file.size)} • ${message.file.mimeType || 'application/octet-stream'}`;

            const action = document.createElement('button');
            action.type = 'button';
            action.className = 'mt-4 py-2 px-4 bg-zinc-900 hover:bg-zinc-800 rounded-xl text-sm';
            action.textContent = key ? 'Скачать и расшифровать' : 'Сначала задайте ключ';
            action.disabled = !key;
            action.style.opacity = key ? '1' : '0.6';
            action.style.cursor = key ? 'pointer' : 'not-allowed';
            action.addEventListener('click', () => downloadFileMessage(message));

            bubble.appendChild(title);
            bubble.appendChild(meta);
            bubble.appendChild(action);
        } else {
            const text = key ? (decrypt(message.cipher, key) || '[Ошибка расшифровки]') : '[Ключ не задан]';
            const textDiv = document.createElement('div');
            textDiv.className = 'text-15px break-words';
            textDiv.textContent = text;
            bubble.appendChild(textDiv);
        }

        const timeDiv = document.createElement('div');
        timeDiv.className = 'text-10px opacity-70 text-right mt-1';
        timeDiv.textContent = String(message.time || '');

        bubble.appendChild(timeDiv);
        row.appendChild(bubble);
        container.appendChild(row);
    });

    container.scrollTop = container.scrollHeight;
}

function sendMessage() {
    const input = document.getElementById('message-input');
    const text = String(input.value || '').trim();

    if (!text || !currentChat || !socket) return;

    const key = chatKeys[currentChat.id];
    if (!key) {
        notify('Задайте ключ чата (иконка ключа)', 'error');
        return;
    }

    const cipher = encrypt(text, key);
    const time = new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
    socket.emit('send-message', { chatId: currentChat.id, cipher, time });
    input.value = '';
}

async function uploadSelectedFile(file) {
    const fileInput = document.getElementById('file-input');

    try {
        if (!file) return;
        if (!currentChat) {
            notify('Сначала выберите чат', 'error');
            return;
        }
        if (isUploadingFile) {
            notify('Файл уже загружается', 'info');
            return;
        }

        const key = chatKeys[currentChat.id];
        if (!key) {
            notify('Сначала задайте ключ чата', 'error');
            return;
        }
        if (file.size <= 0) {
            notify('Нельзя отправить пустой файл', 'error');
            return;
        }
        if (file.size > MAX_FILE_SIZE_BYTES) {
            notify('Максимальный размер файла: 8 МБ', 'error');
            return;
        }

        isUploadingFile = true;
        notify(`Шифрую файл "${file.name}"...`, 'info', 1800);

        const buffer = await file.arrayBuffer();
        const encrypted = encryptBinary(buffer, key);
        const time = new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });

        const response = await fetch(`/api/chats/${encodeURIComponent(currentChat.id)}/files`, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/octet-stream',
                'X-File-Name': encodeURIComponent(file.name || 'file.bin'),
                'X-File-Mime': file.type || 'application/octet-stream',
                'X-File-Size': String(file.size),
                'X-File-Version': String(encrypted.crypto.v),
                'X-File-Salt': encrypted.crypto.s,
                'X-File-Iv': encrypted.crypto.iv,
                'X-File-Mac': encrypted.crypto.mac,
                'X-File-Time': time
            },
            body: encrypted.bytes
        });

        const data = await parseJsonResponse(response);
        if (!response.ok) {
            throw new Error((data && data.error) ? data.error : `Ошибка HTTP ${response.status}`);
        }

        notify(`Файл "${file.name}" отправлен`, 'success');
        return data;
    } catch (error) {
        console.error('Ошибка отправки файла:', error);
        notify(`Не удалось отправить файл: ${error.message}`, 'error');
        if (/сессия|токен/i.test(String(error.message || ''))) {
            logout({ skipServer: true });
        }
        return null;
    } finally {
        isUploadingFile = false;
        if (fileInput) {
            fileInput.value = '';
        }
    }
}

async function downloadFileMessage(message) {
    if (!message?.file?.id || !currentChat) return;

    try {
        const key = chatKeys[currentChat.id];
        if (!key) {
            notify('Сначала задайте ключ чата', 'error');
            return;
        }

        const response = await fetch(`/api/files/${encodeURIComponent(message.file.id)}`, {
            method: 'GET',
            credentials: 'same-origin',
            cache: 'no-store'
        });

        if (!response.ok) {
            const data = await parseJsonResponse(response);
            throw new Error((data && data.error) ? data.error : `Ошибка HTTP ${response.status}`);
        }

        const encryptedBuffer = await response.arrayBuffer();
        const decryptedBytes = decryptBinary(encryptedBuffer, key, message.file.crypto);
        const blob = new Blob([decryptedBytes], {
            type: message.file.mimeType || 'application/octet-stream'
        });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = message.file.name || 'file.bin';
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Ошибка скачивания файла:', error);
        notify(`Не удалось скачать файл: ${error.message}`, 'error');
        if (/сессия|токен/i.test(String(error.message || ''))) {
            logout({ skipServer: true });
        }
    }
}

function showKeyModal() {
    if (!currentChat) {
        notify('Выберите чат', 'error');
        return;
    }

    const inputEl = document.getElementById('key-input');
    inputEl.value = chatKeys[currentChat.id] || '';
    document.getElementById('key-modal').classList.remove('hidden');
    generateQRCode(inputEl.value);
}

function closeKeyModal() {
    document.getElementById('key-modal').classList.add('hidden');
    document.getElementById('qr-container').style.display = 'none';
    document.getElementById('qrcode').innerHTML = '';
}

function generateRandomKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    const randomValues = new Uint32Array(32);
    window.crypto.getRandomValues(randomValues);
    let key = '';
    for (let index = 0; index < randomValues.length; index += 1) {
        key += chars.charAt(randomValues[index] % chars.length);
    }
    document.getElementById('key-input').value = key;
    generateQRCode(key);
}

function generateQRCode(text) {
    if (!text || text.length < 8) {
        document.getElementById('qr-container').style.display = 'none';
        document.getElementById('qrcode').innerHTML = '';
        return;
    }

    document.getElementById('qr-container').style.display = 'flex';
    document.getElementById('qrcode').innerHTML = '';

    new QRCode(document.getElementById('qrcode'), {
        text,
        width: 200,
        height: 200,
        colorDark: '#000000',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.H
    });
}

function saveKey() {
    if (!currentChat) {
        notify('Выберите чат', 'error');
        return;
    }

    const newKey = document.getElementById('key-input').value.trim();
    if (newKey.length < 8) {
        notify('Минимум 8 символов', 'error');
        return;
    }

    chatKeys[currentChat.id] = newKey;
    saveChatKeys(chatKeys);
    closeKeyModal();
    notify('Ключ сохранён', 'success');

    if (socket) {
        pendingChatId = currentChat.id;
        socket.emit('join-chat', { chatId: currentChat.id });
    }
}

function deleteChat(chat) {
    if (!socket || !chat?.canDelete) return;
    showDeleteChatModal(chat);
}

function showChangePasswordModal() {
    document.getElementById('change-password-modal').classList.remove('hidden');
}

function closeChangePasswordModal() {
    document.getElementById('change-password-modal').classList.add('hidden');
}

async function submitChangePassword() {
    const oldPassword = document.getElementById('old-password').value.trim();
    const newPassword = document.getElementById('new-password').value.trim();
    const confirmPassword = document.getElementById('new-password-confirm').value.trim();

    if (!oldPassword || !newPassword) return notify('Заполните поля', 'error');
    if (newPassword !== confirmPassword) return notify('Пароли не совпадают', 'error');
    const passwordError = validatePasswordPolicyClient(newPassword);
    if (passwordError) return notify(passwordError, 'error');

    try {
        const data = await requestJson('/api/change-password', {
            method: 'POST',
            body: JSON.stringify({ oldPassword, newPassword })
        });
        closeChangePasswordModal();
        document.getElementById('old-password').value = '';
        document.getElementById('new-password').value = '';
        document.getElementById('new-password-confirm').value = '';

        if (data && data.reauthRequired) {
            notify('Пароль изменён. Войдите заново.', 'success');
            resetClientState();
            return;
        }

        notify('Пароль изменён', 'success');
    } catch (error) {
        notify(`Ошибка при смене пароля: ${error.message}`, 'error');
    }
}

function renderUsersList(users) {
    const container = document.getElementById('users-list');
    container.innerHTML = '';

    if (!Array.isArray(users) || users.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'text-zinc-500 text-center';
        empty.textContent = 'Пользователей пока нет';
        container.appendChild(empty);
        return;
    }

    users.forEach((user) => {
        const row = document.createElement('div');
        row.className = 'bg-zinc-800 p-4 rounded-2xl flex items-center justify-between';

        const userInfo = document.createElement('div');
        userInfo.className = 'flex items-center gap-4';
        const username = document.createElement('span');
        username.className = 'font-medium';
        username.textContent = user.username;
        userInfo.appendChild(username);

        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'bg-blue-500 hover:bg-blue-600 px-4 py-2 rounded-lg text-sm font-medium';
        button.textContent = 'Смена пароля';
        button.addEventListener('click', () => {
            const newPass = prompt(`Новый пароль для ${user.username}:`);
            if (newPass) {
                changeUserPasswordAsAdmin(user.username, newPass);
            }
        });

        row.appendChild(userInfo);
        row.appendChild(button);
        container.appendChild(row);
    });
}

async function showUsersModal() {
    document.getElementById('users-modal').classList.remove('hidden');

    try {
        const users = await requestJson('/api/users');
        renderUsersList(users);
    } catch (error) {
        console.error(error);
        notify(`Не удалось загрузить список пользователей: ${error.message}`, 'error');
    }
}

async function changeUserPasswordAsAdmin(username, newPassword) {
    const passwordError = validatePasswordPolicyClient(newPassword);
    if (passwordError) return notify(passwordError, 'error');

    try {
        await requestJson('/api/change-password', {
            method: 'POST',
            body: JSON.stringify({ targetUsername: username, newPassword })
        });
        notify(`Пароль для ${username} изменён`, 'success');
        showUsersModal();
    } catch (error) {
        notify(`Ошибка смены пароля: ${error.message}`, 'error');
    }
}

function closeUsersModal() {
    document.getElementById('users-modal').classList.add('hidden');
}

function showResetAllModal() {
    document.getElementById('reset-all-modal').classList.remove('hidden');
}

function closeResetAllModal() {
    document.getElementById('reset-all-modal').classList.add('hidden');
}

async function exportAllAdminData() {
    try {
        const response = await fetch('/api/admin/export-all', {
            method: 'GET',
            credentials: 'same-origin',
            cache: 'no-store'
        });

        if (!response.ok) {
            const data = await parseJsonResponse(response);
            throw new Error((data && data.error) ? data.error : `Ошибка HTTP ${response.status}`);
        }

        const blob = await response.blob();
        const disposition = response.headers.get('Content-Disposition') || '';
        const fileNameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
        const fileName = fileNameMatch ? fileNameMatch[1] : `messenger-backup-${Date.now()}.json`;
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = fileName;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        notify('Архив сохранён', 'success');
    } catch (error) {
        notify(`Не удалось сохранить архив: ${error.message}`, 'error');
    }
}

async function resetAllAdminData() {
    try {
        const data = await requestJson('/api/admin/reset-all', {
            method: 'POST',
            body: JSON.stringify({})
        });

        closeResetAllModal();
        closeUsersModal();
        directoryUsers = [];
        directoryUsersLoadedAt = 0;

        if (data?.reauthRequired) {
            notify('Все данные очищены. Войдите заново.', 'success');
            resetClientState();
            return;
        }

        notify('Все данные очищены', 'success');
        resetClientState();
    } catch (error) {
        notify(`Не удалось очистить данные: ${error.message}`, 'error');
    }
}

function showCreateUserModal() {
    document.getElementById('new-user-login').value = '';
    document.getElementById('new-user-password').value = '';
    document.getElementById('create-user-modal').classList.remove('hidden');
}

function closeCreateUserModal() {
    document.getElementById('new-user-login').value = '';
    document.getElementById('new-user-password').value = '';
    document.getElementById('create-user-modal').classList.add('hidden');
}

async function submitCreateUser() {
    const username = document.getElementById('new-user-login').value.trim();
    const password = document.getElementById('new-user-password').value.trim();

    if (!username || !password) return notify('Заполните поля', 'error');
    const passwordError = validatePasswordPolicyClient(password);
    if (passwordError) return notify(passwordError, 'error');

    try {
        await requestJson('/api/create-user', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
        directoryUsers = [];
        directoryUsersLoadedAt = 0;
        notify('Пользователь создан', 'success');
        closeCreateUserModal();
        showUsersModal();
    } catch (error) {
        notify(`Ошибка создания пользователя: ${error.message}`, 'error');
    }
}

function setMobileSidebar(open) {
    const chatScreen = document.getElementById('chat-screen');
    const chatSidebar = document.getElementById('chat-sidebar');
    const mobileOverlay = document.getElementById('mobile-overlay');

    if (!chatScreen || !chatSidebar || !mobileOverlay) return;

    if (window.innerWidth >= 768) {
        chatScreen.classList.remove('sidebar-open');
        chatSidebar.style.transform = '';
        mobileOverlay.style.opacity = '';
        mobileOverlay.style.pointerEvents = '';
        return;
    }

    chatScreen.classList.toggle('sidebar-open', open);
    chatSidebar.style.transform = open ? 'translateX(0)' : 'translateX(-105%)';
    mobileOverlay.style.opacity = open ? '1' : '0';
    mobileOverlay.style.pointerEvents = open ? 'auto' : 'none';
}

function toggleMobileSidebar(forceOpen) {
    const chatScreen = document.getElementById('chat-screen');
    if (!chatScreen) return;
    const next = (typeof forceOpen === 'boolean') ? forceOpen : !chatScreen.classList.contains('sidebar-open');
    setMobileSidebar(next);
}

function setupModalBackdropClose() {
    ['key-modal', 'change-password-modal', 'users-modal', 'create-user-modal', 'background-modal', 'new-chat-modal', 'group-modal', 'delete-chat-modal', 'reset-all-modal'].forEach((id) => {
        const modal = document.getElementById(id);
        if (!modal) return;
        modal.addEventListener('click', (event) => {
            if (event.target !== modal) return;
            if (id === 'group-modal') {
                closeGroupModal();
                return;
            }
            if (id === 'new-chat-modal') {
                closeNewChatModal();
                return;
            }
            if (id === 'delete-chat-modal') {
                closeDeleteChatModal();
                return;
            }
            if (id === 'reset-all-modal') {
                closeResetAllModal();
                return;
            }
            modal.classList.add('hidden');
        });
    });
}

function bindUiEvents() {
    document.getElementById('login-submit-btn').addEventListener('click', login);
    document.getElementById('admin-btn').addEventListener('click', showUsersModal);
    document.getElementById('open-change-password-btn').addEventListener('click', showChangePasswordModal);
    document.getElementById('open-background-btn').addEventListener('click', showBackgroundModal);
    document.getElementById('logout-btn').addEventListener('click', () => logout());
    document.getElementById('new-chat-btn').addEventListener('click', newChatPrompt);
    document.getElementById('new-group-btn').addEventListener('click', createGroupPrompt);
    document.getElementById('close-new-chat-modal-btn').addEventListener('click', closeNewChatModal);
    document.getElementById('close-group-modal-btn').addEventListener('click', closeGroupModal);
    document.getElementById('submit-group-modal-btn').addEventListener('click', submitGroupModal);
    document.getElementById('close-delete-chat-modal-btn').addEventListener('click', closeDeleteChatModal);
    document.getElementById('confirm-delete-chat-modal-btn').addEventListener('click', confirmDeleteChat);
    document.getElementById('mobile-overlay').addEventListener('click', () => toggleMobileSidebar(false));
    document.getElementById('open-key-modal-btn').addEventListener('click', showKeyModal);
    document.getElementById('send-message-btn').addEventListener('click', sendMessage);
    document.getElementById('attach-file-btn').addEventListener('click', () => {
        if (!currentChat) {
            notify('Сначала выберите чат', 'error');
            return;
        }
        document.getElementById('file-input').click();
    });
    document.getElementById('file-input').addEventListener('change', async (event) => {
        const file = event.target.files && event.target.files[0];
        await uploadSelectedFile(file);
    });
    document.getElementById('key-input').addEventListener('input', (event) => generateQRCode(event.target.value));
    document.getElementById('generate-key-btn').addEventListener('click', generateRandomKey);
    document.getElementById('close-key-modal-btn').addEventListener('click', closeKeyModal);
    document.getElementById('save-key-btn').addEventListener('click', saveKey);
    document.getElementById('close-change-password-btn').addEventListener('click', closeChangePasswordModal);
    document.getElementById('submit-change-password-btn').addEventListener('click', submitChangePassword);
    document.getElementById('show-create-user-btn').addEventListener('click', showCreateUserModal);
    document.getElementById('export-all-btn').addEventListener('click', exportAllAdminData);
    document.getElementById('reset-all-btn').addEventListener('click', showResetAllModal);
    document.getElementById('close-reset-all-modal-btn').addEventListener('click', closeResetAllModal);
    document.getElementById('confirm-reset-all-modal-btn').addEventListener('click', resetAllAdminData);
    document.getElementById('close-users-modal-btn').addEventListener('click', closeUsersModal);
    document.getElementById('close-create-user-btn').addEventListener('click', closeCreateUserModal);
    document.getElementById('submit-create-user-btn').addEventListener('click', submitCreateUser);
    document.getElementById('close-background-modal-btn').addEventListener('click', closeBackgroundModal);

    document.getElementById('password').addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            login();
        }
    });

    document.getElementById('message-input').addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            sendMessage();
        }
    });

    document.getElementById('group-title-input').addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            submitGroupModal();
        }
    });

    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', (event) => {
            event.preventDefault();
            event.stopPropagation();
            toggleMobileSidebar();
        });
    }

    window.addEventListener('resize', () => setMobileSidebar(false));
    const chatMainEl = document.getElementById('chat-main');
    if (chatMainEl) {
        chatMainEl.addEventListener('click', () => {
            if (window.innerWidth < 768) {
                setMobileSidebar(false);
            }
        });
    }
}

async function bootstrapSession() {
    if (isBootstrapping) return;

    try {
        isBootstrapping = true;
        const data = await requestJson('/api/me', {
            method: 'GET',
            cache: 'no-cache'
        });

        currentUser = { username: data.username };
        chatKeys = loadChatKeys();
        showChatScreen(data.username);
        clearChatView();
        initSocket();
    } catch (error) {
        console.error('Ошибка авто-входа:', error);
        showLoginScreen();
    } finally {
        isBootstrapping = false;
    }
}

window.addEventListener('load', () => {
    setupModalBackdropClose();
    setupBackgroundControls();
    setupChatSearch();
    bindUiEvents();
    renderChatHeader(null);
    bootstrapSession();
});

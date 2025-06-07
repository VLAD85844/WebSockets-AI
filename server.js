const fetch = require('node-fetch');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const app = express();

// Мидлвары
app.use(express.json());

// Подключение к MongoDB
mongoose.connect('mongodb://localhost:27017/websocket-chat', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((err) => {
    console.error('Error connecting to MongoDB:', err);
});

const https = require('https');
https.get('https://api.ipify.org?format=json', (response) => {
    response.on('data', (data) => {
        console.log('Server IP:', JSON.parse(data).ip);
    });
});

// Модель пользователя
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
}, { collection: 'users' });

const User = mongoose.model('User', userSchema);

// Модель сообщения
const messageSchema = new mongoose.Schema({
    user: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    room: { type: String, required: true },
    chatType: { type: String, enum: ['room', 'private', 'ai'], default: 'room' },
    recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    timestamp: { type: Date, default: Date.now },
    isEdited: { type: Boolean, default: false }
}, { collection: 'messages' });

const Message = mongoose.model('Message', messageSchema);

// Конфигурация YandexGPT
const YANDEX_GPT_CONFIG = {
  folderId: '',
  apiKey: '',
  apiUrl: '',
  iamTokenUrl: ''
};

// Маршруты для страниц
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/auth.html');
});

app.get('/chat', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Регистрация пользователя
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Вход пользователя
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user._id }, 'your_jwt_secret', { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Защищённый маршрут
app.get('/profile', async (req, res) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ message: 'Access denied' });
    }

    try {
        const decoded = jwt.verify(token, 'your_jwt_secret');
        const user = await User.findById(decoded.userId).select('-password');
        res.json({
            _id: user._id,
            username: user.username,
            email: user.email
        });
    } catch (err) {
        res.status(400).json({ message: 'Invalid token', error: err.message });
    }
});

// Удаление сообщения
app.delete('/message/:id', async (req, res) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: 'Access denied' });

    try {
        const decoded = jwt.verify(token, 'your_jwt_secret');
        const message = await Message.findById(req.params.id);

        if (!message) {
            return res.status(404).json({ message: 'Message not found' });
        }

        const user = await User.findById(decoded.userId);
        if (message.userId.toString() !== decoded.userId.toString() && user.username !== 'admin') {
            return res.status(403).json({ message: 'You can only delete your own messages' });
        }

        await Message.deleteOne({ _id: req.params.id });

        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({
                    type: 'delete',
                    messageId: req.params.id
                }));
            }
        });

        res.json({ message: 'Message deleted successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Редактирование сообщения
app.put('/message/:id', async (req, res) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: 'Access denied' });

    try {
        const decoded = jwt.verify(token, 'your_jwt_secret');
        const { text } = req.body;
        const message = await Message.findById(req.params.id);

        if (!message) {
            return res.status(404).json({ message: 'Message not found' });
        }

        if (message.userId.toString() !== decoded.userId.toString()) {
            return res.status(403).json({ message: 'You can only edit your own messages' });
        }

        const updatedMessage = await Message.findByIdAndUpdate(
            req.params.id,
            { text, isEdited: true },
            { new: true }
        );

        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({
                    type: 'update',
                    message: updatedMessage
                }));
            }
        });

        res.json({ message: 'Message updated successfully', updatedMessage });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Получение истории личных сообщений
app.get('/private-messages/:userId1/:userId2', async (req, res) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: 'Access denied' });

    try {
        const decoded = jwt.verify(token, 'your_jwt_secret');
        const { userId1, userId2 } = req.params;
        const roomName = `private_${[userId1, userId2].sort().join('_')}`;

        const messages = await Message.find({
            room: roomName,
            chatType: 'private'
        }).sort({ timestamp: 1 }).limit(50);

        res.json(messages);
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Функция для получения IAM токена
async function getIamToken() {
    try {
        const response = await fetch(YANDEX_GPT_CONFIG.iamTokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                yandexPassportOauthToken: YANDEX_GPT_CONFIG.apiKey
            })
        });

        if (!response.ok) {
            throw new Error(`IAM token request failed: ${response.status}`);
        }

        const data = await response.json();

        if (!data.iamToken) {
            throw new Error('IAM token not received');
        }

        return data.iamToken;
    } catch (err) {
        console.error('Error getting IAM token:', err);
        throw err;
    }
}

// Маршрут для обработки запросов к YandexGPT
app.post('/api/yandex-ai', async (req, res) => {
    const { message } = req.body;
    const token = req.headers['authorization'];

    if (!token) return res.status(403).json({ message: 'Access denied' });

    try {
        const iamToken = await getIamToken();

        const response = await fetch(YANDEX_GPT_CONFIG.apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${iamToken}`,
                'x-folder-id': YANDEX_GPT_CONFIG.folderId
            },
            body: JSON.stringify({
                modelUri: `gpt://${YANDEX_GPT_CONFIG.folderId}/yandexgpt-lite`,
                completionOptions: {
                    stream: false,
                    temperature: 0.6,
                    maxTokens: "2000"
                },
                messages: [
                    {
                        role: "system",
                        text: "Ты - полезный ассистент в чат-приложении. Отвечай кратко и по делу."
                    },
                    {
                        role: "user",
                        text: message
                    }
                ]
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Yandex GPT API error: ${response.status} - ${errorText}`);
        }

        const data = await response.json();


        if (!data?.result?.alternatives?.[0]?.message?.text) {
            console.error('Invalid Yandex GPT response structure:', JSON.stringify(data, null, 2));
            throw new Error('Invalid response structure from Yandex GPT');
        }

        res.json({
            response: data.result.alternatives[0].message.text
        });
    } catch (err) {
        console.error('Yandex AI request failed:', err);
        res.status(500).json({
            message: 'Yandex AI service error',
            error: err.message
        });
    }
});

// Создание WebSocket-сервера
const wss = new WebSocket.Server({ noServer: true });

// Хранилище онлайн пользователей
const onlineUsers = new Map();

// Функция рассылки статусов пользователей
function broadcastUserStatus() {
    const usersArray = Array.from(onlineUsers.values());
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
                type: 'userStatus',
                users: usersArray
            }));
        }
    });
}

// Обработка подключения WebSocket
wss.on('connection', (ws, request) => {
    let currentRoom = 'general';
    let userId = null;
    let username = null;
    ws.userId = userId;

    // Отправка истории сообщений при подключении
    Message.find({ room: currentRoom, chatType: 'room' }).sort({ timestamp: 1 }).limit(50).then(messages => {
        ws.send(JSON.stringify({
            type: 'history',
            messages: messages.map(msg => ({
                _id: msg._id,
                user: msg.user,
                userId: msg.userId,
                text: msg.text,
                timestamp: msg.timestamp,
                room: msg.room,
                isEdited: msg.isEdited,
                chatType: msg.chatType
            }))
        }));
    });

    // Обработка сообщений от клиента
    ws.on('message', async (message) => {
        const data = JSON.parse(message);

        if (data.type === 'auth') {
            userId = data.userId;
            username = data.username;
            ws.userId = userId;


            onlineUsers.set(userId, {
                userId,
                username,
                lastSeen: new Date(),
                status: 'online'
            });


            broadcastUserStatus();
        }
        else if (data.type === 'heartbeat' && userId) {

            if (onlineUsers.has(userId)) {
                const user = onlineUsers.get(userId);
                user.lastSeen = new Date();
                onlineUsers.set(userId, user);
                broadcastUserStatus();
            }
        }
        else if (data.type === 'message') {
            if (!data.userId) {
                console.error('UserId is required');
                return;
            }

            const newMessage = new Message({
                user: data.user,
                userId: data.userId,
                text: data.text,
                room: data.room,
                chatType: 'room',
                timestamp: new Date()
            });

            await newMessage.save();
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify({
                        type: 'message',
                        message: {
                            _id: newMessage._id,
                            user: data.user,
                            userId: data.userId,
                            text: data.text,
                            timestamp: new Date(),
                            room: data.room,
                            isNew: true,
                            chatType: 'room'
                        }
                    }));
                }
            });
        }
        else if (data.type === 'private_message') {
            if (!data.userId || !data.recipientId) {
                console.error('UserId and recipientId are required');
                return;
            }

            const newMessage = new Message({
                user: data.user,
                userId: data.userId,
                text: data.text,
                room: `private_${[data.userId, data.recipientId].sort().join('_')}`,
                chatType: 'private',
                recipientId: data.recipientId,
                timestamp: new Date()
            });

            await newMessage.save();

            // Отправляем сообщение только отправителю и получателю
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN &&
                    (client.userId === data.userId || client.userId === data.recipientId)) {
                    client.send(JSON.stringify({
                        type: 'private_message',
                        message: {
                            _id: newMessage._id,
                            user: data.user,
                            userId: data.userId,
                            text: data.text,
                            timestamp: new Date(),
                            room: newMessage.room,
                            isNew: true,
                            chatType: 'private'
                        }
                    }));
                }
            });
        }
        else if (data.type === 'ai_message') {
            if (!data.userId) {
                console.error('UserId is required');
                return;
            }

            // Сохраняем сообщение пользователя
            const userMessage = new Message({
                user: data.user,
                userId: data.userId,
                text: data.text,
                room: "ai_chat",
                chatType: "ai",
                timestamp: new Date()
            });
            await userMessage.save();

            // Отправляем сообщение пользователя всем клиентам в чате ИИ
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN && client.currentRoom === "ai_chat") {
                    client.send(JSON.stringify({
                        type: 'message',
                        message: {
                            _id: userMessage._id,
                            user: data.user,
                            userId: data.userId,
                            text: data.text,
                            timestamp: new Date(),
                            room: "ai_chat",
                            isNew: true,
                            chatType: "ai"
                        }
                    }));
                }
            });

            // Отправляем запрос к YandexGPT и получаем ответ
            try {
                const apiResponse = await fetch('http://localhost:3000/api/yandex-ai', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': data.token
                    },
                    body: JSON.stringify({
                        message: data.text
                    })
                });

                if (!apiResponse.ok) {
                    const errorText = await apiResponse.text();
                    throw new Error(`API request failed: ${apiResponse.status} - ${errorText}`);
                }

                const aiResponse = await apiResponse.json();

                if (!aiResponse.response) {
                    throw new Error('Invalid response from AI service');
                }

                const aiBotId = new mongoose.Types.ObjectId();

                const aiMessage = new Message({
                    _id: aiBotId,
                    user: "YandexGPT",
                    userId: aiBotId,
                    text: aiResponse.response,
                    room: "ai_chat",
                    chatType: "ai",
                    recipientId: data.userId,
                    timestamp: new Date()
                });

                await aiMessage.save();

                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN && client.currentRoom === "ai_chat") {
                        client.send(JSON.stringify({
                            type: 'message',
                            message: {
                                _id: aiBotId,
                                user: "YandexGPT",
                                userId: aiBotId,
                                text: aiResponse.response,
                                timestamp: new Date(),
                                room: "ai_chat",
                                isNew: true,
                                chatType: "ai"
                            }
                        }));
                    }
                });
            } catch (err) {
                console.error('Yandex AI request failed:', err);

                // Отправляем сообщение об ошибке пользователю
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN && client.userId === data.userId && client.currentRoom === "ai_chat") {
                        client.send(JSON.stringify({
                            type: 'message',
                            message: {
                                _id: new mongoose.Types.ObjectId(),
                                user: "YandexGPT",
                                userId: data.userId,
                                text: `Извините, произошла ошибка: ${err.message}`,
                                timestamp: new Date(),
                                room: "ai_chat",
                                isNew: true,
                                chatType: "ai"
                            }
                        }));
                    }
                });
            }
        }
        else if (data.type === 'join') {
            currentRoom = data.room;
            const query = { room: currentRoom };

            // Для личных чатов добавляем фильтр по chatType
            if (currentRoom.startsWith('private_')) {
                query.chatType = 'private';
            } else {
                query.chatType = 'room';
            }

            const messages = await Message.find(query)
                .sort({ timestamp: 1 })
                .limit(50);

            ws.send(JSON.stringify({
                type: 'history',
                messages: messages.map(msg => ({
                    _id: msg._id,
                    user: msg.user,
                    userId: msg.userId,
                    text: msg.text,
                    timestamp: msg.timestamp,
                    room: msg.room,
                    isEdited: msg.isEdited,
                    chatType: msg.chatType
                }))
            }));
        }
    });

    // Обработка закрытия соединения
    ws.on('close', () => {
        if (userId) {
            onlineUsers.delete(userId);
            broadcastUserStatus();
        }
    });
});

// Интервал проверки активности
setInterval(() => {
    const now = new Date();
    onlineUsers.forEach((user, userId) => {
        if ((now - user.lastSeen) > 30000) { // 30 секунд неактивности
            onlineUsers.delete(userId);
            broadcastUserStatus();
        }
    });
}, 10000); // Проверяем каждые 10 секунд

// Запуск сервера
app.use(express.static('public'));

app.server = app.listen(3000, () => {
    console.log('Сервер запущен на порту 3000');
});

// Подключение WebSocket к серверу HTTP
app.server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
    });
});
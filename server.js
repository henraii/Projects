// server.js
import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { MongoClient, ObjectId } from 'mongodb';

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: "http://localhost:4321",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3001;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

app.use(cors());
app.use(express.json());

let db;

// Connect to MongoDB
async function connectDB() {
  try {
    const client = await MongoClient.connect(MONGODB_URI);
    db = client.db('socialBlog');
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
}

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// AUTH ROUTES
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, username, displayName } = req.body;
    
    const existingUser = await db.collection('users').findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.collection('users').insertOne({
      email,
      username,
      displayName,
      password: hashedPassword,
      avatar: `https://ui-avatars.com/api/?name=${displayName}&background=random`,
      bio: '',
      followers: [],
      following: [],
      createdAt: new Date()
    });

    const token = jwt.sign({ userId: result.insertedId }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, userId: result.insertedId });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.collection('users').findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, userId: user._id });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// USER ROUTES
app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const user = await db.collection('users').findOne(
      { _id: new ObjectId(req.user.userId) },
      { projection: { password: 0 } }
    );
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/users/search', authenticateToken, async (req, res) => {
  try {
    const { q } = req.query;
    const users = await db.collection('users').find({
      $or: [
        { username: new RegExp(q, 'i') },
        { displayName: new RegExp(q, 'i') }
      ]
    }, { projection: { password: 0 } }).limit(20).toArray();
    
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/users/:userId', authenticateToken, async (req, res) => {
  try {
    const user = await db.collection('users').findOne(
      { _id: new ObjectId(req.params.userId) },
      { projection: { password: 0 } }
    );
    
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    const posts = await db.collection('posts')
      .find({ userId: req.params.userId })
      .sort({ createdAt: -1 })
      .toArray();
    
    res.json({ ...user, posts });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/users/:userId/follow', authenticateToken, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const targetUserId = req.params.userId;

    await db.collection('users').updateOne(
      { _id: new ObjectId(currentUserId) },
      { $addToSet: { following: targetUserId } }
    );

    await db.collection('users').updateOne(
      { _id: new ObjectId(targetUserId) },
      { $addToSet: { followers: currentUserId } }
    );

    res.json({ message: 'Followed successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/users/:userId/follow', authenticateToken, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const targetUserId = req.params.userId;

    await db.collection('users').updateOne(
      { _id: new ObjectId(currentUserId) },
      { $pull: { following: targetUserId } }
    );

    await db.collection('users').updateOne(
      { _id: new ObjectId(targetUserId) },
      { $pull: { followers: currentUserId } }
    );

    res.json({ message: 'Unfollowed successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST ROUTES
app.get('/api/posts', authenticateToken, async (req, res) => {
  try {
    const posts = await db.collection('posts')
      .aggregate([
        { $sort: { createdAt: -1 } },
        { $limit: 50 },
        {
          $lookup: {
            from: 'users',
            localField: 'userId',
            foreignField: '_id',
            as: 'author'
          }
        },
        { $unwind: '$author' },
        { $project: { 'author.password': 0 } }
      ])
      .toArray();
    
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { title, content, tags } = req.body;
    const post = {
      userId: req.user.userId,
      title,
      content,
      tags: tags || [],
      likes: [],
      comments: [],
      createdAt: new Date()
    };
    
    const result = await db.collection('posts').insertOne(post);
    res.status(201).json({ ...post, _id: result.insertedId });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/posts/:postId/like', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const postId = req.params.postId;

    const post = await db.collection('posts').findOne({ _id: new ObjectId(postId) });
    
    const isLiked = post.likes?.includes(userId);
    
    await db.collection('posts').updateOne(
      { _id: new ObjectId(postId) },
      isLiked 
        ? { $pull: { likes: userId } }
        : { $addToSet: { likes: userId } }
    );

    res.json({ message: isLiked ? 'Unliked' : 'Liked' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/posts/:postId/comment', authenticateToken, async (req, res) => {
  try {
    const { content } = req.body;
    const comment = {
      _id: new ObjectId(),
      userId: req.user.userId,
      content,
      createdAt: new Date()
    };

    await db.collection('posts').updateOne(
      { _id: new ObjectId(req.params.postId) },
      { $push: { comments: comment } }
    );

    res.status(201).json(comment);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// CHAT ROUTES
app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const chats = await db.collection('chats')
      .find({ participants: userId })
      .sort({ lastMessageAt: -1 })
      .toArray();

    res.json(chats);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/chats', authenticateToken, async (req, res) => {
  try {
    const { recipientId } = req.body;
    const userId = req.user.userId;

    const existingChat = await db.collection('chats').findOne({
      participants: { $all: [userId, recipientId] }
    });

    if (existingChat) {
      return res.json(existingChat);
    }

    const chat = {
      participants: [userId, recipientId],
      messages: [],
      lastMessageAt: new Date(),
      createdAt: new Date()
    };

    const result = await db.collection('chats').insertOne(chat);
    res.status(201).json({ ...chat, _id: result.insertedId });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const chat = await db.collection('chats').findOne({ 
      _id: new ObjectId(req.params.chatId) 
    });
    
    res.json(chat?.messages || []);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// SOCKET.IO for real-time chat
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error'));

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return next(new Error('Authentication error'));
    socket.userId = decoded.userId;
    next();
  });
});

io.on('connection', (socket) => {
  console.log('User connected:', socket.userId);

  socket.on('join-chat', (chatId) => {
    socket.join(chatId);
  });

  socket.on('send-message', async ({ chatId, content }) => {
    try {
      const message = {
        _id: new ObjectId(),
        userId: socket.userId,
        content,
        createdAt: new Date()
      };

      await db.collection('chats').updateOne(
        { _id: new ObjectId(chatId) },
        { 
          $push: { messages: message },
          $set: { lastMessageAt: new Date() }
        }
      );

      io.to(chatId).emit('new-message', { chatId, message });
    } catch (error) {
      console.error('Error sending message:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.userId);
  });
});

// Start server
connectDB().then(() => {
  httpServer.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});
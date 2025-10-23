// server.js
import 'dotenv/config';
import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { MongoClient, ObjectId } from 'mongodb';
import multer from 'multer';
import path from 'path';
import fs from 'fs';

const app = express();
const httpServer = createServer(app);

// Fixed: Better CORS configuration for Socket.IO
const io = new Server(httpServer, {
  cors: {
    origin: process.env.FRONTEND_URL || "https://myblog-v804.onrender.com",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
  }
});

// Fixed: Single PORT declaration
const PORT = process.env.PORT || 3001;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Fixed: Better CORS for Express
app.use(cors({
  origin: process.env.FRONTEND_URL || "https://myblog-v804.onrender.com",
  credentials: true
}));
app.use(express.json());

// Serve uploaded images
app.use('/uploads', express.static('uploads'));

let db;
let client;

// Create uploads folder if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
  console.log('📁 Created uploads folder');
}

// WARNING: Render has ephemeral filesystem - files will be deleted on restart
// For production, use cloud storage like AWS S3 or Cloudinary
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// Connect to MongoDB
async function connectDB() {
  try {
    console.log('Connecting to MongoDB...');
    client = new MongoClient(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
    });
    
    await client.connect();
    db = client.db('HardenGoat');
    
    console.log('✅ Connected to MongoDB successfully');
    console.log('📦 Database: HardenGoat');
    
    // Test the connection
    await db.command({ ping: 1 });
    console.log('🏓 MongoDB ping successful');
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    process.exit(1);
  }
}

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// AUTH ROUTES
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, username, displayName } = req.body;
    
    // Validation
    if (!email || !password || !username || !displayName) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const existingUser = await db.collection('users').findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      return res.status(400).json({ 
        error: existingUser.email === email ? 'Email already exists' : 'Username already taken' 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.collection('users').insertOne({
      email,
      username,
      displayName,
      password: hashedPassword,
      avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(displayName)}&background=random`,
      bio: '',
      followers: [],
      following: [],
      createdAt: new Date()
    });

    const token = jwt.sign({ userId: result.insertedId.toString() }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ 
      token, 
      userId: result.insertedId.toString(),
      message: 'Account created successfully'
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error during signup' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await db.collection('users').findOne({ email });

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user._id.toString() }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ 
      token, 
      userId: user._id.toString(),
      message: 'Login successful'
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// EDIT PROFILE ROUTE
app.put('/api/users/:userId', authenticateToken, upload.single('avatar'), async (req, res) => {
  try {
    // Check if user is editing their own profile
    if (req.user.userId !== req.params.userId) {
      return res.status(403).json({ error: 'Unauthorized - You can only edit your own profile' });
    }

    const { displayName, bio } = req.body;
    const updateData = { displayName, bio };

    // Add avatar if uploaded
    if (req.file) {
      updateData.avatar = `/uploads/${req.file.filename}`;
      console.log(`🖼️ New avatar uploaded: ${updateData.avatar}`);
    }

    // Update user in database
    const result = await db.collection('users').findOneAndUpdate(
      { _id: new ObjectId(req.params.userId) },
      { $set: updateData },
      { returnDocument: 'after' }
    );

    if (!result.value) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Remove password from response
    const { password, ...userWithoutPassword } = result.value;

    console.log('✅ Profile updated successfully');
    res.json(userWithoutPassword);
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Server error during profile update' });
  }
});

// USER ROUTES
app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const user = await db.collection('users').findOne(
      { _id: new ObjectId(req.user.userId) },
      { projection: { password: 0 } }
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/users/search', authenticateToken, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q) {
      return res.json([]);
    }

    const users = await db.collection('users').find({
      $or: [
        { username: new RegExp(q, 'i') },
        { displayName: new RegExp(q, 'i') }
      ]
    }, { projection: { password: 0 } }).limit(20).toArray();
    
    res.json(users);
  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/users/:userId', authenticateToken, async (req, res) => {
  try {
    const user = await db.collection('users').findOne(
      { _id: new ObjectId(req.params.userId) },
      { projection: { password: 0 } }
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const posts = await db.collection('posts')
      .find({ userId: req.params.userId })
      .sort({ createdAt: -1 })
      .toArray();
    
    res.json({ ...user, posts });
  } catch (error) {
    console.error('Get user profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/users/:userId/follow', authenticateToken, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const targetUserId = req.params.userId;

    if (currentUserId === targetUserId) {
      return res.status(400).json({ error: 'Cannot follow yourself' });
    }

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
    console.error('Follow error:', error);
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
    console.error('Unfollow error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST ROUTES
app.get('/api/posts', authenticateToken, async (req, res) => {
  try {
    const posts = await db.collection('posts')
      .find({})
      .sort({ createdAt: -1 })
      .limit(50)
      .toArray();
    
    // Manually fetch author info for each post
    const postsWithAuthors = await Promise.all(
      posts.map(async (post) => {
        const author = await db.collection('users').findOne(
          { _id: new ObjectId(post.userId) },
          { projection: { password: 0 } }
        );
        return { ...post, author };
      })
    );
    
    res.json(postsWithAuthors);
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/posts/:postId', authenticateToken, async (req, res) => {
  try {
    const post = await db.collection('posts').findOne(
      { _id: new ObjectId(req.params.postId) }
    );

    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    // Fetch author
    const author = await db.collection('users').findOne(
      { _id: new ObjectId(post.userId) },
      { projection: { password: 0 } }
    );

    // Populate comment authors
    if (post.comments && post.comments.length > 0) {
      const commentUserIds = [...new Set(post.comments.map(c => c.userId))];
      const users = await db.collection('users')
        .find(
          { _id: { $in: commentUserIds.map(id => new ObjectId(id)) } },
          { projection: { password: 0 } }
        )
        .toArray();
      
      const userMap = {};
      users.forEach(u => {
        userMap[u._id.toString()] = u;
      });

      post.comments = post.comments.map(comment => ({
        ...comment,
        author: userMap[comment.userId] || null
      }));
    }

    res.json({ ...post, author });
  } catch (error) {
    console.error('Get post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { title, content, tags } = req.body;
    
    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }

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
    console.error('Create post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/posts/:postId/like', authenticateToken, async (req, res) => {
  try {
    const postId = req.params.postId;
    const userId = req.user.userId.toString();

    const post = await db.collection('posts').findOne({ _id: new ObjectId(postId) });
    if (!post) return res.status(404).json({ error: 'Post not found' });

    const isLiked = post.likes?.includes(userId);

    await db.collection('posts').updateOne(
      { _id: new ObjectId(postId) },
      isLiked ? { $pull: { likes: userId } } : { $addToSet: { likes: userId } }
    );

    const updatedPost = await db.collection('posts').findOne(
      { _id: new ObjectId(postId) },
      { projection: { likes: 1 } }
    );

    io.to(postId).emit('update-likes', { postId, likes: updatedPost.likes });
    res.json({ likes: updatedPost.likes });
  } catch (err) {
    console.error('Like post error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all comments for a post
app.get('/api/posts/:postId/comments', authenticateToken, async (req, res) => {
  try {
    const post = await db.collection('posts').findOne({ _id: new ObjectId(req.params.postId) });
    if (!post) return res.status(404).json({ error: 'Post not found' });

    const comments = post.comments || [];
    const userIds = [...new Set(comments.map(c => c.userId))];
    const users = await db.collection('users')
      .find(
        { _id: { $in: userIds.map(id => new ObjectId(id)) } },
        { projection: { password: 0 } }
      )
      .toArray();

    const userMap = Object.fromEntries(users.map(u => [u._id.toString(), u]));
    const populated = comments.map(c => ({
      ...c,
      author: userMap[c.userId] || null
    }));

    res.json(populated);
  } catch (error) {
    console.error('Get comments error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add a new comment
app.post('/api/posts/:postId/comments', authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || text.trim().length === 0) return res.status(400).json({ error: 'Comment cannot be empty' });
    if (text.length > 300) return res.status(400).json({ error: 'Comment too long (max 300 chars)' });

    const comment = {
      _id: new ObjectId().toString(),
      userId: req.user.userId.toString(),
      text: text.trim(),
      createdAt: new Date()
    };

    const result = await db.collection('posts').updateOne(
      { _id: new ObjectId(req.params.postId) },
      { $push: { comments: comment } }
    );

    if (result.modifiedCount === 0) return res.status(404).json({ error: 'Post not found' });

    const user = await db.collection('users').findOne(
      { _id: new ObjectId(req.user.userId) },
      { projection: { password: 0 } }
    );

    const populatedComment = { ...comment, author: user };

    // Emit only to users in this post's room
    io.to(req.params.postId).emit('new-comment', { postId: req.params.postId, comment: populatedComment });

    res.status(201).json(populatedComment);
  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete comment (only by author)
app.delete('/api/posts/:postId/comments/:commentId', authenticateToken, async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    const post = await db.collection('posts').findOne({ _id: new ObjectId(postId) });
    if (!post) return res.status(404).json({ error: 'Post not found' });

    const comment = post.comments.find(c => c._id === commentId);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });
    if (comment.userId !== req.user.userId) return res.status(403).json({ error: 'Unauthorized' });

    await db.collection('posts').updateOne(
      { _id: new ObjectId(postId) },
      { $pull: { comments: { _id: commentId } } }
    );

    io.to(postId).emit('delete-comment', { postId, commentId });
    res.json({ message: 'Comment deleted' });
  } catch (err) {
    console.error('Delete comment error:', err);
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
    console.error('Get chats error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/chats', authenticateToken, async (req, res) => {
  try {
    const { recipientId } = req.body;
    const userId = req.user.userId;

    if (!recipientId) {
      return res.status(400).json({ error: 'Recipient ID is required' });
    }

    if (userId === recipientId) {
      return res.status(400).json({ error: 'Cannot chat with yourself' });
    }

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
    console.error('Create chat error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const chat = await db.collection('chats').findOne({ 
      _id: new ObjectId(req.params.chatId) 
    });
    
    if (!chat) {
      return res.status(404).json({ error: 'Chat not found' });
    }

    // Check if user is a participant
    if (!chat.participants.includes(req.user.userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(chat.messages || []);
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// SOCKET.IO for real-time features
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error: No token provided'));

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return next(new Error('Authentication error: Invalid token'));
    socket.userId = decoded.userId.toString();
    next();
  });
});

io.on('connection', (socket) => {
  console.log('✅ User connected:', socket.userId);

  // Join a post room for real-time comments/likes
  socket.on('join-post', (postId) => {
    socket.join(postId);
    console.log(`User ${socket.userId} joined post room ${postId}`);
  });

  // Real-time chat room
  socket.on('join-chat', (chatId) => {
    socket.join(chatId);
    console.log(`User ${socket.userId} joined chat ${chatId}`);
  });

  // Real-time chat message
  socket.on('send-message', async ({ chatId, content }) => {
    if (!chatId || !content) return;

    const message = {
      _id: new ObjectId().toString(),
      userId: socket.userId,
      content,
      createdAt: new Date()
    };

    try {
      await db.collection('chats').updateOne(
        { _id: new ObjectId(chatId) },
        {
          $push: { messages: message },
          $set: { lastMessageAt: new Date() }
        }
      );

      io.to(chatId).emit('new-message', { chatId, message });
    } catch (error) {
      console.error('Error sending chat message:', error);
    }
  });

  // Real-time post comment
  socket.on('new-comment', async ({ postId, text }) => {
    if (!postId || !text) return;

    const comment = {
      _id: new ObjectId().toString(),
      userId: socket.userId,
      text,
      createdAt: new Date()
    };

    try {
      await db.collection('posts').updateOne(
        { _id: new ObjectId(postId) },
        { $push: { comments: comment } }
      );

      io.to(postId).emit('new-comment', { postId, comment });
    } catch (error) {
      console.error('Error sending comment:', error);
    }
  });

  // Real-time like/unlike
  socket.on('toggle-like', async ({ postId }) => {
    if (!postId) return;

    try {
      const post = await db.collection('posts').findOne({ _id: new ObjectId(postId) });
      if (!post) return;

      const hasLiked = post.likes.includes(socket.userId);

      await db.collection('posts').updateOne(
        { _id: new ObjectId(postId) },
        hasLiked
          ? { $pull: { likes: socket.userId } }
          : { $addToSet: { likes: socket.userId } }
      );

      const updatedPost = await db.collection('posts').findOne({ _id: new ObjectId(postId) });
      io.to(postId).emit('update-likes', { postId, likes: updatedPost.likes });
    } catch (error) {
      console.error('Error toggling like:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('❌ User disconnected:', socket.userId);
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    database: db ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Handle 404
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down gracefully...');
  try {
    await client.close();
    console.log('✅ MongoDB connection closed');
    process.exit(0);
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
});

// Start server - FIXED: Removed duplicate PORT declaration
connectDB().then(() => {
  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 Server running on http://0.0.0.0:${PORT}`);
    console.log(`📡 API available at http://0.0.0.0:${PORT}/api`);
    console.log(`💬 WebSocket server ready for connections`);
    console.log(`🖼️ File uploads enabled at http://0.0.0.0:${PORT}/uploads`);
  });
}).catch(error => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
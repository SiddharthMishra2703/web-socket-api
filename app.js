const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const socketIo = require('socket.io');
const http = require('http');
const dotenv = require("dotenv");
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
dotenv.config({ path: './config.env' });

const PORT = process.env.PORT || 3000;

// Connect to MongoDB
mongoose.connect(process.env.DATABASE, { useNewUrlParser: true, useUnifiedTopology: true });

// Middleware
app.use(express.json());
const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization'];
  
    if (!token) {
      return res.status(403).send({ message: 'No token provided' });
    }
  
    jwt.verify(token, 'secret', (err, decoded) => {
      if (err) {
        return res.status(401).send({ message: 'Unauthorized' });
      }
  
      req.user = decoded; // Save the decoded user information in the request object
      next(); // Proceed to the next middleware or route handler
    });
  };

// User Schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

// Group Schema
const groupSchema = new mongoose.Schema({
  name: String,
  members: [String],
  messages: [{ sender: String, message: String, timestamp: Date }],
});

const User = mongoose.model('User', userSchema);
const Group = mongoose.model('Group', groupSchema);

// Routes
app.get("/", (req, res) => {
    res.send('Web Socket API');
});

app.post('/auth/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword });
  await user.save();
  res.status(201).send('User registered');
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ username }, 'secret');
    res.json({ token });
  } else {
    res.status(401).send('Invalid credentials');
  }
});

app.post('/groups', authMiddleware, async (req, res) => {
  const { groupName } = req.body;
  const group = new Group({ name: groupName, members: [], messages: [] });
  await group.save();
  res.status(201).send('Group created');
});

app.post('/groups/:id/join', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const group = await Group.findById(id);
  group.members.push(req.user.username);
  await group.save();
  res.status(200).send('Joined group');
});

app.post('/groups/:id/leave', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const group = await Group.findById(id);
  group.members = group.members.filter(member => member !== req.user.username);
  await group.save();
  res.status(200).send('Left group');
});

app.get('/groups/:id/messages', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const group = await Group.findById(id);
  res.json(group.messages);
});

// WebSocket Events
io.use((socket, next) => {
  const token = socket.handshake.query.token;
  jwt.verify(token, 'secret', (err, decoded) => {
    if (err) return next(new Error('Authentication error'));
    socket.user = decoded;
    next();
  });
}).on('connection', socket => {
  console.log('a user connected');
  
  socket.on('join', groupId => {
    socket.join(groupId);
  });
  
  socket.on('message', async ({ groupId, message }) => {
    const group = await Group.findById(groupId);
    const newMessage = { sender: socket.user.username, message, timestamp: new Date() };
    group.messages.push(newMessage);
    await group.save();
    io.to(groupId).emit('message', newMessage);
  });

  socket.on('disconnect', () => {
    console.log('user disconnected');
  });
});

// Start Server
server.listen(PORT, () => {
  console.log('Server running on port ' + PORT);
});

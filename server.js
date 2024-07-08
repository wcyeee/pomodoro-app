const express = require('express');
const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const mongoose = require('mongoose');

mongoose.connect('YOUR_MONGODB_CONNECTION_STRING', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  pomodoroData: Array,
});

const User = mongoose.model('User', userSchema);

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('./models/User'); // 使用你定義的User模型

const secret = 'your_jwt_secret';

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ email, password: hashedPassword });
  await newUser.save();
  res.status(201).send('User registered');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ id: user._id }, secret, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).send('Invalid credentials');
  }
});

app.post('/pomodoro-data', async (req, res) => {
    const { token, pomodoroData } = req.body;
    try {
      const decoded = jwt.verify(token, secret);
      await User.findByIdAndUpdate(decoded.id, { pomodoroData });
      res.send('Data saved');
    } catch (error) {
      res.status(400).send('Invalid token');
    }
  });
  app.get('/pomodoro-data', async (req, res) => {
    const { token } = req.query;
    try {
      const decoded = jwt.verify(token, secret);
      const user = await User.findById(decoded.id);
      res.json(user.pomodoroData);
    } catch (error) {
      res.status(400).send('Invalid token');
    }
  });
    
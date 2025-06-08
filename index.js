const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const PORT = 6969;
const SECRET_KEY = 'your-secret-key'; // bạn có thể để trong .env

app.use(express.json());

// Fake "database" lưu trong RAM
const users = [];

// Đăng ký
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  const existing = users.find(u => u.email === email);
  if (existing) return res.status(400).json({ message: 'Email đã tồn tại' });

  const hashed = await bcrypt.hash(password, 10);
  users.push({ email, password: hashed });
  res.json({ message: 'Đăng ký thành công' });
});

// Đăng nhập
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ message: 'Sai tài khoản hoặc mật khẩu' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ message: 'Sai tài khoản hoặc mật khẩu' });

  const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

// Lấy thông tin người dùng từ token
app.get('/api/profile', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Thiếu token' });

  try {
    const token = auth.split(' ')[1];
    const payload = jwt.verify(token, SECRET_KEY);
    res.json({ email: payload.email });
  } catch (err) {
    res.status(401).json({ message: 'Token không hợp lệ' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ API server is running at http://localhost:${PORT}`);
});


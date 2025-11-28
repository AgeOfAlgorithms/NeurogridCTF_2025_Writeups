import express from 'express';
import bcrypt from 'bcryptjs';
import { addUser, getUserByEmail } from '../data/store.js';
import { csrfProtection } from '../middleware/csrf.js';
import { asyncHandler } from '../middleware/errorHandler.js';

const router = express.Router();

router.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  res.render('auth/register');
});

router.post('/register', csrfProtection, asyncHandler(async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;

  if (!username || !email || !password || !confirmPassword) {
    req.flash('error', 'All fields are required');
    return res.redirect('/register');
  }

  if (password !== confirmPassword) {
    req.flash('error', 'Passwords do not match');
    return res.redirect('/register');
  }

  const existingUser = await getUserByEmail(email);
  if (existingUser) {
    req.flash('error', 'Email already registered');
    return res.redirect('/register');
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  await addUser({
    username,
    email,
    password: hashedPassword,
    role: 'user'
  });

  req.flash('success', 'Registration successful! Please login.');
  res.redirect('/login');
}));

router.get('/login', (req, res) => {
  if (req.session.user) {
    const role = req.session.user.role;
    if (role === 'admin') {
      return res.redirect('/admin/dashboard');
    } else if (role === 'operator') {
      return res.redirect('/operator/dashboard');
    } else {
      return res.redirect('/user/dashboard');
    }
  }
  res.render('auth/login');
});

router.post('/login', csrfProtection, asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    req.flash('error', 'All fields are required');
    return res.redirect('/login');
  }

  const user = await getUserByEmail(email);
  if (!user) {
    req.flash('error', 'Invalid credentials');
    return res.redirect('/login');
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    req.flash('error', 'Invalid credentials');
    return res.redirect('/login');
  }

  req.session.user = {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role
  };

  req.flash('success', `Welcome back, ${user.username}!`);

  if (user.role === 'admin') {
    return res.redirect('/admin/dashboard');
  } else if (user.role === 'operator') {
    return res.redirect('/operator/dashboard');
  } else {
    return res.redirect('/user/dashboard');
  }
}));

router.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

export default router;

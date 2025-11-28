import crypto from 'crypto';
import express from 'express';
import session from 'express-session';
import flash from 'connect-flash';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config();

import authRoutes from './routes/auth.js';
import userRoutes from './routes/user.js';
import operatorRoutes from './routes/operator.js';
import adminRoutes from './routes/admin.js';
import imageRoutes from './routes/images.js';
import { generateCSRFToken } from './middleware/csrf.js';
import { globalErrorHandler, notFoundHandler } from './middleware/errorHandler.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

// Use SESSION_SECRET from environment or generate one (fallback for local dev)
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');


const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: sessionSecret,
  resave: true,
  saveUninitialized: true,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true
  }
}));

app.use(flash());

// Content Security Policy
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; " +
    "script-src 'self' https://cdn.tailwindcss.com; " +
    "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; " +
    "img-src 'self' data: https: http: blob:; " +
    "font-src 'self' data: https://fonts.gstatic.com; " +
    "connect-src 'self'; " +
    "frame-ancestors 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self'; " +
    "object-src 'none'; " +
    "media-src 'self'; " +
    "worker-src 'none';"
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.success = req.flash('success');
  res.locals.error = req.flash('error');
  res.locals.csrfToken = generateCSRFToken(req);
  next();
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use('/', authRoutes);
app.use('/user', userRoutes);
app.use('/operator', operatorRoutes);
app.use('/admin', adminRoutes);
app.use('/images', imageRoutes);

app.get('/', (req, res) => {
  if (req.session.user) {
    const role = req.session.user.role;
    if (role === 'admin') return res.redirect('/admin/dashboard');
    if (role === 'operator') return res.redirect('/operator/dashboard');
    return res.redirect('/user/dashboard');
  }
  res.redirect('/login');
});

app.use(notFoundHandler);
app.use(globalErrorHandler);

app.listen(PORT, () => {
  console.log(`Server running on http://127.0.0.1:${PORT}`);
  console.log('Routes registered:');
  console.log('  - Auth routes: /login, /register, /logout');
  console.log('  - User routes: /user/*');
  console.log('  - Operator routes: /operator/*');
  console.log('  - Admin routes: /admin/*');
  console.log('  - Image serving: /images/:filename');
});

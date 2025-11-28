import pool from '../database/db.js';

export function requireAuth(req, res, next) {
  if (!req.session.user) {
    req.flash('error', 'Please login to continue');
    return res.redirect('/login');
  }
  next();
}

export async function hasRole(req, role) {
  if (!req.session.user) return false;
  try {
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE username = ? AND role = ?',
      [req.session.user.username, role]
    );
    return rows.length > 0;
  } catch (error) {
    return false;
  }
}

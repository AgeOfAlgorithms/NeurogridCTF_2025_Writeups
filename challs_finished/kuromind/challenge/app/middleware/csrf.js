import crypto from 'crypto';

/**
 * Generate CSRF token
 */
export function generateCSRFToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

/**
 * Verify CSRF token
 */
export function verifyCSRFToken(req) {
  const token = req.body?._csrf || req.query?._csrf || req.headers['x-csrf-token'];
  const sessionToken = req.session.csrfToken;
  
  if (!sessionToken || !token) {
    return false;
  }
  
  try {
    return crypto.timingSafeEqual(
      Buffer.from(token, 'hex'),
      Buffer.from(sessionToken, 'hex')
    );
  } catch (e) {
    return false;
  }
}

/**
 * CSRF middleware - works with regular and multipart forms
 */
export function csrfProtection(req, res, next) {
  // Skip CSRF for GET, HEAD, OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  if (!verifyCSRFToken(req)) {
    return res.status(403).send('CSRF token validation failed');
  }
  
  next();
}

/**
 * CSRF middleware for routes that use multer (multipart/form-data)
 * This should be placed AFTER multer middleware
 */
export function csrfProtectionAfterMulter(req, res, next) {
  // Skip CSRF for GET, HEAD, OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  if (!verifyCSRFToken(req)) {
    return res.status(403).send('CSRF token validation failed');
  }
  
  next();
}

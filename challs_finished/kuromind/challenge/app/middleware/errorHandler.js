// Wrapper to catch async errors and pass to global error handler
export const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// Global error handling middleware (must be last!)
export const globalErrorHandler = (err, req, res, next) => {
  console.error('[ERROR]', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString()
  });

  // Set default error status
  err.statusCode = err.statusCode || 500;

  // Flash error message to user
  req.flash('error', err.message || 'An error occurred. Please try again.');

  // Return to previous page or home
  const referrer = req.get('referer') || '/';
  res.redirect(referrer);
};

// 404 handler
export const notFoundHandler = (req, res) => {
  res.status(404).render('404', {
    url: req.url,
    method: req.method
  });
};

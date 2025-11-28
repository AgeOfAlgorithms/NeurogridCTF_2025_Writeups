import express from 'express';
import { requireAuth, hasRole } from '../middleware/auth.js';
import { csrfProtection } from '../middleware/csrf.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import {
  getKnowledgeItems,
  getKnowledgeItemById,
  getRegularUsers,
  updateKnowledgeItem,
  addReviewHistory,
  getOperatorHistory,
  updateUserRole,
  isProtectedUser,
  ROLE_SUGGESTIONS,
  PROTECTED_ROLES
} from '../data/store.js';

const router = express.Router();

router.use(requireAuth);
router.use(asyncHandler(async (req, res, next) => {
  if (!(await hasRole(req, 'operator')) && !(await hasRole(req, 'admin'))) {
    req.flash('error', 'Access denied');
    return res.redirect('/user/dashboard');
  }
  next();
}));

router.get('/dashboard', asyncHandler(async (req, res) => {
  const allItems = await getKnowledgeItems();
  const pendingItems = allItems.filter(k => k.status === 'pending');
  const history = await getOperatorHistory(req.session.user.id);
  res.render('operator/dashboard', {
    user: req.session.user,
    pendingItems,
    history
  });
}));

router.get('/review/:id', asyncHandler(async (req, res) => {
  const { id } = req.params;
  const item = await getKnowledgeItemById(parseInt(id));

  if (!item) {
    req.flash('error', 'Item not found');
    return res.redirect('/operator/dashboard');
  }

  if (item.status !== 'pending') {
    req.flash('error', 'This item has already been reviewed');
    return res.redirect('/operator/dashboard');
  }

  res.render('operator/review', {
    user: req.session.user,
    item
  });
}));

router.post('/review/:id', csrfProtection, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { action, feedback } = req.body;

  const item = await getKnowledgeItemById(parseInt(id));
  if (!item) {
    req.flash('error', 'Item not found');
    return res.redirect('/operator/dashboard');
  }

  if (item.status !== 'pending') {
    req.flash('error', 'This item has already been reviewed');
    return res.redirect('/operator/dashboard');
  }

  const newStatus = action === 'approve' ? 'approved' : 'rejected';
  await updateKnowledgeItem(parseInt(id), {
    status: newStatus,
    reviewFeedback: feedback
  });

  await addReviewHistory({
    knowledgeId: parseInt(id),
    operatorId: req.session.user.id,
    action: newStatus,
    feedback
  });

  req.flash('success', `Item ${newStatus} successfully`);
  res.redirect('/operator/dashboard');
}));

router.get('/users', asyncHandler(async (req, res) => {
  const regularUsers = await getRegularUsers();
  res.render('operator/users', { 
    user: req.session.user,
    users: regularUsers,
    roleSuggestions: ROLE_SUGGESTIONS
  });
}));

router.post('/users/:id/role', csrfProtection, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const role = req.body.role && req.body.role.trim();
  const userId = parseInt(id);

  if (await isProtectedUser(userId)) {
    req.flash('error', 'Cannot modify system accounts');
    return res.redirect('/operator/users');
  }

  if (PROTECTED_ROLES.includes(role)) {
    req.flash('error', 'Cannot assign system roles');
    return res.redirect('/operator/users');
  }

  const updatedUser = await updateUserRole(userId, role);
  if (updatedUser) {
    req.flash('success', `User role updated to ${role}`);
  } else {
    req.flash('error', 'Failed to update user role');
  }

  res.redirect('/operator/users');
}));

router.get('/history', asyncHandler(async (req, res) => {
  const history = await getOperatorHistory(req.session.user.id);
  res.render('operator/history', {
    user: req.session.user,
    history
  });
}));

export default router;

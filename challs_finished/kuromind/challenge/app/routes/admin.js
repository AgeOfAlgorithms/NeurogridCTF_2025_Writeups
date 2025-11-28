import express from 'express';
import { requireAuth, hasRole } from '../middleware/auth.js';
import { csrfProtection } from '../middleware/csrf.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import {
  getUsers,
  getUserById,
  getApprovedKnowledgeItems,
  getKnowledgeItemById,
  updateUserRole,
  isProtectedUser,
  ROLE_SUGGESTIONS,
  PROTECTED_ROLES
} from '../data/store.js';

const router = express.Router();

router.use(requireAuth);
router.use(asyncHandler(async (req, res, next) => {
  if (!(await hasRole(req, 'admin'))) {
    req.flash('error', 'Access denied');
    return res.redirect('/user/dashboard');
  }
  next();
}));

router.get('/dashboard', asyncHandler(async (req, res) => {
  const availableKnowledge = await getApprovedKnowledgeItems();

  res.render('admin/dashboard', {
    user: req.session.user,
    items: availableKnowledge
  });
}));

router.get('/knowledge/:id', asyncHandler(async (req, res) => {
  const item = await getKnowledgeItemById(parseInt(req.params.id));

  if (!item) {
    req.flash('error', 'Knowledge item not found');
    return res.redirect('/admin/dashboard');
  }

  if (item.status !== 'approved') {
    req.flash('error', 'This knowledge is not available yet');
    return res.redirect('/admin/dashboard');
  }

  const submitter = await getUserById(item.userId);
  const submittedBy = submitter ? submitter.username : 'Unknown User';

  res.render('admin/view', {
    user: req.session.user,
    item: { ...item, submittedBy }
  });
}));

router.get('/users', asyncHandler(async (req, res) => {
  const allUsers = await getUsers();
  res.render('admin/users', {
    user: req.session.user,
    users: allUsers,
    roleSuggestions: ROLE_SUGGESTIONS,
    protectedRoles: PROTECTED_ROLES
  });
}));

router.post('/users/:id/role', csrfProtection, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const role = req.body.role && req.body.role.trim();
  const userId = parseInt(id);

  if (await isProtectedUser(userId)) {
    req.flash('error', 'Cannot modify system accounts');
    return res.redirect('/admin/users');
  }

  if (PROTECTED_ROLES.includes(role)) {
    req.flash('error', 'Cannot assign system roles');
    return res.redirect('/admin/users');
  }

  const updatedUser = await updateUserRole(userId, role);
  if (updatedUser) {
    req.flash('success', `User role updated to ${role}`);
  } else {
    req.flash('error', 'Failed to update user role');
  }

  res.redirect('/admin/users');
}));

router.get('/all-knowledge', asyncHandler(async (req, res) => {
  const availableKnowledge = await getApprovedKnowledgeItems();

  res.render('admin/all-knowledge', {
    user: req.session.user,
    items: availableKnowledge
  });
}));

export default router;

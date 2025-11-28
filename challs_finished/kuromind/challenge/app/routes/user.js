import express from 'express';
import { requireAuth, hasRole } from '../middleware/auth.js';
import { upload, validateUploadedFile } from '../middleware/upload.js';
import { csrfProtection, csrfProtectionAfterMulter } from '../middleware/csrf.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { deepMerge } from '../utils/merge.js';
import {
  getApprovedPublicKnowledgeItems,
  getKnowledgeItemById,
  addKnowledgeItem,
  updateKnowledgeItem,
  addDraft,
  updateDraft,
  deleteDraft,
  getUserDrafts,
  getDraftById,
  submitDraftAsKnowledge,
  getUserSubmissionHistory,
  DEFAULT_IMAGE
} from '../data/store.js';

const router = express.Router();

router.use(requireAuth);
router.use(asyncHandler(async (req, res, next) => {
  if (await hasRole(req, 'admin')) {
    return res.redirect('/admin/dashboard');
  }
  if (await hasRole(req, 'operator')) {
    return res.redirect('/operator/dashboard');
  }
  next();
}));

// Dashboard
router.get('/dashboard', asyncHandler(async (req, res) => {
  const publicKnowledge = await getApprovedPublicKnowledgeItems();
  const userDrafts = await getUserDrafts(req.session.user.id);

  res.render('user/dashboard', {
    knowledge: publicKnowledge,
    drafts: userDrafts
  });
}));

// View knowledge details (public approved only)
router.get('/knowledge/:id', asyncHandler(async (req, res) => {
  const item = await getKnowledgeItemById(parseInt(req.params.id));
  
  if (!item) {
    req.flash('error', 'Knowledge item not found');
    return res.redirect('/user/dashboard');
  }

  // Users can only view public approved knowledge
  if (item.status !== 'approved' || item.isRestricted) {
    req.flash('error', 'This knowledge is restricted or not available');
    return res.redirect('/user/dashboard');
  }

  res.render('user/view', { item });
}));

// Drafts page
router.get('/drafts', asyncHandler(async (req, res) => {
  const userDrafts = await getUserDrafts(req.session.user.id);
  res.render('user/drafts', { drafts: userDrafts });
}));


// Delete draft handler
router.post('/drafts/delete/:id', csrfProtection, asyncHandler(async (req, res) => {
  const draftId = parseInt(req.params.id);
  const draft = await getDraftById(draftId);

  if (!draft || draft.userId !== req.session.user.id) {
    req.flash('error', 'Draft not found');
    return res.redirect('/user/drafts');
  }

  await deleteDraft(draftId);
  req.flash('success', 'Draft deleted successfully');
  res.redirect('/user/drafts');
}));

// Submit draft for review
router.post('/drafts/submit/:id', csrfProtection, asyncHandler(async (req, res) => {
  const draftId = parseInt(req.params.id);
  const draft = await getDraftById(draftId);

  if (!draft || draft.userId !== req.session.user.id) {
    req.flash('error', 'Draft not found');
    return res.redirect('/user/drafts');
  }

  await submitDraftAsKnowledge(draftId);
  
  // Trigger bot review
  try {
      fetch('http://127.0.0.1:1337/review', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    console.log('[App] Bot review triggered for new submission');
  } catch (error) {
    console.error('[App] Failed to trigger bot review:', error.message);
  }
  
  req.flash('success', 'Draft submitted for review');
  res.redirect('/user/history');
}));

// Add knowledge page (creates draft)
router.get('/add', (req, res) => {
  res.render('user/add');
});

// Add knowledge handler (creates draft) with image upload
router.post('/add', upload.single('image'), validateUploadedFile, csrfProtectionAfterMulter, asyncHandler(async (req, res) => {
  const { title, description, tags } = req.body;

  if (!title || !description) {
    req.flash('error', 'Title and description are required');
    return res.redirect('/user/add');
  }

  const imageName = req.file ? req.file.filename : DEFAULT_IMAGE;

  let parsedTags = {};
  if (tags) {
    try {
      parsedTags = JSON.parse(tags);
    } catch (e) {
      console.error('Invalid tags format:', e);

      req.flash('error', 'Invalid tags format');
      return res.redirect('/user/add');
    }
  }

  await addDraft({
    title,
    description,
    tags: parsedTags,
    image: imageName,
    userId: req.session.user.id
  });

  req.flash('success', 'Draft saved successfully');
  res.redirect('/user/drafts');
}));

// User submission history
router.get('/history', asyncHandler(async (req, res) => {
  const history = await getUserSubmissionHistory(req.session.user.id);
  res.render('user/history', { history });
}));

// Edit page - handles both drafts and rejected submissions
router.get('/edit/:id', asyncHandler(async (req, res) => {
  const itemId = parseInt(req.params.id);
  
  // First check if it's a draft
  const draft = await getDraftById(itemId);
  if (draft && draft.userId === req.session.user.id) {
    return res.render('user/edit', { item: draft, isDraft: true });
  }

  // Otherwise check if it's a rejected knowledge item
  const item = await getKnowledgeItemById(itemId);

  if (!item) {
    req.flash('error', 'Item not found');
    return res.redirect('/user/drafts');
  }

  if (item.userId !== req.session.user.id) {
    req.flash('error', 'Item not found');
    return res.redirect('/user/drafts');
  }

  if (item.status !== 'rejected') {
    req.flash('error', 'Only rejected items can be edited');
    return res.redirect('/user/history');
  }

  res.render('user/edit', { item, isDraft: false });
}));

// Edit handler - handles both drafts and rejected submissions with image upload
router.post('/edit/:id', upload.single('image'), validateUploadedFile, csrfProtectionAfterMulter, asyncHandler(async (req, res) => {
  const { title, description, tags } = req.body;
  const itemId = parseInt(req.params.id);

  if (!title || !description) {
    req.flash('error', 'Title and description are required');
    return res.redirect(`/user/edit/${itemId}`);
  }

  // First check if it's a draft
  const draft = await getDraftById(itemId);
  if (draft && draft.userId === req.session.user.id) {
    const imageName = req.file ? req.file.filename : draft.image;

    let updatedTags = draft.tags || {};
    if (tags) {
      try {
        const newTags = JSON.parse(tags);
        updatedTags = deepMerge(updatedTags, newTags);
      } catch (e) {
        console.error('Invalid tags format:', e);
        req.flash('error', 'Invalid tags format');
        return res.redirect(`/user/edit/${itemId}`);
      }
    }

    await updateDraft(itemId, {
      title,
      description,
      tags: updatedTags,
      image: imageName
    });

    req.flash('success', 'Draft updated successfully');
    return res.redirect('/user/drafts');
  }

  // Otherwise handle rejected knowledge item
  const item = await getKnowledgeItemById(itemId);

  if (!item) {
    req.flash('error', 'Item not found');
    return res.redirect('/user/history');
  }

  if (item.userId !== req.session.user.id) {
    req.flash('error', 'Item not found');
    return res.redirect('/user/history');
  }

  if (item.status !== 'rejected') {
    req.flash('error', 'Only rejected items can be edited');
    return res.redirect('/user/history');
  }

  const imageName = req.file ? req.file.filename : item.image;

  let updatedTags = item.tags || {};
  if (tags) {
    try {
      const newTags = JSON.parse(tags);
      updatedTags = deepMerge(updatedTags, newTags);
    } catch (e) {
      console.error('Invalid tags format:', e);
      req.flash('error', 'Invalid tags format');
      return res.redirect(`/user/edit/${itemId}`);
    }
  }

  await updateKnowledgeItem(itemId, {
    title,
    description,
    tags: updatedTags,
    image: imageName,
    status: 'pending'
  });

  // Trigger bot review
  try {
      fetch('http://127.0.0.1:1337/review', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    console.log('[App] Bot review triggered for resubmission');
  } catch (error) {
    console.error('[App] Failed to trigger bot review:', error.message);
  }

  req.flash('success', 'Knowledge updated and resubmitted for review');
  res.redirect('/user/history');
}));

export default router;

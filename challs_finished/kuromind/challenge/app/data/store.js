import bcrypt from 'bcryptjs';
import pool from '../database/db.js';

export const ROLE_SUGGESTIONS = [
  'None',
  'Apprentice',
  'Scholar',
  'Sage',
  'Master',
  'Elder',
  'Guardian',
  'Seeker',
  'Keeper',
  'Archivist'
];

export const PROTECTED_ROLES = ['admin', 'operator'];

export const DEFAULT_IMAGE = 'the_unknown.png';

export async function addUser(userData) {
  try {
    const [result] = await pool.execute(
      'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
      [userData.username, userData.email, userData.password, userData.role]
    );

    return {
      id: result.insertId,
      ...userData,
      createdAt: new Date()
    };
  } catch (e) {
    console.error('[DB] Error adding user:', e.message);
    throw new Error('Failed to create user account');
  }
}

export async function updateUserRole(userId, role) {
  try {
    if (await isProtectedUser(userId)) {
      return null;
    }

    const [result] = await pool.execute(
      'UPDATE users SET role = ? WHERE id = ?',
      [role, userId]
    );

    if (result.affectedRows > 0) {
      const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [userId]);
      return rows[0];
    }

    return null;
  } catch (e) {
    console.error('[DB] Error updating user role:', e.message);
    throw new Error('Failed to update user role');
  }
}

export async function isProtectedUser(userId) {
  const [rows] = await pool.execute('SELECT role FROM users WHERE id = ?', [userId]);
  return rows.length > 0 && PROTECTED_ROLES.includes(rows[0].role);
}

export function hasElevatedPermissions(role) {
  return PROTECTED_ROLES.includes(role);
}

export async function getUsers() {
  const [rows] = await pool.execute('SELECT * FROM users ORDER BY createdAt DESC');
  return rows;
}

export async function getUserByEmail(email) {
  const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
  return rows[0] || null;
}

export async function getUserById(id) {
  const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [id]);
  return rows[0] || null;
}

export async function getApprovedPublicKnowledgeItems() {
  const [rows] = await pool.execute(
    'SELECT * FROM knowledge_items WHERE status = ? AND isRestricted = ? ORDER BY createdAt DESC',
    ['approved', false]
  );
  return rows.map(item => {
    if (item.tags && typeof item.tags === 'string') {
      item.tags = JSON.parse(item.tags);
    }
    return item;
  });
}

export async function getApprovedKnowledgeItems() {
  const [rows] = await pool.execute(
    'SELECT * FROM knowledge_items WHERE status = ? ORDER BY createdAt DESC',
    ['approved']
  );
  return rows.map(item => {
    if (item.tags && typeof item.tags === 'string') {
      item.tags = JSON.parse(item.tags);
    }
    return item;
  });
}

export async function getKnowledgeItemById(id) {
  const [rows] = await pool.execute('SELECT * FROM knowledge_items WHERE id = ?', [id]);
  const item = rows[0] || null;
  if (item && typeof item.tags === 'string') {
    item.tags = JSON.parse(item.tags);
  }
  return item;
}

export async function getRegularUsers() {
  const [rows] = await pool.execute(
    'SELECT * FROM users WHERE role NOT IN (?, ?) ORDER BY createdAt DESC',
    ['admin', 'operator']
  );
  return rows;
}

export async function addDraft(draftData) {
  try {
    const [result] = await pool.execute(
      'INSERT INTO drafts (title, description, tags, image, userId) VALUES (?, ?, ?, ?, ?)',
      [draftData.title, draftData.description, JSON.stringify(draftData.tags), draftData.image, draftData.userId]
    );

    return {
      id: result.insertId,
      ...draftData,
      createdAt: new Date(),
      updatedAt: new Date()
    };
  } catch (e) {
    console.error('[DB] Error adding draft:', e.message);
    throw new Error('Failed to create draft');
  }
}

export async function updateDraft(id, updates) {
  try {
    const [result] = await pool.execute(
      'UPDATE drafts SET title = ?, description = ?, tags = ?, image = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?',
      [updates.title, updates.description, JSON.stringify(updates.tags), updates.image, id]
    );

    if (result.affectedRows > 0) {
      const [rows] = await pool.execute('SELECT * FROM drafts WHERE id = ?', [id]);
      const draft = rows[0];
      if (draft && typeof draft.tags === 'string') {
        draft.tags = JSON.parse(draft.tags);
      }
      return draft;
    }

    return null;
  } catch (e) {
    console.error('Error updating draft:', e.message);
    return null;
  }
}

export async function deleteDraft(id) {
  try {
    const [result] = await pool.execute('DELETE FROM drafts WHERE id = ?', [id]);
    return result.affectedRows > 0;
  } catch (e) {
    console.error('[DB] Error deleting draft:', e.message);
    throw new Error('Failed to delete draft');
  }
}

export async function getUserDrafts(userId) {
  const [rows] = await pool.execute('SELECT * FROM drafts WHERE userId = ? ORDER BY updatedAt DESC', [userId]);
  return rows.map(draft => {
    if (draft.tags && typeof draft.tags === 'string') {
      draft.tags = JSON.parse(draft.tags);
    }
    return draft;
  });
}

export async function getDraftById(id) {
  const [rows] = await pool.execute('SELECT * FROM drafts WHERE id = ?', [id]);
  const draft = rows[0] || null;
  if (draft && typeof draft.tags === 'string') {
    draft.tags = JSON.parse(draft.tags);
  }
  return draft;
}

export async function submitDraftAsKnowledge(draftId) {
  const draft = await getDraftById(draftId);
  if (!draft) return null;

  const newKnowledge = await addKnowledgeItem({
    title: draft.title,
    description: draft.description,
    tags: draft.tags,
    image: draft.image,
    userId: draft.userId,
    status: 'pending',
    isRestricted: false
  });

  await deleteDraft(draftId);
  return newKnowledge;
}

export async function addKnowledgeItem(itemData) {
  try {
    const [result] = await pool.execute(
      'INSERT INTO knowledge_items (title, description, tags, image, userId, status, isRestricted, dangerLevel) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [
        itemData.title,
        itemData.description,
        JSON.stringify(itemData.tags),
        itemData.image,
        itemData.userId,
        itemData.status,
        itemData.isRestricted || false,
        itemData.dangerLevel || null
      ]
    );

    return {
      id: result.insertId,
      ...itemData,
      createdAt: new Date()
    };
  } catch (e) {
    console.error('[DB] Error adding knowledge item:', e.message);
    throw new Error('Failed to create knowledge item');
  }
}

export async function updateKnowledgeItem(id, updates) {
  const fields = [];
  const values = [];

  if (updates.title !== undefined) {
    fields.push('title = ?');
    values.push(updates.title);
  }
  if (updates.description !== undefined) {
    fields.push('description = ?');
    values.push(updates.description);
  }
  if (updates.tags !== undefined) {
    fields.push('tags = ?');
    values.push(JSON.stringify(updates.tags));
  }
  if (updates.image !== undefined) {
    fields.push('image = ?');
    values.push(updates.image);
  }
  if (updates.status !== undefined) {
    fields.push('status = ?');
    values.push(updates.status);
  }
  if (updates.isRestricted !== undefined) {
    fields.push('isRestricted = ?');
    values.push(updates.isRestricted);
  }
  if (updates.dangerLevel !== undefined) {
    fields.push('dangerLevel = ?');
    values.push(updates.dangerLevel);
  }
  if (updates.reviewFeedback !== undefined) {
    fields.push('reviewFeedback = ?');
    values.push(updates.reviewFeedback);
  }

  if (fields.length === 0) return null;

  values.push(id);
  const [result] = await pool.execute(
    `UPDATE knowledge_items SET ${fields.join(', ')} WHERE id = ?`,
    values
  );

  if (result.affectedRows > 0) {
    const [rows] = await pool.execute('SELECT * FROM knowledge_items WHERE id = ?', [id]);
    const item = rows[0];
    if (item && typeof item.tags === 'string') {
      item.tags = JSON.parse(item.tags);
    }
    return item;
  }

  return null;
}

export async function getUserKnowledgeItems(userId) {
  const [rows] = await pool.execute(
    'SELECT * FROM knowledge_items WHERE userId = ? ORDER BY createdAt DESC',
    [userId]
  );
  return rows.map(item => {
    if (item.tags && typeof item.tags === 'string') {
      item.tags = JSON.parse(item.tags);
    }
    return item;
  });
}

export async function getKnowledgeItems() {
  const [rows] = await pool.execute('SELECT * FROM knowledge_items ORDER BY createdAt DESC');
  return rows.map(item => {
    if (item.tags && typeof item.tags === 'string') {
      item.tags = JSON.parse(item.tags);
    }
    return item;
  });
}

export async function addReviewHistory(historyData) {
  try {
    const [result] = await pool.execute(
      'INSERT INTO review_history (knowledgeId, operatorId, action, feedback) VALUES (?, ?, ?, ?)',
      [
        historyData.knowledgeId,
        historyData.operatorId,
        historyData.action,
        historyData.feedback || null
      ]
    );

    return {
      id: result.insertId,
      ...historyData,
      timestamp: new Date()
    };
  } catch (e) {
    console.error('[DB] Error adding review history:', e.message);
    throw new Error('Failed to record review');
  }
}

export async function getOperatorHistory(operatorId) {
  const [rows] = await pool.execute(
    `SELECT
      rh.*,
      ki.title as knowledgeTitle,
      ki.description as knowledgeDescription,
      ki.tags as knowledgeTags,
      ki.status as knowledgeStatus,
      ki.isRestricted as knowledgeIsRestricted,
      ki.image as knowledgeImage,
      ki.dangerLevel as knowledgeDangerLevel,
      u.username as submitterName
     FROM review_history rh
     LEFT JOIN knowledge_items ki ON rh.knowledgeId = ki.id
     LEFT JOIN users u ON ki.userId = u.id
     WHERE rh.operatorId = ?
     ORDER BY rh.timestamp DESC`,
    [operatorId]
  );
  return rows.map(row => {
    if (row.knowledgeTags && typeof row.knowledgeTags === 'string') {
      row.knowledgeTags = JSON.parse(row.knowledgeTags);
    }
    return row;
  });
}

export async function getUserSubmissionHistory(userId) {
  const [rows] = await pool.execute(
    `SELECT
      ki.*,
      u.username as submitterName,
      rh.action as reviewAction,
      rh.feedback as reviewFeedback,
      rh.timestamp as reviewTimestamp,
      op.username as reviewerName
     FROM knowledge_items ki
     LEFT JOIN users u ON ki.userId = u.id
     LEFT JOIN review_history rh ON ki.id = rh.knowledgeId
     LEFT JOIN users op ON rh.operatorId = op.id
     WHERE ki.userId = ?
     ORDER BY ki.createdAt DESC`,
    [userId]
  );
  return rows.map(row => {
    if (row.tags && typeof row.tags === 'string') {
      row.tags = JSON.parse(row.tags);
    }
    return row;
  });
}

export async function getReviewHistory() {
  const [rows] = await pool.execute('SELECT * FROM review_history ORDER BY timestamp DESC');
  return rows;
}

// Session store - simple in-memory store
export const sessionStore = {};

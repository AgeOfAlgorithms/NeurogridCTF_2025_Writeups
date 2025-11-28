import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { asyncHandler } from '../middleware/errorHandler.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = express.Router();

router.get('/:filename', asyncHandler((req, res) => {
  try {
    const filename = path.basename(req.params.filename);
    const uploadsDir = path.join(__dirname, '../uploads');
    const filepath = path.join(uploadsDir, filename);

    // Path traversal protection
    if (!filepath.startsWith(uploadsDir)) {
      return res.status(403).send('Forbidden');
    }

    // Check if file exists
    if (!fs.existsSync(filepath)) {
      return res.status(404).send('Image not found');
    }

    // Validate file extension
    const allowedExts = ['.jpeg', '.jpg', '.png', '.gif', '.webp'];
    const ext = path.extname(filename).toLowerCase();

    if (!allowedExts.includes(ext)) {
      return res.status(403).send('Forbidden');
    }

    // Serve the file
    res.sendFile(filepath, (err) => {
      if (err) {
        console.error('[IMAGE] Error sending file:', err);
        res.status(500).send('Error loading image');
      }
    });
  } catch (error) {
    console.error('[IMAGE] Error processing request:', error);
    res.status(500).send('Error loading image');
  }
}));

export default router;

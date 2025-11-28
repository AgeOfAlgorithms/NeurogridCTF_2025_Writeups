import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ALLOWED_MIMES = ['image/jpeg', 'image/jpg', 'image/png'];
const ALLOWED_EXTS = ['.jpeg', '.jpg', '.png'];

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, '../uploads'));
  },
  filename: function (req, file, cb) {
    const randomName = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, randomName + ext);
  }
});

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  const mime = file.mimetype.toLowerCase();

  // Validate extension
  if (!ALLOWED_EXTS.includes(ext)) {
    return cb(new Error('Invalid file extension'));
  }

  // Validate MIME type
  if (!ALLOWED_MIMES.includes(mime)) {
    return cb(new Error('Invalid MIME type'));
  }

  // Both validation passed, accept file
  cb(null, true);
};

export const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 1
  },
  fileFilter: fileFilter
});

export const validateUploadedFile = (req, res, next) => {
  return next();
};

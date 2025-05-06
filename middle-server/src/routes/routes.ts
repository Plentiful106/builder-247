import express from 'express';
import { nonceMiddleware } from '../middleware/nonce';

const router = express.Router();

// Example route using nonce middleware
router.get('/nonce', nonceMiddleware);

router.post('/secure-endpoint', nonceMiddleware, (req, res) => {
  // This route requires a valid nonce
  res.json({ message: 'Secure endpoint accessed successfully' });
});

export default router;
import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

// In-memory store for nonces (in production, use a distributed cache like Redis)
const nonceStore = new Set<string>();

// Maximum age of a nonce (5 minutes)
const NONCE_MAX_AGE = 5 * 60 * 1000;

// Nonce storage with expiration
const nonceCache: { [key: string]: number } = {};

/**
 * Generate a cryptographically secure nonce
 * @returns {string} A unique nonce
 */
export function generateNonce(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Validate a nonce
 * @param {string} nonce - The nonce to validate
 * @returns {boolean} Whether the nonce is valid
 */
export function validateNonce(nonce: string): boolean {
  // Check if nonce exists and is not expired
  const timestamp = nonceCache[nonce];
  
  if (!timestamp) {
    return false;
  }

  // Check if nonce is within max age
  const currentTime = Date.now();
  if (currentTime - timestamp > NONCE_MAX_AGE) {
    delete nonceCache[nonce];
    return false;
  }

  // Remove used nonce to prevent replay
  delete nonceCache[nonce];
  return true;
}

/**
 * Middleware to handle nonce generation and validation
 * @param {Request} req - Express request object
 * @param {Response} res - Express response object
 * @param {NextFunction} next - Express next middleware function
 */
export function nonceMiddleware(req: Request, res: Response, next: NextFunction) {
  // Handle nonce generation for GET requests
  if (req.method === 'GET') {
    const nonce = generateNonce();
    nonceCache[nonce] = Date.now();
    return res.json({ nonce });
  }

  // Validate nonce for other methods
  const nonce = req.headers['x-nonce'] as string;

  if (!nonce) {
    return res.status(400).json({ error: 'Nonce is required' });
  }

  if (!validateNonce(nonce)) {
    return res.status(401).json({ error: 'Invalid or expired nonce' });
  }

  next();
}

export default nonceMiddleware;
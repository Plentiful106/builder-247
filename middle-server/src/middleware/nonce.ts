import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

/**
 * NonceMiddleware provides protection against replay attacks by ensuring 
 * each request has a unique nonce and is used only once.
 */
export class NonceMiddleware {
  // In-memory store of used nonces (in production, use a distributed cache)
  private static usedNonces: Set<string> = new Set();

  /**
   * Generate a cryptographically secure random nonce
   * @returns {string} A unique nonce value
   */
  static generateNonce(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Validate and track nonce to prevent replay attacks
   * @param req Express request object 
   * @param res Express response object
   * @param next Express next middleware function
   */
  static validate(req: Request, res: Response, next: NextFunction): void {
    // Extract nonce from request headers or body
    const nonce = req.headers['x-nonce'] as string || req.body?.nonce;

    // Check if nonce is present
    if (!nonce) {
      res.status(400).json({ 
        error: 'Nonce is required',
        message: 'A unique nonce must be provided with each request' 
      });
      return;
    }

    // Check nonce length and format
    if (typeof nonce !== 'string' || nonce.length !== 64) {
      res.status(400).json({ 
        error: 'Invalid nonce',
        message: 'Nonce must be a 64-character hexadecimal string' 
      });
      return;
    }

    // Check if nonce has been used before
    if (this.usedNonces.has(nonce)) {
      res.status(409).json({ 
        error: 'Nonce already used',
        message: 'This nonce has already been consumed' 
      });
      return;
    }

    // Mark nonce as used
    this.usedNonces.add(nonce);

    // Optional: Implement nonce expiration (remove after a certain time)
    // This is a simple implementation; in production, use a distributed cache with TTL
    setTimeout(() => {
      this.usedNonces.delete(nonce);
    }, 5 * 60 * 1000); // Remove nonce after 5 minutes

    next();
  }

  /**
   * Clear all used nonces (useful for testing)
   */
  static clearNonces(): void {
    this.usedNonces.clear();
  }
}
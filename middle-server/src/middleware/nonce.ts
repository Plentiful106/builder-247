import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import winston from 'winston';

// Configure logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'nonce-validation.log' }),
    new winston.transports.Console()
  ]
});

// Nonce configuration
const NONCE_MAX_AGE = 5 * 60 * 1000; // 5 minutes
const MAX_NONCE_STORE_SIZE = 10000;

class NonceManager {
  private nonceStore: Map<string, number>;

  constructor() {
    this.nonceStore = new Map();
  }

  /**
   * Generate a cryptographically secure nonce
   * @returns {string} A unique nonce
   */
  generateNonce(): string {
    const nonce = crypto.randomBytes(32).toString('hex');
    const timestamp = Date.now();

    // Prevent nonce store from growing indefinitely
    if (this.nonceStore.size >= MAX_NONCE_STORE_SIZE) {
      this.pruneExpiredNonces();
    }

    this.nonceStore.set(nonce, timestamp);
    return nonce;
  }

  /**
   * Validate a nonce
   * @param {string} nonce - The nonce to validate
   * @returns {boolean} Whether the nonce is valid
   */
  validateNonce(nonce: string): boolean {
    const timestamp = this.nonceStore.get(nonce);

    // Check if nonce exists
    if (!timestamp) {
      logger.warn('Nonce validation failed: Nonce not found', { nonce });
      return false;
    }

    // Check nonce age
    const currentTime = Date.now();
    if (currentTime - timestamp > NONCE_MAX_AGE) {
      logger.warn('Nonce validation failed: Nonce expired', { 
        nonce, 
        age: currentTime - timestamp 
      });
      this.nonceStore.delete(nonce);
      return false;
    }

    // Remove used nonce to prevent replay
    this.nonceStore.delete(nonce);
    return true;
  }

  /**
   * Prune expired nonces to prevent memory growth
   */
  private pruneExpiredNonces(): void {
    const currentTime = Date.now();
    for (const [nonce, timestamp] of this.nonceStore.entries()) {
      if (currentTime - timestamp > NONCE_MAX_AGE) {
        this.nonceStore.delete(nonce);
      }
    }
  }
}

// Singleton instance of NonceManager
const nonceManager = new NonceManager();

/**
 * Middleware to handle nonce generation and validation
 * @param {Request} req - Express request object
 * @param {Response} res - Express response object
 * @param {NextFunction} next - Express next middleware function
 */
export function nonceMiddleware(req: Request, res: Response, next: NextFunction) {
  // Log nonce validation attempt
  logger.info('Nonce middleware invoked', { 
    method: req.method, 
    path: req.path 
  });

  // Generate nonce for GET requests
  if (req.method === 'GET') {
    const nonce = nonceManager.generateNonce();
    return res.status(200).json({ nonce });
  }

  // Validate nonce for other methods
  const nonce = req.headers['x-nonce'] as string;

  // Check for missing nonce
  if (!nonce) {
    logger.error('Nonce validation failed: Missing nonce', { 
      method: req.method, 
      path: req.path 
    });
    return res.status(400).json({ 
      error: 'Nonce is required',
      message: 'Please obtain a valid nonce before making this request'
    });
  }

  // Validate nonce
  if (!nonceManager.validateNonce(nonce)) {
    logger.error('Nonce validation failed: Invalid or expired nonce', { 
      method: req.method, 
      path: req.path 
    });
    return res.status(400).json({ 
      error: 'Invalid or expired nonce',
      message: 'The provided nonce is invalid or has expired'
    });
  }

  // Log successful nonce validation
  logger.info('Nonce validation successful', { 
    method: req.method, 
    path: req.path 
  });

  next();
}

export default nonceMiddleware;
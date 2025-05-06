import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

// Configuration constants
const NONCE_MAX_AGE = 5 * 60 * 1000; // 5 minutes
const MAX_NONCE_STORE_SIZE = 10000;

// Logging utility
const log = (level: 'info' | 'warn' | 'error', message: string, details?: object) => {
  const logEntry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...details
  };
  console[level](JSON.stringify(logEntry));
};

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
    // Prune old nonces to prevent unbounded growth
    this.pruneExpiredNonces();

    // Prevent store from growing too large
    if (this.nonceStore.size >= MAX_NONCE_STORE_SIZE) {
      log('warn', 'Nonce store reached maximum size', { 
        currentSize: this.nonceStore.size 
      });
      this.clearOldestNonces();
    }

    const nonce = crypto.randomBytes(32).toString('hex');
    const timestamp = Date.now();
    
    this.nonceStore.set(nonce, timestamp);
    
    log('info', 'Nonce generated', { 
      nonceLength: nonce.length 
    });
    
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
      log('warn', 'Nonce validation failed: Nonce not found', { 
        nonceLength: nonce.length 
      });
      return false;
    }

    const currentTime = Date.now();
    const nonceAge = currentTime - timestamp;

    // Check nonce age
    if (nonceAge > NONCE_MAX_AGE) {
      log('warn', 'Nonce validation failed: Nonce expired', { 
        nonceAge,
        maxAge: NONCE_MAX_AGE 
      });
      this.nonceStore.delete(nonce);
      return false;
    }

    // Remove used nonce to prevent replay
    this.nonceStore.delete(nonce);
    
    log('info', 'Nonce validated successfully', { 
      nonceAge 
    });
    
    return true;
  }

  /**
   * Prune expired nonces from the store
   */
  private pruneExpiredNonces(): void {
    const currentTime = Date.now();
    for (const [nonce, timestamp] of this.nonceStore.entries()) {
      if (currentTime - timestamp > NONCE_MAX_AGE) {
        this.nonceStore.delete(nonce);
      }
    }
  }

  /**
   * Clear oldest nonces when store reaches maximum size
   */
  private clearOldestNonces(): void {
    const sortedNonces = Array.from(this.nonceStore.entries())
      .sort((a, b) => a[1] - b[1]);
    
    const excessNonces = sortedNonces.slice(0, 
      Math.max(0, this.nonceStore.size - MAX_NONCE_STORE_SIZE / 2)
    );

    for (const [nonce] of excessNonces) {
      this.nonceStore.delete(nonce);
    }
  }
}

// Singleton instance
const nonceManager = new NonceManager();

/**
 * Nonce middleware for request authentication
 * @param {Request} req - Express request object
 * @param {Response} res - Express response object
 * @param {NextFunction} next - Express next middleware function
 */
export function nonceMiddleware(req: Request, res: Response, next: NextFunction) {
  log('info', 'Nonce middleware processing', { 
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
    log('error', 'Nonce validation failed: Missing nonce', { 
      method: req.method, 
      path: req.path 
    });
    return res.status(400).json({ 
      error: 'Nonce is required',
      message: 'A valid nonce must be provided for this request'
    });
  }

  // Validate nonce
  if (!nonceManager.validateNonce(nonce)) {
    log('error', 'Nonce validation failed: Invalid or expired', { 
      method: req.method, 
      path: req.path 
    });
    return res.status(400).json({ 
      error: 'Invalid or expired nonce',
      message: 'The provided nonce is invalid or has expired'
    });
  }

  log('info', 'Nonce validated successfully', { 
    method: req.method, 
    path: req.path 
  });

  next();
}

export default nonceMiddleware;
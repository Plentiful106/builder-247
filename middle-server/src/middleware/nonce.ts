import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import Redis from 'ioredis';

/**
 * Configuration interface for Nonce Middleware
 */
export interface NonceConfig {
  /**
   * Redis connection options for distributed nonce tracking
   */
  redisConfig?: {
    host?: string;
    port?: number;
    password?: string;
  };

  /**
   * Nonce configuration options
   */
  nonce?: {
    /**
     * Nonce expiration time in seconds (default: 300s / 5 minutes)
     */
    ttl?: number;

    /**
     * Nonce length in bytes (default: 32 bytes)
     */
    length?: number;
  };
}

/**
 * NonceMiddleware provides protection against replay attacks by ensuring 
 * each request has a unique nonce and is used only once.
 */
export class NonceMiddleware {
  // Redis client for distributed nonce tracking
  private static redisClient: Redis | null = null;

  // Default configuration
  private static defaultConfig: NonceConfig = {
    redisConfig: {
      host: 'localhost',
      port: 6379
    },
    nonce: {
      ttl: 300,  // 5 minutes
      length: 32 // 64-character hex string
    }
  };

  /**
   * Initialize the middleware with optional configuration
   * @param config Configuration for nonce middleware
   */
  static initialize(config?: NonceConfig): void {
    const mergedConfig = { 
      ...this.defaultConfig, 
      ...config 
    };

    // Initialize Redis client if Redis config is provided
    if (mergedConfig.redisConfig) {
      this.redisClient = new Redis({
        host: mergedConfig.redisConfig.host,
        port: mergedConfig.redisConfig.port,
        password: mergedConfig.redisConfig.password
      });
    }
  }

  /**
   * Generate a cryptographically secure random nonce
   * @param length Optional nonce length (default from config)
   * @returns {string} A unique nonce value
   */
  static generateNonce(length?: number): string {
    const nonceLength = length || this.defaultConfig.nonce?.length || 32;
    return crypto.randomBytes(nonceLength).toString('hex');
  }

  /**
   * Inject nonce into request headers for API clients
   * @param req Express request object
   * @returns {string} Generated nonce
   */
  static injectNonce(req: Request): string {
    const nonce = this.generateNonce();
    
    // Inject nonce into headers
    req.headers['x-nonce'] = nonce;
    
    // Also set in body if it exists
    if (req.body) {
      req.body.nonce = nonce;
    }

    return nonce;
  }

  /**
   * Validate and track nonce to prevent replay attacks
   * @param req Express request object 
   * @param res Express response object
   * @param next Express next middleware function
   */
  static async validate(req: Request, res: Response, next: NextFunction): Promise<void> {
    // Extract nonce from request headers or body
    const nonce = req.headers['x-nonce'] as string || req.body?.nonce;

    // Check if nonce is present
    if (!nonce) {
      res.status(400).json({ 
        error: 'Nonce Required',
        message: 'A unique nonce must be provided with each request' 
      });
      return;
    }

    // Check nonce length and format
    if (typeof nonce !== 'string' || nonce.length !== 64) {
      res.status(400).json({ 
        error: 'Invalid Nonce',
        message: 'Nonce must be a 64-character hexadecimal string' 
      });
      return;
    }

    try {
      // Use Redis for distributed nonce tracking if available
      if (this.redisClient) {
        const exists = await this.redisClient.get(`nonce:${nonce}`);
        if (exists) {
          res.status(409).json({ 
            error: 'Nonce Already Used',
            message: 'This nonce has already been consumed' 
          });
          return;
        }

        // Store nonce with expiration
        await this.redisClient.set(
          `nonce:${nonce}`, 
          'used', 
          'EX', 
          this.defaultConfig.nonce?.ttl || 300
        );
      } else {
        // Fallback to in-memory tracking if no Redis
        if (this.usedNonces.has(nonce)) {
          res.status(409).json({ 
            error: 'Nonce Already Used',
            message: 'This nonce has already been consumed' 
          });
          return;
        }
        this.usedNonces.add(nonce);
      }

      next();
    } catch (error) {
      // Graceful error handling
      res.status(500).json({
        error: 'Nonce Validation Failed',
        message: 'Unable to validate nonce due to a server error'
      });
    }
  }

  // In-memory fallback for nonce tracking
  private static usedNonces: Set<string> = new Set();

  /**
   * Clear all used nonces (useful for testing)
   */
  static clearNonces(): void {
    this.usedNonces.clear();
    if (this.redisClient) {
      this.redisClient.flushdb();
    }
  }
}
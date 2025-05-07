import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

/**
 * Configuration interface for Nonce Middleware
 */
export interface NonceConfig {
  /**
   * Length of the nonce in bytes
   * @default 32
   */
  nonceLength?: number;

  /**
   * Time-to-live for nonce in seconds
   * @default 300 (5 minutes)
   */
  nonceTTL?: number;

  /**
   * Custom storage mechanism for nonces
   * @default InMemoryNonceStore
   */
  nonceStore?: NonceStore;
}

/**
 * Interface for Nonce Storage Strategies
 */
export interface NonceStore {
  /**
   * Check if a nonce has been used
   * @param nonce Nonce to check
   * @returns Promise<boolean> indicating if nonce is used
   */
  isNonceUsed(nonce: string): Promise<boolean>;

  /**
   * Mark a nonce as used
   * @param nonce Nonce to mark
   * @returns Promise<void>
   */
  markNonceUsed(nonce: string): Promise<void>;

  /**
   * Clear all used nonces
   * @returns Promise<void>
   */
  clearNonces(): Promise<void>;
}

/**
 * Default In-Memory Nonce Store
 */
class InMemoryNonceStore implements NonceStore {
  private usedNonces = new Set<string>();

  async isNonceUsed(nonce: string): Promise<boolean> {
    return this.usedNonces.has(nonce);
  }

  async markNonceUsed(nonce: string): Promise<void> {
    this.usedNonces.add(nonce);
  }

  async clearNonces(): Promise<void> {
    this.usedNonces.clear();
  }
}

/**
 * Nonce Middleware for API Request Protection
 */
export class NonceMiddleware {
  private static config: NonceConfig = {
    nonceLength: 32,
    nonceTTL: 300,
    nonceStore: new InMemoryNonceStore()
  };

  /**
   * Initialize middleware with custom configuration
   * @param config Configuration options
   */
  static initialize(config?: Partial<NonceConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Generate a cryptographically secure nonce
   * @returns Hexadecimal nonce string
   */
  static generateNonce(): string {
    const { nonceLength = 32 } = this.config;
    return crypto.randomBytes(nonceLength).toString('hex');
  }

  /**
   * Inject nonce into request for different client libraries
   * @param req Express request object
   * @returns Generated nonce
   */
  static injectNonce(req: Request): string {
    const nonce = this.generateNonce();

    // Inject nonce into headers
    req.headers['x-nonce'] = nonce;

    // Inject nonce into body if exists
    if (req.body) {
      req.body.nonce = nonce;
    }

    return nonce;
  }

  /**
   * Middleware to validate nonce and prevent replay attacks
   * @param req Express request object
   * @param res Express response object
   * @param next Express next function
   */
  static async validate(
    req: Request, 
    res: Response, 
    next: NextFunction
  ): Promise<void> {
    const { nonceStore } = this.config;

    // Extract nonce from headers or body
    const nonce = 
      req.headers['x-nonce'] as string || 
      req.body?.nonce;

    // Validate nonce presence
    if (!nonce) {
      res.status(400).json({
        error: 'Nonce Required',
        message: 'A unique nonce must be provided with each request'
      });
      return;
    }

    // Validate nonce format (64-char hex)
    if (typeof nonce !== 'string' || nonce.length !== 64) {
      res.status(400).json({
        error: 'Invalid Nonce',
        message: 'Nonce must be a 64-character hexadecimal string'
      });
      return;
    }

    try {
      // Check if nonce has been used
      const isUsed = await nonceStore.isNonceUsed(nonce);
      
      if (isUsed) {
        res.status(409).json({
          error: 'Nonce Already Used',
          message: 'This nonce has already been consumed'
        });
        return;
      }

      // Mark nonce as used
      await nonceStore.markNonceUsed(nonce);

      next();
    } catch (error) {
      // Graceful error handling
      res.status(500).json({
        error: 'Nonce Validation Failed',
        message: 'Unable to validate nonce due to a server error'
      });
    }
  }

  /**
   * Clear all used nonces (useful for testing)
   */
  static async clearNonces(): Promise<void> {
    await this.config.nonceStore.clearNonces();
  }
}
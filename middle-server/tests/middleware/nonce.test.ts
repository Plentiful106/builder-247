import { generateNonce, validateNonce, nonceMiddleware } from '../../src/middleware/nonce';
import { Request, Response, NextFunction } from 'express';

describe('Nonce Middleware', () => {
  describe('generateNonce', () => {
    it('should generate a unique nonce', () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      
      expect(nonce1).toBeTruthy();
      expect(nonce2).toBeTruthy();
      expect(nonce1).not.toEqual(nonce2);
    });

    it('should generate a hex string of 64 characters', () => {
      const nonce = generateNonce();
      expect(nonce).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('validateNonce', () => {
    it('should return false for an unused nonce', () => {
      const nonce = generateNonce();
      expect(validateNonce(nonce)).toBeFalsy();
    });

    it('should return true for a valid nonce within time limit', () => {
      const mockNonce = generateNonce();
      
      // Manually add nonce to cache
      (validateNonce as any).nonceCache = { [mockNonce]: Date.now() };
      
      expect(validateNonce(mockNonce)).toBeTruthy();
      
      // Nonce should be invalidated after first use
      expect(validateNonce(mockNonce)).toBeFalsy();
    });

    it('should return false for an expired nonce', () => {
      jest.useFakeTimers();
      const mockNonce = generateNonce();
      
      // Manually add nonce to cache with an old timestamp
      (validateNonce as any).nonceCache = { 
        [mockNonce]: Date.now() - (6 * 60 * 1000) // 6 minutes ago
      };
      
      expect(validateNonce(mockNonce)).toBeFalsy();
      
      jest.useRealTimers();
    });
  });

  describe('nonceMiddleware', () => {
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;
    let mockNext: NextFunction;

    beforeEach(() => {
      mockReq = {
        method: 'POST',
        headers: {}
      };
      mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
      mockNext = jest.fn();
    });

    it('should generate nonce for GET requests', () => {
      mockReq.method = 'GET';
      
      nonceMiddleware(mockReq as Request, mockRes as Response, mockNext);
      
      expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
        nonce: expect.any(String)
      }));
    });

    it('should reject requests without nonce', () => {
      nonceMiddleware(mockReq as Request, mockRes as Response, mockNext);
      
      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Nonce is required' });
    });

    it('should call next for valid nonce', () => {
      const validNonce = generateNonce();
      mockReq.headers = { 'x-nonce': validNonce };
      
      // Simulate nonce cache
      (validateNonce as any).nonceCache = { [validNonce]: Date.now() };
      
      nonceMiddleware(mockReq as Request, mockRes as Response, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    it('should reject invalid nonce', () => {
      mockReq.headers = { 'x-nonce': 'invalid_nonce' };
      
      nonceMiddleware(mockReq as Request, mockRes as Response, mockNext);
      
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Invalid or expired nonce' });
    });
  });
});
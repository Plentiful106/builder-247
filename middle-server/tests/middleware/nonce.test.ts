import { nonceMiddleware } from '../../src/middleware/nonce';
import { Request, Response, NextFunction } from 'express';
import winston from 'winston';

// Mock winston logger to prevent actual logging during tests
jest.mock('winston', () => ({
  createLogger: jest.fn(() => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  }))
}));

describe('Nonce Middleware', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockReq = {
      method: 'POST',
      path: '/test-path',
      headers: {}
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    mockNext = jest.fn();
  });

  describe('Nonce Generation', () => {
    it('should generate a nonce for GET requests', () => {
      mockReq.method = 'GET';
      
      nonceMiddleware(mockReq as Request, mockRes as Response, mockNext);
      
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
        nonce: expect.any(String)
      }));
    });
  });

  describe('Nonce Validation', () => {
    it('should reject requests without nonce', () => {
      nonceMiddleware(mockReq as Request, mockRes as Response, mockNext);
      
      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
        error: 'Nonce is required'
      }));
    });

    it('should validate nonce successfully', () => {
      // First, generate a nonce
      const generateNonceReq = { method: 'GET' } as Request;
      const generateNonceRes = { 
        status: jest.fn().mockReturnThis(), 
        json: jest.fn() 
      } as unknown as Response;
      nonceMiddleware(generateNonceReq, generateNonceRes, mockNext);
      
      // Extract the generated nonce
      const nonce = (generateNonceRes.json as jest.Mock).mock.calls[0][0].nonce;

      // Now validate the nonce
      mockReq.headers = { 'x-nonce': nonce };
      nonceMiddleware(mockReq as Request, mockRes as Response, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
    });

    it('should reject reused nonce', () => {
      // First, generate a nonce
      const generateNonceReq = { method: 'GET' } as Request;
      const generateNonceRes = { 
        status: jest.fn().mockReturnThis(), 
        json: jest.fn() 
      } as unknown as Response;
      nonceMiddleware(generateNonceReq, generateNonceRes, mockNext);
      
      // Extract the generated nonce
      const nonce = (generateNonceRes.json as jest.Mock).mock.calls[0][0].nonce;

      // First validation should succeed
      mockReq.headers = { 'x-nonce': nonce };
      nonceMiddleware(mockReq as Request, mockRes as Response, mockNext);
      
      // Second validation should fail
      mockReq.headers = { 'x-nonce': nonce };
      nonceMiddleware(mockReq as Request, mockRes as Response, mockNext);
      
      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
        error: 'Invalid or expired nonce'
      }));
    });
  });

  describe('Performance and Limits', () => {
    it('should handle maximum nonce store size', () => {
      // Simulate generating many nonces to test store size management
      const nonces: string[] = [];
      
      for (let i = 0; i < 15000; i++) {
        const generateNonceReq = { method: 'GET' } as Request;
        const generateNonceRes = { 
          status: jest.fn().mockReturnThis(), 
          json: jest.fn() 
        } as unknown as Response;
        
        nonceMiddleware(generateNonceReq, generateNonceRes, mockNext);
        const nonce = (generateNonceRes.json as jest.Mock).mock.calls[0][0].nonce;
        nonces.push(nonce);
      }
      
      // Expect no errors or exceptions
      expect(nonces.length).toBeGreaterThan(10000);
    });
  });
});
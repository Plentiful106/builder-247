import { NonceMiddleware } from '../../src/middleware/nonce';
import { Request, Response, NextFunction } from 'express';

describe('NonceMiddleware', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: jest.MockedFunction<NextFunction>;

  beforeEach(() => {
    // Clear nonces before each test
    NonceMiddleware.clearNonces();

    mockRequest = {};
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    mockNext = jest.fn();
  });

  describe('generateNonce', () => {
    it('should generate a unique 64-character hex nonce', () => {
      const nonce1 = NonceMiddleware.generateNonce();
      const nonce2 = NonceMiddleware.generateNonce();

      expect(nonce1).toHaveLength(64);
      expect(nonce2).toHaveLength(64);
      expect(nonce1).toMatch(/^[0-9a-f]+$/);
      expect(nonce1).not.toEqual(nonce2);
    });
  });

  describe('validate', () => {
    it('should reject request without nonce', () => {
      mockRequest.headers = {};

      NonceMiddleware.validate(
        mockRequest as Request, 
        mockResponse as Response, 
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith(expect.objectContaining({
        error: 'Nonce is required'
      }));
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject invalid nonce format', () => {
      mockRequest.headers = { 'x-nonce': 'short' };

      NonceMiddleware.validate(
        mockRequest as Request, 
        mockResponse as Response, 
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith(expect.objectContaining({
        error: 'Invalid nonce'
      }));
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject reused nonce', () => {
      const validNonce = NonceMiddleware.generateNonce();
      mockRequest.headers = { 'x-nonce': validNonce };

      // First request should pass
      NonceMiddleware.validate(
        mockRequest as Request, 
        mockResponse as Response, 
        mockNext
      );
      expect(mockNext).toHaveBeenCalled();

      // Reset mocks
      mockNext.mockClear();
      mockResponse.status = jest.fn().mockReturnThis();
      mockResponse.json = jest.fn();

      // Second request with same nonce should fail
      NonceMiddleware.validate(
        mockRequest as Request, 
        mockResponse as Response, 
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(409);
      expect(mockResponse.json).toHaveBeenCalledWith(expect.objectContaining({
        error: 'Nonce already used'
      }));
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should accept request with valid unique nonce', () => {
      const validNonce = NonceMiddleware.generateNonce();
      mockRequest.headers = { 'x-nonce': validNonce };

      NonceMiddleware.validate(
        mockRequest as Request, 
        mockResponse as Response, 
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it('should accept nonce from request body', () => {
      const validNonce = NonceMiddleware.generateNonce();
      mockRequest.body = { nonce: validNonce };

      NonceMiddleware.validate(
        mockRequest as Request, 
        mockResponse as Response, 
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });
  });
});
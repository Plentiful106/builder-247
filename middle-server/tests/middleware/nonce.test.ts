import { NonceMiddleware, NonceConfig } from '../../src/middleware/nonce';
import { Request, Response, NextFunction } from 'express';
import Redis from 'ioredis';

// Mock Redis to avoid actual connections during testing
jest.mock('ioredis');

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

    // Reset middleware configuration
    NonceMiddleware.initialize();
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

    it('should support custom nonce length', () => {
      const customNonce = NonceMiddleware.generateNonce(16);
      expect(customNonce).toHaveLength(32);
    });
  });

  describe('injectNonce', () => {
    it('should inject nonce into request headers', () => {
      const req = {} as Request;
      const nonce = NonceMiddleware.injectNonce(req);

      expect(req.headers['x-nonce']).toBe(nonce);
    });

    it('should inject nonce into request body if it exists', () => {
      const req = { body: {} } as Request;
      const nonce = NonceMiddleware.injectNonce(req);

      expect(req.body.nonce).toBe(nonce);
      expect(req.headers['x-nonce']).toBe(nonce);
    });
  });

  describe('validate', () => {
    it('should reject request without nonce', async () => {
      mockRequest.headers = {};

      await NonceMiddleware.validate(
        mockRequest as Request, 
        mockResponse as Response, 
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith(expect.objectContaining({
        error: 'Nonce Required'
      }));
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject invalid nonce format', async () => {
      mockRequest.headers = { 'x-nonce': 'short' };

      await NonceMiddleware.validate(
        mockRequest as Request, 
        mockResponse as Response, 
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith(expect.objectContaining({
        error: 'Invalid Nonce'
      }));
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject reused nonce', async () => {
      const validNonce = NonceMiddleware.generateNonce();
      mockRequest.headers = { 'x-nonce': validNonce };

      // First request should pass
      await NonceMiddleware.validate(
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
      await NonceMiddleware.validate(
        mockRequest as Request, 
        mockResponse as Response, 
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(409);
      expect(mockResponse.json).toHaveBeenCalledWith(expect.objectContaining({
        error: 'Nonce Already Used'
      }));
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should support nonce from request body', async () => {
      const validNonce = NonceMiddleware.generateNonce();
      mockRequest.body = { nonce: validNonce };

      await NonceMiddleware.validate(
        mockRequest as Request, 
        mockResponse as Response, 
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it('should support configuration with custom Redis settings', async () => {
      const mockRedisConfig: NonceConfig = {
        redisConfig: {
          host: 'test-redis',
          port: 6379
        }
      };

      // Initialize with custom config
      NonceMiddleware.initialize(mockRedisConfig);

      // Verify Redis was initialized with correct config
      expect(Redis).toHaveBeenCalledWith({
        host: 'test-redis',
        port: 6379,
        password: undefined
      });
    });
  });
});
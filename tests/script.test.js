import { jest } from '@jest/globals';

// Mock the @sgnl-ai/secevent module
jest.unstable_mockModule('@sgnl-ai/secevent', () => {
  const mockBuilder = {
    withIssuer: jest.fn().mockReturnThis(),
    withAudience: jest.fn().mockReturnThis(),
    withIat: jest.fn().mockReturnThis(),
    withClaim: jest.fn().mockReturnThis(),
    withEvent: jest.fn().mockReturnThis(),
    sign: jest.fn().mockResolvedValue({ jwt: 'mock.jwt.token' })
  };
  return {
    createBuilder: jest.fn(() => mockBuilder)
  };
});

// Mock crypto module
jest.unstable_mockModule('crypto', () => ({
  createPrivateKey: jest.fn(() => 'mock-private-key')
}));

// Import after mocking
const { createBuilder } = await import('@sgnl-ai/secevent');
const { createPrivateKey } = await import('crypto');
const script = (await import('../src/script.mjs')).default;

// Mock fetch globally
global.fetch = jest.fn();

describe('CAEP Session Revoked Transmitter', () => {
  let mockBuilder;
  const mockContext = {
    secrets: {
      SSF_KEY: '-----BEGIN RSA PRIVATE KEY-----\nMOCK_KEY\n-----END RSA PRIVATE KEY-----',
      SSF_KEY_ID: 'test-key-id',
      AUTH_TOKEN: 'Bearer test-token'
    }
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockBuilder = createBuilder();
    global.fetch.mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      text: jest.fn().mockResolvedValue('{"success":true}')
    });
  });

  describe('invoke', () => {
    const validParams = {
      audience: 'https://example.com',
      subject: '{"format":"email","email":"user@example.com"}',
      address: 'https://receiver.example.com/events'
    };

    test('should successfully transmit a session revoked event', async () => {
      const result = await script.invoke(validParams, mockContext);

      expect(result).toEqual({
        status: 'success',
        statusCode: 200,
        body: '{"success":true}',
        retryable: false
      });

      expect(createBuilder).toHaveBeenCalled();
      expect(mockBuilder.withIssuer).toHaveBeenCalledWith('https://sgnl.ai/');
      expect(mockBuilder.withAudience).toHaveBeenCalledWith('https://example.com');
      expect(mockBuilder.withClaim).toHaveBeenCalledWith('sub_id', {
        format: 'email',
        email: 'user@example.com'
      });
      expect(mockBuilder.withEvent).toHaveBeenCalledWith(
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        expect.objectContaining({
          event_timestamp: expect.any(Number)
        })
      );
    });

    test('should include optional event claims when provided', async () => {
      const params = {
        ...validParams,
        initiatingEntity: 'admin',
        reasonAdmin: 'Security policy violation',
        reasonUser: 'Your session has been terminated for security reasons',
        eventTimestamp: 1234567890
      };

      await script.invoke(params, mockContext);

      expect(mockBuilder.withEvent).toHaveBeenCalledWith(
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        expect.objectContaining({
          event_timestamp: 1234567890,
          initiating_entity: 'admin',
          reason_admin: 'Security policy violation',
          reason_user: 'Your session has been terminated for security reasons'
        })
      );
    });

    test('should use custom issuer and signing method when provided', async () => {
      const params = {
        ...validParams,
        issuer: 'https://custom.issuer.com',
        signingMethod: 'RS512'
      };

      await script.invoke(params, mockContext);

      expect(mockBuilder.withIssuer).toHaveBeenCalledWith('https://custom.issuer.com');
      expect(mockBuilder.sign).toHaveBeenCalledWith({
        key: 'mock-private-key',
        alg: 'RS512',
        kid: 'test-key-id'
      });
    });

    test('should append address suffix when provided', async () => {
      const params = {
        ...validParams,
        addressSuffix: '/v1/events'
      };

      await script.invoke(params, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        'https://receiver.example.com/events/v1/events',
        expect.any(Object)
      );
    });

    test('should include auth token in request headers', async () => {
      await script.invoke(validParams, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token'
          })
        })
      );
    });

    test('should handle auth token without Bearer prefix', async () => {
      const context = {
        secrets: {
          ...mockContext.secrets,
          AUTH_TOKEN: 'test-token-no-prefix'
        }
      };

      await script.invoke(validParams, context);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token-no-prefix'
          })
        })
      );
    });

    test('should use custom user agent when provided', async () => {
      const params = {
        ...validParams,
        userAgent: 'CustomAgent/1.0'
      };

      await script.invoke(params, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'User-Agent': 'CustomAgent/1.0'
          })
        })
      );
    });

    test('should throw error for missing audience', async () => {
      const params = { ...validParams };
      delete params.audience;

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('audience is required');
    });

    test('should throw error for missing subject', async () => {
      const params = { ...validParams };
      delete params.subject;

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('subject is required');
    });

    test('should throw error for missing address', async () => {
      const params = { ...validParams };
      delete params.address;

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('address is required');
    });

    test('should throw error for invalid subject JSON', async () => {
      const params = {
        ...validParams,
        subject: 'invalid json'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('Invalid subject JSON');
    });

    test('should throw error for missing SSF_KEY secret', async () => {
      const context = {
        secrets: {
          SSF_KEY_ID: 'test-key-id'
        }
      };

      await expect(script.invoke(validParams, context))
        .rejects.toThrow('SSF_KEY secret is required');
    });

    test('should throw error for missing SSF_KEY_ID secret', async () => {
      const context = {
        secrets: {
          SSF_KEY: 'mock-key'
        }
      };

      await expect(script.invoke(validParams, context))
        .rejects.toThrow('SSF_KEY_ID secret is required');
    });

    test('should handle non-retryable HTTP errors', async () => {
      global.fetch.mockResolvedValue({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: jest.fn().mockResolvedValue('{"error":"Invalid request"}')
      });

      const result = await script.invoke(validParams, mockContext);

      expect(result).toEqual({
        status: 'failed',
        statusCode: 400,
        body: '{"error":"Invalid request"}',
        retryable: false
      });
    });

    test('should throw error for retryable HTTP errors', async () => {
      global.fetch.mockResolvedValue({
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
        text: jest.fn().mockResolvedValue('Rate limited')
      });

      await expect(script.invoke(validParams, mockContext))
        .rejects.toThrow('SET transmission failed: 429 Too Many Requests');
    });

    test('should throw error for 502 Bad Gateway', async () => {
      global.fetch.mockResolvedValue({
        ok: false,
        status: 502,
        statusText: 'Bad Gateway',
        text: jest.fn().mockResolvedValue('')
      });

      await expect(script.invoke(validParams, mockContext))
        .rejects.toThrow('SET transmission failed: 502 Bad Gateway');
    });

    test('should throw error for 503 Service Unavailable', async () => {
      global.fetch.mockResolvedValue({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
        text: jest.fn().mockResolvedValue('')
      });

      await expect(script.invoke(validParams, mockContext))
        .rejects.toThrow('SET transmission failed: 503 Service Unavailable');
    });

    test('should throw error for 504 Gateway Timeout', async () => {
      global.fetch.mockResolvedValue({
        ok: false,
        status: 504,
        statusText: 'Gateway Timeout',
        text: jest.fn().mockResolvedValue('')
      });

      await expect(script.invoke(validParams, mockContext))
        .rejects.toThrow('SET transmission failed: 504 Gateway Timeout');
    });

    test('should properly format URL with trailing slash in address', async () => {
      const params = {
        ...validParams,
        address: 'https://receiver.example.com/',
        addressSuffix: '/events'
      };

      await script.invoke(params, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        'https://receiver.example.com/events',
        expect.any(Object)
      );
    });

    test('should properly format URL without leading slash in suffix', async () => {
      const params = {
        ...validParams,
        address: 'https://receiver.example.com',
        addressSuffix: 'events'
      };

      await script.invoke(params, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        'https://receiver.example.com/events',
        expect.any(Object)
      );
    });

    test('should send correct content type header', async () => {
      await script.invoke(validParams, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/secevent+jwt',
            'Accept': 'application/json'
          }),
          body: 'mock.jwt.token'
        })
      );
    });

    test('should create private key from PEM string', async () => {
      await script.invoke(validParams, mockContext);

      expect(createPrivateKey).toHaveBeenCalledWith(
        '-----BEGIN RSA PRIVATE KEY-----\nMOCK_KEY\n-----END RSA PRIVATE KEY-----'
      );
    });
  });

  describe('error handler', () => {
    test('should request retry for 429 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 429 Too Many Requests')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should request retry for 502 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 502 Bad Gateway')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should request retry for 503 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 503 Service Unavailable')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should request retry for 504 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 504 Gateway Timeout')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should re-throw non-retryable errors', async () => {
      const params = {
        error: new Error('Authentication failed: 401 Unauthorized')
      };

      await expect(script.error(params, {}))
        .rejects.toThrow('Authentication failed: 401 Unauthorized');
    });

    test('should re-throw generic errors', async () => {
      const params = {
        error: new Error('Unknown error occurred')
      };

      await expect(script.error(params, {}))
        .rejects.toThrow('Unknown error occurred');
    });
  });

  describe('halt handler', () => {
    test('should return halted status', async () => {
      const result = await script.halt({}, {});

      expect(result).toEqual({ status: 'halted' });
    });
  });
});
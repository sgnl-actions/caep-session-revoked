import { jest } from '@jest/globals';
import { SGNL_USER_AGENT } from '@sgnl-actions/utils';

// Mock @sgnl-ai/set-transmitter module
jest.unstable_mockModule('@sgnl-ai/set-transmitter', () => ({
  transmitSET: jest.fn().mockResolvedValue({
    status: 'success',
    statusCode: 200,
    body: '{"success":true}',
    retryable: false
  })
}));

// Mock @sgnl-actions/utils module
jest.unstable_mockModule('@sgnl-actions/utils', () => ({
  signSET: jest.fn().mockResolvedValue('mock.jwt.token'),
  getBaseURL: jest.fn((params, context) => params.address || context.environment?.ADDRESS),
  getAuthorizationHeader: jest.fn().mockResolvedValue('Bearer test-token'),
  SGNL_USER_AGENT: 'SGNL-CAEP-Hub/2.0'
}));

// Import after mocking
const { transmitSET } = await import('@sgnl-ai/set-transmitter');
const { signSET, getBaseURL, getAuthorizationHeader } = await import('@sgnl-actions/utils');
const script = (await import('../src/script.mjs')).default;

describe('CAEP Session Revoked Transmitter', () => {
  const mockContext = {
    environment: {
      ADDRESS: 'https://receiver.example.com/events'
    },
    secrets: {
      BEARER_AUTH_TOKEN: 'Bearer test-token'
    }
  };

  beforeEach(() => {
    jest.clearAllMocks();
    signSET.mockClear();
    signSET.mockResolvedValue('mock.jwt.token');
    getBaseURL.mockClear();
    getBaseURL.mockImplementation((params, context) => params.address || context.environment?.ADDRESS);
    getAuthorizationHeader.mockClear();
    getAuthorizationHeader.mockResolvedValue('Bearer test-token');
    transmitSET.mockResolvedValue({
      status: 'success',
      statusCode: 200,
      body: '{"success":true}',
      retryable: false
    });
  });

  describe('invoke', () => {
    const validParams = {
      audience: 'https://example.com',
      subject: '{"format":"email","email":"user@example.com"}'
    };

    test('should successfully transmit a session revoked event', async () => {
      const result = await script.invoke(validParams, mockContext);

      expect(result).toEqual({
        status: 'success',
        statusCode: 200,
        body: '{"success":true}',
        retryable: false
      });

      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        {
          aud: 'https://example.com',
          sub_id: {
            format: 'email',
            email: 'user@example.com'
          },
          events: {
            'https://schemas.openid.net/secevent/caep/event-type/session-revoked': expect.objectContaining({
              event_timestamp: expect.any(Number)
            })
          }
        }
      );
    });

    test('should include optional event claims when provided', async () => {
      const params = {
        ...validParams,
        initiating_entity: 'admin',
        reason_admin: 'Security policy violation',
        reason_user: 'Your session has been terminated for security reasons'
      };

      await script.invoke(params, mockContext);

      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          events: {
            'https://schemas.openid.net/secevent/caep/event-type/session-revoked': expect.objectContaining({
              event_timestamp: expect.any(Number),
              initiating_entity: 'admin',
              reason_admin: 'Security policy violation',
              reason_user: 'Your session has been terminated for security reasons'
            })
          }
        })
      );
    });

    test('should include auth token in request', async () => {
      await script.invoke(validParams, mockContext);

      expect(getAuthorizationHeader).toHaveBeenCalledWith(mockContext);
      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token',
            'User-Agent': SGNL_USER_AGENT
          })
        })
      );
    });

    test('should handle auth token without Bearer prefix', async () => {
      getAuthorizationHeader.mockResolvedValue('test-token-no-prefix');

      await script.invoke(validParams, mockContext);

      expect(getAuthorizationHeader).toHaveBeenCalledWith(mockContext);
      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'test-token-no-prefix',
            'User-Agent': 'SGNL-CAEP-Hub/2.0'
          })
        })
      );
    });

    test('should throw error for invalid subject JSON', async () => {
      const params = {
        ...validParams,
        subject: 'invalid json'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('Invalid subject JSON');
    });


    test('should handle non-retryable HTTP errors', async () => {
      transmitSET.mockResolvedValue({
        status: 'failed',
        statusCode: 400,
        body: '{"error":"Invalid request"}',
        retryable: false
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
      transmitSET.mockRejectedValue(
        new Error('SET transmission failed: 429 Too Many Requests')
      );

      await expect(script.invoke(validParams, mockContext))
        .rejects.toThrow('SET transmission failed: 429 Too Many Requests');
    });

    test('should throw error for 502 Bad Gateway', async () => {
      transmitSET.mockRejectedValue(
        new Error('SET transmission failed: 502 Bad Gateway')
      );

      await expect(script.invoke(validParams, mockContext))
        .rejects.toThrow('SET transmission failed: 502 Bad Gateway');
    });

    test('should throw error for 503 Service Unavailable', async () => {
      transmitSET.mockRejectedValue(
        new Error('SET transmission failed: 503 Service Unavailable')
      );

      await expect(script.invoke(validParams, mockContext))
        .rejects.toThrow('SET transmission failed: 503 Service Unavailable');
    });

    test('should throw error for 504 Gateway Timeout', async () => {
      transmitSET.mockRejectedValue(
        new Error('SET transmission failed: 504 Gateway Timeout')
      );

      await expect(script.invoke(validParams, mockContext))
        .rejects.toThrow('SET transmission failed: 504 Gateway Timeout');
    });

    test('should transmit JWT to correct URL', async () => {
      await script.invoke(validParams, mockContext);

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.any(Object)
      );
    });

    test('should use address from params when provided', async () => {
      const params = {
        ...validParams,
        address: 'https://custom.example.com/events'
      };

      await script.invoke(params, mockContext);

      expect(getBaseURL).toHaveBeenCalledWith(params, mockContext);
      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://custom.example.com/events',
        expect.any(Object)
      );
    });

    test('should use ADDRESS from environment when params.address not provided', async () => {
      await script.invoke(validParams, mockContext);

      expect(getBaseURL).toHaveBeenCalledWith(validParams, mockContext);
      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.any(Object)
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
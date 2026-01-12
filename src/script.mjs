import { getAuthorizationHeader, getBaseURL, resolveJSONPathTemplates } from '@sgnl-actions/utils';
import { transmitSET } from '@sgnl-ai/set-transmitter';

// Event type constant
const SESSION_REVOKED_EVENT = 'https://schemas.openid.net/secevent/caep/event-type/session-revoked';

/**
 * Sign a Security Event Token (SET) with server-side keys
 * @param {Object} context - Context object containing crypto operations
 * @param {Object} payload - SET payload to sign
 * @returns {Promise<string>} Signed JWT
 */
async function signSET(context, payload) {
  const CRYPTO_SIGN_JWT_ENDPOINT = "crypto.sgnl.svc.cluster.local:80";

  let signEndpoint = `${CRYPTO_SIGN_JWT_ENDPOINT}?typ=secevent%2Bjwt`;

  try {
    let normalizedPayload;
    if (payload === undefined || payload === null) {
      normalizedPayload = {};
    } else if (typeof payload === 'object' && !Array.isArray(payload)) {
      normalizedPayload = payload;
    } else {
      throw new TypeError('payload must be an object when signing JWT');
    }

    console.log("Calling Sign Endpoint", JSON.stringify(normalizedPayload, null, 2));

    const response = await fetch(signEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ payload: normalizedPayload || {} }),
    });

    if (!response.ok) {
      // Consume response body to avoid memory leaks
      await response.text();

      if (response.status >= 400 && response.status < 500) {
        throw new Error('Failed to sign JWT: invalid request');
      }

      // Other non-OK status codes
      throw new Error('Failed to sign JWT: service unavailable');
    }

    const result = await response.json();
    return result.jwt;
  } catch (error) {
    if (error instanceof TypeError ||
        error.message.includes('Failed to sign JWT') ||
        error.message.includes('Invalid typ parameter')) {
      throw error;
    }
    // Network errors and other unexpected errors - don't expose internal details
    throw new Error('Failed to sign JWT: service unavailable');
  }
}


/**
 * Parse subject JSON string
 */
function parseSubject(subjectStr) {
  try {
    return JSON.parse(subjectStr);
  } catch (error) {
    throw new Error(`Invalid subject JSON: ${error.message}`);
  }
}

export default {
  /**
   * Main execution handler - transmits a CAEP Session Revoked event as a Security Event Token
   *
   * @param {Object} params - Job input parameters
   * @param {string} params.subject - Subject identifier JSON (e.g., {"format":"email","email":"user@example.com"})
   * @param {string} params.audience - Intended recipient of the SET (e.g., https://customer.okta.com/)
   * @param {string} params.address - Optional destination URL override (defaults to ADDRESS environment variable)
   * @param {string} params.initiating_entity - What initiated the session revocation (optional)
   * @param {string} params.reason_admin - Administrative reason for revocation (optional)
   * @param {string} params.reason_user - User-facing reason for revocation (optional)
   *
   * @param {Object} context - Execution context with secrets and environment
   * @param {Object} context.environment - Environment configuration
   * @param {string} context.environment.ADDRESS - Default destination URL for the SET transmission
   *
   * The configured auth type will determine which of the following environment variables and secrets are available
   * @param {string} context.secrets.BEARER_AUTH_TOKEN
   *
   * @param {string} context.secrets.BASIC_USERNAME
   * @param {string} context.secrets.BASIC_PASSWORD
   *
   * @param {string} context.secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_AUDIENCE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_SCOPE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL
   *
   * @param {string} context.secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN
   *
   * @param {Object} context.crypto - Cryptographic operations API
   * @param {Function} context.crypto.signJWT - Function to sign JWTs with server-side keys
   *
   * @returns {Object} Transmission result with status, statusCode, body, and retryable flag
   */
  invoke: async (params, context) => {
    const jobContext = context.data || {};

    // Resolve JSONPath templates in params
    const { result: resolvedParams, errors } = resolveJSONPathTemplates(params, jobContext);
    if (errors.length > 0) {
      console.warn('Template resolution errors:', errors);
    }

    const address = getBaseURL(resolvedParams, context);
    const authHeader = await getAuthorizationHeader(context);

    // Parse parameters
    const subject = parseSubject(resolvedParams.subject);

    // Build event payload
    const eventPayload = {
      event_timestamp: Math.floor(Date.now() / 1000)
    };

    // Add optional event claims
    if (resolvedParams.initiating_entity) {
      eventPayload.initiating_entity = resolvedParams.initiating_entity;
    }
    if (resolvedParams.reason_admin) {
      eventPayload.reason_admin = resolvedParams.reason_admin;
    }
    if (resolvedParams.reason_user) {
      eventPayload.reason_user = resolvedParams.reason_user;
    }

    // Build the SET payload (reserved claims will be added during signing)
    const setPayload = {
      aud: resolvedParams.audience,
      sub_id: subject,  // CAEP 3.0 format
      events: {
        [SESSION_REVOKED_EVENT]: eventPayload
      }
    };

    console.log('SET Payload:', JSON.stringify(setPayload, null, 2));

    const jwt = await signSET(context, setPayload);

    console.log('Transmitting SET to:', address);

    // Transmit the SET
    return await transmitSET(jwt, address, {
      headers: {
        'Authorization': authHeader,
        'User-Agent': 'SGNL-CAEP-Hub/2.0'
      }
    });
  },

  /**
   * Error handler for retryable failures
   */
  error: async (params, _context) => {
    const { error } = params;

    // Check if this is a retryable error
    if (error.message?.includes('429') ||
        error.message?.includes('502') ||
        error.message?.includes('503') ||
        error.message?.includes('504')) {
      return { status: 'retry_requested' };
    }

    // Non-retryable error
    throw error;
  },

  /**
   * Cleanup handler
   */
  halt: async (_params, _context) => {
    return { status: 'halted' };
  }
};
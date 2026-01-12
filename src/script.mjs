import { getAuthorizationHeader, getBaseURL, signSET, resolveJSONPathTemplates } from '@sgnl-actions/utils';
import { transmitSET } from '@sgnl-ai/set-transmitter';

// Event type constant
const SESSION_REVOKED_EVENT = 'https://schemas.openid.net/secevent/caep/event-type/session-revoked';


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
import { transmitSET } from '@sgnl-ai/set-transmitter';
import { resolveJSONPathTemplates, signSET } from '@sgnl-actions/utils';

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

/**
 * Build destination URL
 */
function buildUrl(address, suffix) {
  if (!suffix) {
    return address;
  }
  const baseUrl = address.endsWith('/') ? address.slice(0, -1) : address;
  const cleanSuffix = suffix.startsWith('/') ? suffix.slice(1) : suffix;
  return `${baseUrl}/${cleanSuffix}`;
}

export default {
  /**
   * Transmit a CAEP Session Revoked event
   */
  invoke: async (params, context) => {
    const jobContext = context.data || {};

    // Resolve JSONPath templates in params
    const { result: resolvedParams, errors } = resolveJSONPathTemplates(params, jobContext);
    if (errors.length > 0) {
     console.warn('Template resolution errors:', errors);
    }

    // Validate required parameters
    if (!resolvedParams.audience) {
      throw new Error('audience is required');
    }
    if (!resolvedParams.subject) {
      throw new Error('subject is required');
    }
    if (!resolvedParams.address) {
      throw new Error('address is required');
    }

    // Get secrets
    const authToken = context.secrets?.AUTH_TOKEN;

    // Parse parameters
    const subject = parseSubject(resolvedParams.subject);

    // Build event payload
    const eventPayload = {
      event_timestamp: resolvedParams.eventTimestamp || Math.floor(Date.now() / 1000)
    };

    // Add optional event claims
    if (resolvedParams.initiatingEntity) {
      eventPayload.initiating_entity = resolvedParams.initiatingEntity;
    }
    if (resolvedParams.reasonAdmin) {
      eventPayload.reason_admin = resolvedParams.reasonAdmin;
    }
    if (resolvedParams.reasonUser) {
      eventPayload.reason_user = resolvedParams.reasonUser;
    }

    // Build the SET payload 
    const setPayload = {
      aud: resolvedParams.audience,
      sub_id: subject,  // CAEP 3.0 format
      events: {
        [SESSION_REVOKED_EVENT]: eventPayload
      }
    };

    const jwt = await signSET(context, setPayload);

    // Build destination URL
    const url = buildUrl(resolvedParams.address, resolvedParams.addressSuffix);

    // Transmit the SET using the library
    return await transmitSET(jwt, url, {
      authToken,
      headers: {
        'User-Agent': resolvedParams.userAgent || 'SGNL-Action-Framework/1.0'
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
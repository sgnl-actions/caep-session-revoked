# CAEP Session Revoked Event Transmitter

This action transmits CAEP (Continuous Access Evaluation Protocol) Session Revoked events as Security Event Tokens (SET) to specified receivers. It implements the [OpenID CAEP specification](https://openid.net/specs/openid-caep-1_0.html) for session revocation notifications.

## Overview

The CAEP Session Revoked event is used to notify receivers when a user's session has been terminated. This can occur due to:
- Security policy violations
- Administrative actions
- User-initiated logout
- System-detected anomalies

## Prerequisites

- Node.js 22 runtime environment
- RSA private key for JWT signing
- Target receiver endpoint that accepts Security Event Tokens
- Optional: Bearer token for receiver authentication

## Configuration

### Secrets

| Name | Required | Description |
|------|----------|-------------|
| `SSF_KEY` | Yes | RSA private key in PEM format for signing the JWT |
| `SSF_KEY_ID` | Yes | Key identifier to include in the JWT header |
| `AUTH_TOKEN` | No | Bearer token for authenticating with the SET receiver |

### Input Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `audience` | text | Yes | Intended recipient of the SET (e.g., `https://customer.okta.com/`) |
| `subject` | text | Yes | Subject identifier JSON (e.g., `{"format":"email","email":"user@example.com"}`) |
| `address` | text | Yes | Destination URL for the SET transmission |
| `initiatingEntity` | text | No | What initiated the revocation: `policy`, `admin`, `user`, `system` |
| `reasonAdmin` | text | No | Administrative reason for revocation (shown to admins) |
| `reasonUser` | text | No | User-facing reason for revocation (shown to users) |
| `eventTimestamp` | number | No | Unix timestamp when the session was revoked (defaults to now) |
| `addressSuffix` | text | No | Optional suffix to append to the address |
| `issuer` | text | No | JWT issuer identifier (default: `https://sgnl.ai/`) |
| `signingMethod` | text | No | JWT signing algorithm: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512` (default: `RS256`) |
| `userAgent` | text | No | User-Agent header for HTTP requests |

### Outputs

| Name | Type | Description |
|------|------|-------------|
| `status` | text | Operation result: `success` or `failed` |
| `statusCode` | number | HTTP status code from the SET receiver |
| `body` | text | Response body from the SET receiver |
| `retryable` | boolean | Whether the error is retryable |

## Usage Examples

### Basic Session Revocation

```json
{
  "audience": "https://receiver.example.com",
  "subject": "{\"format\":\"email\",\"email\":\"user@example.com\"}",
  "address": "https://receiver.example.com/events"
}
```

### Admin-Initiated Revocation with Reasons

```json
{
  "audience": "https://receiver.example.com",
  "subject": "{\"format\":\"email\",\"email\":\"user@example.com\"}",
  "address": "https://receiver.example.com/events",
  "initiatingEntity": "admin",
  "reasonAdmin": "Account compromised - suspicious login from new location",
  "reasonUser": "Your session has been terminated for security reasons. Please log in again."
}
```

### Policy-Triggered Revocation

```json
{
  "audience": "https://receiver.example.com",
  "subject": "{\"format\":\"opaque\",\"id\":\"user-123-456\"}",
  "address": "https://api.example.com",
  "addressSuffix": "/v1/security-events",
  "initiatingEntity": "policy",
  "reasonAdmin": "Device compliance check failed",
  "reasonUser": "Your device no longer meets security requirements"
}
```

## Subject Formats

The `subject` parameter must be a JSON string representing the user whose session was revoked. Common formats include:

### Email Format
```json
{"format": "email", "email": "user@example.com"}
```

### Opaque Identifier
```json
{"format": "opaque", "id": "user-unique-id-123"}
```

### Phone Number
```json
{"format": "phone_number", "phone_number": "+1-555-555-5555"}
```

## Error Handling

The action distinguishes between retryable and non-retryable errors:

### Retryable Errors
These errors will trigger automatic retries by the framework:
- `429 Too Many Requests` - Rate limiting
- `502 Bad Gateway` - Temporary gateway issues
- `503 Service Unavailable` - Service temporarily unavailable
- `504 Gateway Timeout` - Request timeout

### Non-Retryable Errors
These errors indicate permanent failures:
- `400 Bad Request` - Invalid request format
- `401 Unauthorized` - Invalid authentication credentials
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Endpoint not found

## Security Considerations

1. **Private Key Security**: The `SSF_KEY` must be kept secure and should never be logged or exposed
2. **HTTPS Only**: All SET transmissions use HTTPS to ensure confidentiality
3. **JWT Validation**: Receivers should validate the JWT signature using the corresponding public key
4. **Subject Privacy**: Avoid including sensitive information in the subject identifier
5. **Reason Text**: Be careful not to expose sensitive details in reason messages

## Event Structure

The action creates a CAEP Session Revoked event following this structure:

```json
{
  "iss": "https://sgnl.ai/",
  "aud": "https://receiver.example.com",
  "iat": 1234567890,
  "sub_id": {
    "format": "email",
    "email": "user@example.com"
  },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
      "event_timestamp": 1234567890,
      "initiating_entity": "admin",
      "reason_admin": "Security policy violation",
      "reason_user": "Your session has been terminated"
    }
  }
}
```

## Troubleshooting

### Common Issues

1. **"SSF_KEY secret is required"**
   - Ensure the RSA private key is configured in secrets
   - Verify the key is in PEM format

2. **"Invalid subject JSON"**
   - Check that the subject parameter contains valid JSON
   - Ensure proper escaping of quotes in JSON strings

3. **"SET transmission failed: 401 Unauthorized"**
   - Verify the AUTH_TOKEN secret is configured correctly
   - Check that the token hasn't expired

4. **"SET transmission failed: 429 Too Many Requests"**
   - The receiver is rate limiting requests
   - The framework will automatically retry with backoff

### Debug Tips

- Use a lower-level signing method (RS256) initially for compatibility
- Test with a simple email subject format first
- Verify the receiver endpoint accepts the `/events` path if using addressSuffix
- Check receiver logs for detailed error messages

## References

- [OpenID CAEP Specification](https://openid.net/specs/openid-caep-1_0.html)
- [RFC 8417 - Security Event Token (SET)](https://datatracker.ietf.org/doc/html/rfc8417)
- [CAEP Event Types](https://openid.net/specs/openid-caep-1_0.html#rfc.section.4)
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
- Pre-signed JWT Security Event Token (created externally)
- Target receiver endpoint that accepts Security Event Tokens
- Optional: Bearer token for receiver authentication

## Configuration

### Secrets

| Name | Required | Description |
|------|----------|-------------|
| `BEARER_AUTH_TOKEN` | No | Bearer token for authenticating with the SET receiver |

### Input Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `jwt` | text | Yes | Pre-signed JWT Security Event Token |
| `address` | text | Yes | Destination URL for the SET transmission |
| `addressSuffix` | text | No | Optional suffix to append to the address |
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
  "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "address": "https://receiver.example.com/events"
}
```

### With Address Suffix

```json
{
  "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "address": "https://api.example.com",
  "addressSuffix": "/v1/security-events"
}
```

## JWT Structure

The JWT parameter must be a pre-signed Security Event Token. The JWT should be created externally and follow the CAEP specification. Here's an example of the expected JWT payload structure:

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

1. **JWT Security**: The pre-signed JWT must be created securely and protected during transmission
2. **HTTPS Only**: All SET transmissions use HTTPS to ensure confidentiality
3. **JWT Validation**: Receivers should validate the JWT signature using the corresponding public key
4. **Token Expiration**: Ensure JWTs have appropriate expiration times
5. **Bearer Token**: Protect the `BEARER_AUTH_TOKEN` secret and rotate it regularly


## Troubleshooting

### Common Issues

1. **"jwt is required"**
   - Ensure the JWT parameter is provided and not empty
   - Verify the JWT is properly formatted

2. **"SET transmission failed: 401 Unauthorized"**
   - Verify the `BEARER_AUTH_TOKEN` secret is configured correctly
   - Check that the token hasn't expired

3. **"SET transmission failed: 429 Too Many Requests"**
   - The receiver is rate limiting requests
   - The framework will automatically retry with backoff

### Debug Tips

- Verify the JWT is valid and not expired before transmission
- Test the receiver endpoint independently to ensure it's accessible
- Verify the receiver endpoint accepts the `/events` path if using addressSuffix
- Check receiver logs for detailed error messages about JWT validation

## References

- [OpenID CAEP Specification](https://openid.net/specs/openid-caep-1_0.html)
- [RFC 8417 - Security Event Token (SET)](https://datatracker.ietf.org/doc/html/rfc8417)
- [CAEP Event Types](https://openid.net/specs/openid-caep-1_0.html#rfc.section.4)
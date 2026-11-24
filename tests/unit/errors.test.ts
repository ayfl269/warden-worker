import { describe, expect, it } from 'vitest';

import { AppError, isAppError } from '../../src/errors';

describe('AppError', () => {
  it('maps every variant to the Rust status/body pair', () => {
    const cases: Array<[AppError, number, string, string]> = [
      [
        AppError.worker(new Error('boom')),
        500,
        'application/json',
        '{"error":"Worker error: boom"}',
      ],
      [AppError.database(), 500, 'application/json', '{"error":"Database error"}'],
      [
        AppError.notFound('Cipher not found'),
        404,
        'application/json',
        '{"error":"Cipher not found"}',
      ],
      [AppError.badRequest('nope'), 400, 'application/json', '{"error":"nope"}'],
      [
        AppError.unauthorized('Invalid token'),
        401,
        'application/json',
        '{"error":"Invalid token"}',
      ],
      [AppError.tooManyRequests('slow down'), 429, 'application/json', '{"error":"slow down"}'],
      [AppError.crypto('bad key'), 500, 'application/json', '{"error":"Crypto error: bad key"}'],
      [AppError.internal(), 500, 'application/json', '{"error":"Internal server error"}'],
    ];

    for (const [error, status, contentType, body] of cases) {
      expect(error.status).toBe(status);
      expect(error.contentType).toBe(contentType);
      expect(error.body).toBe(body);
    }
  });

  it('keeps verbatim bodies for 2FA-required and ApiJson errors', () => {
    const twoFactor = '{"error":"invalid_grant","error_description":"Two factor required."}';
    const error = AppError.twoFactorRequired(twoFactor);
    expect(error.status).toBe(400);
    expect(error.body).toBe(twoFactor);

    const api = AppError.apiJson(422, { error: 'Unexpected RegisterData format' });
    expect(api.status).toBe(422);
    expect(api.body).toBe('{"error":"Unexpected RegisterData format"}');
  });

  it('emits plain-text axum-style rejections', () => {
    const cases: Array<[AppError, number, string]> = [
      [AppError.payloadTooLarge(), 413, 'Failed to buffer the request body: length limit exceeded'],
      [
        AppError.jsonSyntax('unexpected token'),
        400,
        'Failed to parse the request body as JSON: unexpected token',
      ],
      [
        AppError.jsonData('type: Required'),
        422,
        'Failed to deserialize the JSON body into the target type: type: Required',
      ],
      [
        AppError.unsupportedMediaType(),
        415,
        'Expected request with `Content-Type: application/json`',
      ],
    ];

    for (const [error, status, body] of cases) {
      expect(error.status).toBe(status);
      expect(error.contentType).toBe('text/plain; charset=utf-8');
      expect(error.body).toBe(body);
    }
  });

  it('produces a Response with the right status and headers', async () => {
    const response = AppError.badRequest('invalid').toResponse();
    expect(response.status).toBe(400);
    expect(response.headers.get('content-type')).toBe('application/json');
    expect(await response.text()).toBe('{"error":"invalid"}');
  });

  it('narrows with isAppError', () => {
    expect(isAppError(AppError.internal())).toBe(true);
    expect(isAppError(new Error('x'))).toBe(false);
  });
});

/**
 * Application error type.
 *
 * Mirrors `src/error.rs`: every variant maps to a fixed status code and body,
 * and the JSON envelope is always `{"error":"<message>"}` unless a handler
 * returns a verbatim body.
 */

const JSON_CONTENT_TYPE = 'application/json';
const TEXT_CONTENT_TYPE = 'text/plain; charset=utf-8';

function jsonError(message: string): string {
  return JSON.stringify({ error: message });
}

export class AppError extends Error {
  readonly status: number;
  readonly body: string;
  readonly contentType: string;

  constructor(status: number, body: string, contentType: string = JSON_CONTENT_TYPE) {
    super(body);
    this.name = 'AppError';
    this.status = status;
    this.body = body;
    this.contentType = contentType;
  }

  toResponse(): Response {
    return new Response(this.body, {
      status: this.status,
      headers: { 'content-type': this.contentType },
    });
  }

  /**
   * 500 `Worker error` — an unexpected binding/runtime failure.
   *
   * The underlying message is logged, never returned: binding errors name
   * namespaces, buckets and (on registration) whether an email is already
   * taken, which is a free enumeration oracle for an anonymous caller.
   */
  static worker(error: unknown): AppError {
    console.error('[worker] binding/runtime error', error);
    return new AppError(500, jsonError('Worker error'));
  }

  /** 500 `Database error` — a D1 failure whose details are not exposed. */
  static database(): AppError {
    return new AppError(500, jsonError('Database error'));
  }

  static notFound(message: string): AppError {
    return new AppError(404, jsonError(message));
  }

  static badRequest(message: string): AppError {
    return new AppError(400, jsonError(message));
  }

  static unauthorized(message: string): AppError {
    return new AppError(401, jsonError(message));
  }

  static tooManyRequests(message: string): AppError {
    return new AppError(429, jsonError(message));
  }

  /** 500 `Crypto error: {m}`. */
  static crypto(message: string): AppError {
    return new AppError(500, jsonError(`Crypto error: ${message}`));
  }

  /** 500 `Internal server error` — e.g. a missing required secret. */
  static internal(): AppError {
    return new AppError(500, jsonError('Internal server error'));
  }

  /** 400 with a verbatim body (used for the 2FA-required payload). */
  static twoFactorRequired(body: string): AppError {
    return new AppError(400, body);
  }

  /** Arbitrary status with a verbatim JSON body (`AppError::ApiJson`). */
  static apiJson(status: number, body: unknown): AppError {
    return new AppError(status, JSON.stringify(body));
  }

  // ── axum extractor rejections (plain text, like the Rust stack) ─────

  /** 413: `DefaultBodyLimit` exceeded. */
  static payloadTooLarge(): AppError {
    return new AppError(
      413,
      'Failed to buffer the request body: length limit exceeded',
      TEXT_CONTENT_TYPE,
    );
  }

  /** 400: body was not valid JSON. */
  static jsonSyntax(detail: string): AppError {
    return new AppError(
      400,
      `Failed to parse the request body as JSON: ${detail}`,
      TEXT_CONTENT_TYPE,
    );
  }

  /** 422: JSON was valid but did not match the expected shape. */
  static jsonData(detail: string): AppError {
    return new AppError(
      422,
      `Failed to deserialize the JSON body into the target type: ${detail}`,
      TEXT_CONTENT_TYPE,
    );
  }

  /** 415: missing or wrong `Content-Type`. */
  static unsupportedMediaType(): AppError {
    return new AppError(
      415,
      'Expected request with `Content-Type: application/json`',
      TEXT_CONTENT_TYPE,
    );
  }
}

export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}

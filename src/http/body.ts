import { MAX_BODY_BYTES } from '../env';
import { AppError } from '../errors';

/** Minimal structural view of a Zod schema, so callers keep full inference. */
export interface BodySchema<T> {
  safeParse(value: unknown):
    | { success: true; data: T }
    | {
        success: false;
        error: { issues: ReadonlyArray<{ path?: PropertyKey[]; message: string }> };
      };
}

function isJsonContentType(value: string | null): boolean {
  if (value === null) return false;
  const mediaType = value.split(';', 1)[0]?.trim().toLowerCase() ?? '';
  return mediaType === 'application/json' || mediaType.endsWith('+json');
}

function isFormContentType(value: string | null): boolean {
  if (value === null) return false;
  const mediaType = value.split(';', 1)[0]?.trim().toLowerCase() ?? '';
  return mediaType === 'application/x-www-form-urlencoded';
}

/** Read the body as text, enforcing axum's 5 MiB `DefaultBodyLimit`. */
export async function readBodyText(request: Request): Promise<string> {
  const declaredLength = request.headers.get('content-length');
  if (declaredLength !== null) {
    const parsed = Number(declaredLength);
    if (Number.isFinite(parsed) && parsed > MAX_BODY_BYTES) {
      throw AppError.payloadTooLarge();
    }
  }

  const buffer = await request.arrayBuffer();
  if (buffer.byteLength > MAX_BODY_BYTES) {
    throw AppError.payloadTooLarge();
  }
  return new TextDecoder().decode(buffer);
}

/**
 * Parse and validate a JSON body.
 *
 * Error mapping matches axum: 415 for the wrong content type, 400 for invalid
 * JSON syntax, 422 when the JSON does not match the target type.
 */
export async function readJson<T>(request: Request, schema: BodySchema<T>): Promise<T> {
  if (!isJsonContentType(request.headers.get('content-type'))) {
    throw AppError.unsupportedMediaType();
  }

  const text = await readBodyText(request);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw AppError.jsonSyntax(error instanceof Error ? error.message : String(error));
  }

  const result = schema.safeParse(parsed);
  if (!result.success) {
    const detail = result.error.issues
      .map((issue) => {
        const path = (issue.path ?? []).map(String).join('.');
        return path.length > 0 ? `${path}: ${issue.message}` : issue.message;
      })
      .join(', ');
    throw AppError.jsonData(detail.length > 0 ? detail : 'invalid body');
  }

  return result.data;
}

/** Parse an `application/x-www-form-urlencoded` body (identity token endpoint). */
export async function readForm(request: Request): Promise<URLSearchParams> {
  if (!isFormContentType(request.headers.get('content-type'))) {
    throw new AppError(
      415,
      'Expected request with `Content-Type: application/x-www-form-urlencoded`',
      'text/plain; charset=utf-8',
    );
  }
  return new URLSearchParams(await readBodyText(request));
}

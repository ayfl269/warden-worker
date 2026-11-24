/**
 * Responses that are emitted as pre-built JSON strings.
 *
 * The Rust handlers assemble cipher/sync/domain payloads by concatenating JSON
 * fragments (from SQLite `json_object` or manual string building) and return
 * them with `Content-Type: application/json`. This helper preserves that
 * behaviour byte for byte.
 */
export function rawJson(body: string): Response {
  return new Response(body, { headers: { 'content-type': 'application/json' } });
}

/** `Json(())` in axum serializes to the literal body `null`. */
export function emptyJson(): Response {
  return new Response('null', { headers: { 'content-type': 'application/json' } });
}

export function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

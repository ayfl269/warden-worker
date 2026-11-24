/** Hibernation tags and protocol helpers for the notification hub. */

export const USER_KIND_TAG = 'k:user';
export const ANONYMOUS_KIND_TAG = 'k:anon';

export type ConnectionKind = 'user' | 'anonymous';

/** Per-socket attachment stored by the Durable Object. */
export interface ConnectionAttachment {
  kind: ConnectionKind;
  userId: string | null;
  token: string | null;
  deviceId: string | null;
  protocolInitialized: boolean;
  connectedAt: string;
}

export function userTag(userId: string): string {
  return `u:${userId}`;
}

export function anonymousTag(token: string): string {
  return `a:${token}`;
}

/** Fan-out selector: either a user id or an anonymous access token. */
export type FanoutSelector =
  | { kind: 'by_user'; user_id: string }
  | { kind: 'by_anonymous_token'; token: string };

export function selectorTag(selector: FanoutSelector): string {
  return selector.kind === 'by_user' ? userTag(selector.user_id) : anonymousTag(selector.token);
}

export function parseFanoutSelector(value: unknown): FanoutSelector | null {
  if (value === null || typeof value !== 'object') return null;
  const record = value as Record<string, unknown>;

  if (record.kind === 'by_user' && typeof record.user_id === 'string') {
    return { kind: 'by_user', user_id: record.user_id };
  }
  if (record.kind === 'by_anonymous_token' && typeof record.token === 'string') {
    return { kind: 'by_anonymous_token', token: record.token };
  }
  return null;
}

/**
 * Parse the client handshake frame.
 *
 * Clients send `{"protocol":"messagepack","version":1}` and may append a single
 * record separator (0x1e).
 */
export function isProtocolHandshake(message: string): boolean {
  let text = message;
  if (text.endsWith('\u001e')) text = text.slice(0, -1);

  try {
    const parsed = JSON.parse(text) as { protocol?: unknown; version?: unknown };
    return parsed.protocol === 'messagepack' && parsed.version === 1;
  } catch {
    return false;
  }
}

export function isWebSocketUpgrade(request: Request): boolean {
  return (request.headers.get('upgrade') ?? '').toLowerCase() === 'websocket';
}

/** Decode a base64 fan-out message body. */
export function decodeFanoutMessage(value: string): Uint8Array | null {
  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return null;
  }
}

export function encodeFanoutMessage(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

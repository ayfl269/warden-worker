import { describe, expect, it } from 'vitest';

import {
  anonymousTag,
  decodeFanoutMessage,
  encodeFanoutMessage,
  isProtocolHandshake,
  isWebSocketUpgrade,
  parseFanoutSelector,
  selectorTag,
  userTag,
} from '../../src/notifications/connection';

describe('tags', () => {
  it('builds user and anonymous tags', () => {
    expect(userTag('u1')).toBe('u:u1');
    expect(anonymousTag('tok')).toBe('a:tok');
  });

  it('maps selectors to tags', () => {
    expect(selectorTag({ kind: 'by_user', user_id: 'u1' })).toBe('u:u1');
    expect(selectorTag({ kind: 'by_anonymous_token', token: 't' })).toBe('a:t');
  });
});

describe('parseFanoutSelector', () => {
  it('accepts both selector kinds', () => {
    expect(parseFanoutSelector({ kind: 'by_user', user_id: 'u1' })).toEqual({
      kind: 'by_user',
      user_id: 'u1',
    });
    expect(parseFanoutSelector({ kind: 'by_anonymous_token', token: 't' })).toEqual({
      kind: 'by_anonymous_token',
      token: 't',
    });
  });

  it('rejects malformed selectors', () => {
    expect(parseFanoutSelector(null)).toBeNull();
    expect(parseFanoutSelector('by_user')).toBeNull();
    expect(parseFanoutSelector({ kind: 'by_user' })).toBeNull();
    expect(parseFanoutSelector({ kind: 'other', user_id: 'u' })).toBeNull();
  });
});

describe('protocol handshake', () => {
  it('accepts the messagepack handshake with or without a record separator', () => {
    const message = JSON.stringify({ protocol: 'messagepack', version: 1 });
    expect(isProtocolHandshake(message)).toBe(true);
    expect(isProtocolHandshake(`${message}\u001e`)).toBe(true);
  });

  it('rejects other protocols, versions and malformed JSON', () => {
    expect(isProtocolHandshake(JSON.stringify({ protocol: 'json', version: 1 }))).toBe(false);
    expect(isProtocolHandshake(JSON.stringify({ protocol: 'messagepack', version: 2 }))).toBe(
      false,
    );
    expect(isProtocolHandshake('not json')).toBe(false);
  });
});

describe('websocket upgrade detection', () => {
  it('is case-insensitive', () => {
    expect(
      isWebSocketUpgrade(new Request('https://x', { headers: { upgrade: 'websocket' } })),
    ).toBe(true);
    expect(
      isWebSocketUpgrade(new Request('https://x', { headers: { upgrade: 'WebSocket' } })),
    ).toBe(true);
    expect(isWebSocketUpgrade(new Request('https://x'))).toBe(false);
  });
});

describe('fanout message encoding', () => {
  it('round-trips bytes through base64', () => {
    const bytes = new Uint8Array([0x00, 0x91, 0x06, 0xff]);
    const encoded = encodeFanoutMessage(bytes);
    expect(decodeFanoutMessage(encoded)).toEqual(bytes);
  });

  it('returns null for invalid base64', () => {
    expect(decodeFanoutMessage('!!!')).toBeNull();
  });
});

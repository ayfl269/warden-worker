import { describe, expect, it } from 'vitest';

import {
  authPayload,
  cipherPayload,
  createAnonymousUpdateFrame,
  createPingFrame,
  createUpdateFrame,
  INITIAL_RESPONSE,
  UPDATE_TYPE,
  userPayload,
} from '../../src/notifications/frames';
import { encode, encodeTimestamp, frame, type MsgValue } from '../../src/notifications/msgpack';

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** Decode the LEB128 length prefix and return the body. */
function unframe(bytes: Uint8Array): Uint8Array {
  let length = 0;
  let shift = 0;
  let offset = 0;
  for (;;) {
    const byte = bytes[offset++] as number;
    length |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  expect(bytes.length - offset).toBe(length);
  return bytes.subarray(offset);
}

describe('msgpack encoding', () => {
  it('encodes nil, booleans, ints and strings', () => {
    expect(toHex(encode(null))).toBe('c0');
    expect(toHex(encode(true))).toBe('c3');
    expect(toHex(encode(false))).toBe('c2');
    expect(toHex(encode(0))).toBe('00');
    expect(toHex(encode(127))).toBe('7f');
    expect(toHex(encode(128))).toBe('d1' + '0080');
    expect(toHex(encode(-1))).toBe('ff');
    expect(toHex(encode('a'))).toBe('a161');
  });

  it('encodes arrays and maps in insertion order', () => {
    expect(toHex(encode([]))).toBe('90');
    expect(toHex(encode([1, 2]))).toBe('920102');
    expect(toHex(encode({ a: 1, b: 2 }))).toBe('82a16101a16202');
  });

  it('encodes the timestamp as ext -1 with 8 bytes', () => {
    const value = encodeTimestamp('2026-01-01T00:00:00.000Z');
    expect(value).toMatchObject({ ext: -1 });

    const encoded = encode(value);
    expect(encoded[0]).toBe(0xd7);
    expect(encoded[1]).toBe(0xff);

    const data = encoded.subarray(2);
    expect(data).toHaveLength(8);
    const decoded = new DataView(data.buffer, data.byteOffset, 8).getBigUint64(0, false);
    expect(Number(decoded & ((1n << 34n) - 1n))).toBe(1_767_225_600);
  });
});

describe('framing', () => {
  it('prefixes the body length as unsigned LEB128', () => {
    expect(toHex(frame(new Uint8Array([0x91, 0x06])))).toBe('029106');
    expect(toHex(frame(new Uint8Array(new Array(128).fill(0))))).toBe(`8001${'00'.repeat(128)}`);
  });

  it('builds the ping frame', () => {
    expect(toHex(createPingFrame())).toBe('029106');
  });

  it('builds the initial response', () => {
    expect(toHex(INITIAL_RESPONSE)).toBe('7b7d1e');
  });
});

describe('update frames', () => {
  it('wraps a cipher update in the ReceiveMessage envelope', () => {
    const bytes = createUpdateFrame(
      cipherPayload('c1', 'u1', '2026-01-01T00:00:00.000Z'),
      UPDATE_TYPE.SyncCipherUpdate,
      null,
    );
    const body = unframe(bytes);

    // array(5) = 1, map(0), nil, "ReceiveMessage"
    expect(body[0]).toBe(0x95);
    expect(body[1]).toBe(0x01);
    expect(body[2]).toBe(0x80);
    expect(body[3]).toBe(0xc0);
    expect(body[4]).toBe(0xae);
    expect(new TextDecoder().decode(body.subarray(5, 19))).toBe('ReceiveMessage');

    // fifth element is array(1) of a map(3): ContextId, Type, Payload
    expect(body[19]).toBe(0x91);
    expect(body[20]).toBe(0x83);
    const text = new TextDecoder().decode(body);
    expect(text).toContain('ContextId');
    expect(text).toContain('Payload');
    expect(toHex(body)).toContain('d7ff');
  });

  it('builds the anonymous frame with the upstream misspelling', () => {
    const bytes = createAnonymousUpdateFrame(
      authPayload('a1', 'u1'),
      UPDATE_TYPE.AuthRequestResponse,
      'u1',
    );
    const text = new TextDecoder().decode(unframe(bytes));
    expect(text).toContain('AuthRequestResponseRecieved');
    expect(text).toContain('UserId');
  });

  it('includes the user id in payload builders', () => {
    expect(userPayload('u1', '2026-01-01T00:00:00.000Z').UserId).toBe('u1');
    expect(cipherPayload('c1', 'u1', '2026-01-01T00:00:00.000Z')).toMatchObject({
      Id: 'c1',
      UserId: 'u1',
      OrganizationId: null,
      CollectionIds: null,
    });
  });

  it('keeps payload key order stable', () => {
    const payload: Record<string, MsgValue> = cipherPayload('c', 'u', '2026-01-01T00:00:00.000Z');
    expect(Object.keys(payload)).toEqual([
      'Id',
      'UserId',
      'OrganizationId',
      'CollectionIds',
      'RevisionDate',
    ]);
  });
});

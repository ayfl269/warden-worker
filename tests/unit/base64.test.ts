import { describe, expect, it } from 'vitest';

import {
  base64ToBytes,
  base64UrlNoPadToBytes,
  base64UrlToBytes,
  bytesToBase64,
  bytesToBase64Url,
  bytesToBase64UrlNoPad,
} from '../../src/auth/base64';

describe('base64 helpers', () => {
  it('round-trips arbitrary bytes with the STANDARD alphabet', () => {
    const bytes = new Uint8Array([0x00, 0x01, 0xfb, 0xff, 0x7f, 0x80]);
    const encoded = bytesToBase64(bytes);
    expect(encoded).toBe('AAH7/3+A');
    expect([...base64ToBytes(encoded)]).toEqual([...bytes]);
  });

  it('encodes the URL_SAFE alphabet but keeps padding', () => {
    const bytes = new Uint8Array([0xfb, 0xff]);
    expect(bytesToBase64(bytes)).toBe('+/8=');
    expect(bytesToBase64Url(bytes)).toBe('-_8=');
    expect([...base64UrlToBytes('-_8=')]).toEqual([0xfb, 0xff]);
  });

  it('strips padding for URL_SAFE_NO_PAD and accepts it back', () => {
    const bytes = new Uint8Array([0xfb, 0xff]);
    const encoded = bytesToBase64UrlNoPad(bytes);
    expect(encoded).toBe('-_8');
    expect([...base64UrlNoPadToBytes(encoded)]).toEqual([0xfb, 0xff]);
  });

  it('decodes unpadded input whose length is not a multiple of 4', () => {
    const payload = bytesToBase64UrlNoPad(new TextEncoder().encode('{"sub":"x"}'));
    expect(payload).toBe('eyJzdWIiOiJ4In0');
    expect(new TextDecoder().decode(base64UrlNoPadToBytes(payload))).toBe('{"sub":"x"}');
  });

  it('handles empty input', () => {
    expect(bytesToBase64(new Uint8Array(0))).toBe('');
    expect(base64ToBytes('')).toHaveLength(0);
    expect(bytesToBase64UrlNoPad(new Uint8Array(0))).toBe('');
  });
});

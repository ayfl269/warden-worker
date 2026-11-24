import { describe, expect, it } from 'vitest';

import { isStreamingRoute } from '../../src/handlers/streaming';

describe('isStreamingRoute', () => {
  it('matches attachment and Send file uploads', () => {
    expect(isStreamingRoute('PUT', '/api/ciphers/c1/attachment/a1/azure-upload')).toBe(true);
    expect(isStreamingRoute('put', '/api/sends/s1/file/f1/azure-upload')).toBe(true);
  });

  it('matches attachment downloads', () => {
    expect(isStreamingRoute('GET', '/api/ciphers/c1/attachment/a1/download')).toBe(true);
  });

  it('matches Send file downloads', () => {
    expect(isStreamingRoute('GET', '/api/sends/s1/f1')).toBe(true);
  });

  it('does not shadow the Send access routes', () => {
    expect(isStreamingRoute('GET', '/api/sends/access/x')).toBe(false);
    expect(isStreamingRoute('GET', '/api/sends/file/x')).toBe(false);
    expect(isStreamingRoute('GET', '/api/sends/access/file/f1')).toBe(false);
  });

  it('does not match other methods or shapes', () => {
    expect(isStreamingRoute('POST', '/api/ciphers/c1/attachment/a1/azure-upload')).toBe(false);
    expect(isStreamingRoute('GET', '/api/sends/s1')).toBe(false);
    expect(isStreamingRoute('GET', '/api/ciphers/c1/attachment/a1')).toBe(false);
    expect(isStreamingRoute('GET', '/api/sync')).toBe(false);
  });

  it('tolerates trailing slashes and root paths', () => {
    expect(isStreamingRoute('GET', '/api/sends/s1/f1/')).toBe(true);
    expect(isStreamingRoute('GET', '/')).toBe(false);
  });
});

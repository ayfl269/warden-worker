import { describe, expect, it } from 'vitest';

import { buildCipherData, cipherRequestSchema, typeFieldsOf } from '../../src/models/cipher';

describe('buildCipherData', () => {
  it('keeps name first and omits absent fields', () => {
    const data = buildCipherData({ name: '2.name', typeFields: { secureNote: { type: 0 } } });
    expect(Object.keys(data)).toEqual(['name', 'secureNote']);
    expect(JSON.stringify(data)).toBe('{"name":"2.name","secureNote":{"type":0}}');
  });

  it('preserves the documented field order', () => {
    const data = buildCipherData({
      name: 'n',
      notes: 'notes',
      typeFields: {
        login: { username: 'u' },
        fields: [],
        passwordHistory: [{ password: 'p' }],
        reprompt: 0,
        key: 'k',
      },
    });
    expect(Object.keys(data)).toEqual([
      'name',
      'notes',
      'login',
      'fields',
      'passwordHistory',
      'reprompt',
      'key',
    ]);
  });

  it('omits null notes but preserves null field values', () => {
    const withNullNotes = buildCipherData({ name: 'n', notes: null, typeFields: {} });
    expect('notes' in withNullNotes).toBe(false);

    const nullLogin = buildCipherData({ name: 'n', typeFields: { login: null } });
    expect(nullLogin.login).toBeNull();
  });

  it('normalizes passwordHistory', () => {
    expect(
      buildCipherData({
        name: 'n',
        typeFields: {
          passwordHistory: [
            { password: 'keep', lastUsedDate: 'x' },
            { password: 1 },
            'nope',
            null,
            { other: true },
          ],
        },
      }).passwordHistory,
    ).toEqual([{ password: 'keep', lastUsedDate: 'x' }]);

    expect(
      buildCipherData({ name: 'n', typeFields: { passwordHistory: 'not-an-array' } })
        .passwordHistory,
    ).toEqual([]);

    expect(buildCipherData({ name: 'n', typeFields: {} }).passwordHistory).toBeUndefined();
  });
});

describe('cipherRequestSchema', () => {
  const base = { type: 2, name: '2.name' };

  it('accepts favorite as a boolean or 0/1', () => {
    expect(cipherRequestSchema.parse({ ...base, favorite: true }).favorite).toBe(true);
    expect(cipherRequestSchema.parse({ ...base, favorite: 1 }).favorite).toBe(true);
    expect(cipherRequestSchema.parse({ ...base, favorite: 0 }).favorite).toBe(false);
    expect(cipherRequestSchema.parse(base).favorite).toBeUndefined();
  });

  it('normalizes empty folder ids to null', () => {
    expect(cipherRequestSchema.parse({ ...base, folderId: '' }).folderId).toBeNull();
    expect(cipherRequestSchema.parse({ ...base, folderId: 'f1' }).folderId).toBe('f1');
    expect(cipherRequestSchema.parse(base).folderId).toBeUndefined();
  });

  it('rejects cipher types outside 1..8', () => {
    expect(() => cipherRequestSchema.parse({ ...base, type: 0 })).toThrow();
    expect(() => cipherRequestSchema.parse({ ...base, type: 9 })).toThrow();
    expect(() => cipherRequestSchema.parse({ ...base, type: 1.5 })).toThrow();
  });

  it('requires a name', () => {
    expect(() => cipherRequestSchema.parse({ type: 2 })).toThrow();
  });

  it('extracts only the flattened type fields', () => {
    const request = cipherRequestSchema.parse({
      ...base,
      folderId: 'f1',
      favorite: true,
      secureNote: { type: 0 },
      notes: 'n',
    });
    expect(typeFieldsOf(request)).toEqual({ secureNote: { type: 0 } });
  });
});

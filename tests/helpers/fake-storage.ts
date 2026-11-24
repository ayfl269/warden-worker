/** Minimal in-memory R2 stub used by attachment tests. */
export interface FakeR2Object {
  body: ReadableStream;
  size: number;
}

export class FakeR2Bucket {
  readonly store = new Map<string, Uint8Array>();

  async put(
    key: string,
    value: ReadableStream | Uint8Array | string,
  ): Promise<{ size: number; key: string }> {
    let bytes: Uint8Array;
    if (typeof value === 'string') {
      bytes = new TextEncoder().encode(value);
    } else if (value instanceof Uint8Array) {
      bytes = value;
    } else {
      bytes = new Uint8Array(await new Response(value).arrayBuffer());
    }
    this.store.set(key, bytes);
    return { size: bytes.length, key };
  }

  async get(key: string): Promise<FakeR2Object | null> {
    const bytes = this.store.get(key);
    if (bytes === undefined) return null;
    return { body: new Response(bytes).body as ReadableStream, size: bytes.length };
  }

  async head(key: string): Promise<{ size: number } | null> {
    const bytes = this.store.get(key);
    return bytes === undefined ? null : { size: bytes.length };
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
}

/** Minimal KV stub with stream support and metadata. */
export class FakeKVNamespace {
  readonly store = new Map<string, { bytes: Uint8Array; metadata: Record<string, unknown> }>();

  async put(
    key: string,
    value: ReadableStream | Uint8Array | string,
    options?: { metadata?: Record<string, unknown> },
  ): Promise<void> {
    let bytes: Uint8Array;
    if (typeof value === 'string') {
      bytes = new TextEncoder().encode(value);
    } else if (value instanceof Uint8Array) {
      bytes = value;
    } else {
      bytes = new Uint8Array(await new Response(value).arrayBuffer());
    }
    this.store.set(key, { bytes, metadata: options?.metadata ?? {} });
  }

  async getWithMetadata(
    key: string,
    _type: 'stream',
  ): Promise<{ value: ReadableStream | null; metadata: Record<string, unknown> | null }> {
    const entry = this.store.get(key);
    if (entry === undefined) return { value: null, metadata: null };
    return { value: new Response(entry.bytes).body as ReadableStream, metadata: entry.metadata };
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
}

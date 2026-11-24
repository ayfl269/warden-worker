import { describe, expect, it } from 'vitest';

import type { Env } from '../../src/env';
import { decodeFanoutMessage } from '../../src/notifications/connection';
import {
  publishCipherUpdate,
  publishFolderUpdate,
  publishSendUpdate,
  publishUserLogout,
  publishUserUpdate,
} from '../../src/notifications/publish';

interface Captured {
  url: string;
  selector: unknown;
  bytes: Uint8Array;
}

function capturingEnv(): { env: Env; captured: Captured[] } {
  const captured: Captured[] = [];

  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit) {
      const body = JSON.parse(String(init?.body ?? '{}')) as {
        selector?: unknown;
        message?: string;
      };
      const bytes = typeof body.message === 'string' ? decodeFanoutMessage(body.message) : null;
      if (bytes !== null) {
        captured.push({ url: String(input), selector: body.selector, bytes });
      }
      return new Response('{}');
    },
  };

  const env = {
    NOTIFY_DO: {
      idFromName: (name: string) => name,
      get: () => stub,
    },
  } as unknown as Env;

  return { env, captured };
}

function textOf(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

async function flush(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 10));
}

describe('notification fan-out', () => {
  it('sends cipher payloads with the entity id', async () => {
    const { env, captured } = capturingEnv();

    publishCipherUpdate(env, 'u1', 1, 'cipher-1', '2026-01-01T00:00:00.000Z', 'dev-1');
    await flush();

    expect(captured).toHaveLength(1);
    expect(captured[0]?.url).toBe('https://notify.internal/fanout');
    expect(captured[0]?.selector).toEqual({ kind: 'by_user', user_id: 'u1' });

    const text = textOf(captured[0]!.bytes);
    expect(text).toContain('cipher-1');
    expect(text).toContain('ReceiveMessage');
    expect(text).toContain('dev-1');
    expect(text).toContain('CollectionIds');
  });

  it('sends folder and send payloads with their ids', async () => {
    const { env, captured } = capturingEnv();

    publishFolderUpdate(env, 'u1', 7, 'folder-1', '2026-01-01T00:00:00.000Z');
    publishSendUpdate(env, 'u1', 12, 'send-1', '2026-01-01T00:00:00.000Z');
    await flush();

    expect(captured).toHaveLength(2);
    expect(textOf(captured[0]!.bytes)).toContain('folder-1');
    expect(textOf(captured[1]!.bytes)).toContain('send-1');
  });

  it('sends user payloads with the user id only', async () => {
    const { env, captured } = capturingEnv();

    publishUserUpdate(env, 'u1', 10, '2026-01-01T00:00:00.000Z');
    await flush();

    const text = textOf(captured[0]!.bytes);
    expect(text).toContain('UserId');
    expect(text).not.toContain('CollectionIds');
  });

  it('uses LogOut (11) for logout notifications', async () => {
    const { env, captured } = capturingEnv();

    publishUserLogout(env, 'u1', '2026-01-01T00:00:00.000Z', 'dev-1');
    await flush();

    // The type is encoded as a small positive int (0x0b) inside the frame.
    const bytes = captured[0]!.bytes;
    expect([...bytes]).toContain(0x0b);
    expect(textOf(bytes)).toContain('ReceiveMessage');
  });

  it('is a no-op without a NOTIFY_DO binding', async () => {
    const { captured } = capturingEnv();
    publishUserUpdate({} as Env, 'u1', 0, '2026-01-01T00:00:00.000Z');
    await flush();
    expect(captured).toHaveLength(0);
  });
});

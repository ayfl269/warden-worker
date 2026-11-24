import { DurableObject } from 'cloudflare:workers';

import { isSessionStillValid, parseBearer, verifyAccessToken } from '../auth/jwt';
import { getDbUnconstrained, nowString } from '../db/client';
import type { Env } from '../env';
import {
  ANONYMOUS_KIND_TAG,
  anonymousTag,
  type ConnectionAttachment,
  decodeFanoutMessage,
  isProtocolHandshake,
  isWebSocketUpgrade,
  parseFanoutSelector,
  selectorTag,
  USER_KIND_TAG,
  userTag,
} from '../notifications/connection';
import { INITIAL_RESPONSE } from '../notifications/frames';

/**
 * WebSocket notification hub.
 *
 * Uses the WebSocket Hibernation API: sockets are tagged so the object can be
 * evicted between messages and still fan out to the right clients.
 */
export class NotifyDo extends DurableObject<Env> {
  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/notifications/hub' || url.pathname === '/hub') {
      return this.userHub(request, url);
    }
    if (url.pathname === '/notifications/anonymous-hub' || url.pathname === '/anonymous-hub') {
      return this.anonymousHub(request, url);
    }
    if (url.pathname === '/fanout') {
      return this.fanout(request);
    }

    return new Response(null, { status: 404 });
  }

  private async userHub(request: Request, url: URL): Promise<Response> {
    if (!isWebSocketUpgrade(request)) {
      return new Response('Expected WebSocket', { status: 426 });
    }

    const token =
      url.searchParams.get('access_token') ??
      url.searchParams.get('token') ??
      parseBearer(request.headers.get('authorization') ?? undefined);
    if (token === null || token.length === 0) {
      return new Response(JSON.stringify({ error: 'Missing access token' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    }

    const claims = await verifyAccessToken(this.env, token);
    if (claims === null) {
      return new Response(JSON.stringify({ error: 'Invalid token' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    }

    const db = getDbUnconstrained(this.env);
    try {
      if (!(await isSessionStillValid(db, claims))) {
        return new Response(JSON.stringify({ error: 'Invalid token' }), {
          status: 401,
          headers: { 'content-type': 'application/json' },
        });
      }
    } catch {
      return new Response(JSON.stringify({ error: 'Invalid token' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    }

    const attachment: ConnectionAttachment = {
      kind: 'user',
      userId: claims.sub,
      token: null,
      deviceId: claims.device,
      protocolInitialized: false,
      connectedAt: nowString(),
    };

    return this.accept(request, attachment, [userTag(claims.sub), USER_KIND_TAG]);
  }

  private async anonymousHub(request: Request, url: URL): Promise<Response> {
    if (!isWebSocketUpgrade(request)) {
      return new Response('Expected WebSocket', { status: 426 });
    }

    const token = url.searchParams.get('token');
    if (token === null || token.length === 0) {
      return new Response(JSON.stringify({ error: 'Missing token' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      });
    }

    const attachment: ConnectionAttachment = {
      kind: 'anonymous',
      userId: null,
      token,
      deviceId: null,
      protocolInitialized: false,
      connectedAt: nowString(),
    };

    return this.accept(request, attachment, [anonymousTag(token), ANONYMOUS_KIND_TAG]);
  }

  private accept(request: Request, attachment: ConnectionAttachment, tags: string[]): Response {
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    server.serializeAttachment(attachment);
    this.ctx.acceptWebSocket(server, tags);

    return new Response(null, { status: 101, webSocket: client });
  }

  private async fanout(request: Request): Promise<Response> {
    const body = (await request.json()) as { selector?: unknown; message?: unknown };
    const selector = parseFanoutSelector(body.selector);
    const message = typeof body.message === 'string' ? decodeFanoutMessage(body.message) : null;

    if (selector === null || message === null) {
      return new Response(JSON.stringify({ error: 'invalid fanout request' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      });
    }

    const sockets = this.ctx.getWebSockets(selectorTag(selector));
    let sent = 0;
    let pruned = 0;

    for (const socket of sockets) {
      const attachment = socket.deserializeAttachment() as ConnectionAttachment | null;
      if (attachment === null || attachment.kind === undefined) {
        pruned += 1;
        socket.close(1008, 'invalid connection attachment');
        continue;
      }
      if (!attachment.protocolInitialized) continue;

      try {
        socket.send(message);
        sent += 1;
      } catch {
        pruned += 1;
        socket.close(1011, 'send failed');
      }
    }

    return new Response(JSON.stringify({ matched: sockets.length, sent, pruned }), {
      headers: { 'content-type': 'application/json' },
    });
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== 'string') {
      // Binary frames from the client are echoed back unchanged.
      try {
        ws.send(message);
      } catch {
        ws.close(1011, 'websocket error');
      }
      return;
    }

    if (!isProtocolHandshake(message)) return;

    const attachment = ws.deserializeAttachment() as ConnectionAttachment | null;
    if (attachment === null) {
      ws.close(1008, 'invalid connection attachment');
      return;
    }

    attachment.protocolInitialized = true;
    ws.serializeAttachment(attachment);
    ws.send(INITIAL_RESPONSE);
  }

  override async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    try {
      ws.close(code, reason);
    } catch {
      // Already closed.
    }
  }

  override async webSocketError(ws: WebSocket): Promise<void> {
    try {
      ws.close(1011, 'websocket error');
    } catch {
      // Already closed.
    }
  }
}

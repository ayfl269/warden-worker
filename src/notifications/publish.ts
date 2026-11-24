import type { Env } from '../env';
import { encodeFanoutMessage, type FanoutSelector, selectorTag } from './connection';
import {
  authPayload,
  cipherPayload,
  createAnonymousUpdateFrame,
  createUpdateFrame,
  folderPayload,
  sendPayload,
  UPDATE_TYPE,
  userPayload,
} from './frames';
import type { MsgValue } from './msgpack';
import { sendPush, userPushPayload } from './push';

/**
 * Notification fan-out.
 *
 * Frames are posted to the singleton `NotifyDo` (`/fanout`), which resolves the
 * hibernation tag and pushes the bytes to every initialized socket. Delivery is
 * fire-and-forget: a missing binding or a relay failure must never fail the API
 * request.
 */

function dispatch(env: Env, selector: FanoutSelector, frame: Uint8Array): void {
  if (env.NOTIFY_DO === undefined) return;

  const body = JSON.stringify({
    selector,
    message: encodeFanoutMessage(frame),
  });

  try {
    const id = env.NOTIFY_DO.idFromName('global');
    const stub = env.NOTIFY_DO.get(id);
    void stub
      .fetch('https://notify.internal/fanout', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body,
      })
      .catch((error: unknown) => {
        console.warn(`[notify] fan-out failed for ${selectorTag(selector)}`, error);
      });
  } catch (error) {
    console.warn(`[notify] fan-out threw for ${selectorTag(selector)}`, error);
  }
}

function publishToUser(
  env: Env,
  userId: string,
  type: number,
  payload: Record<string, MsgValue>,
  contextId?: string,
): void {
  dispatch(
    env,
    { kind: 'by_user', user_id: userId },
    createUpdateFrame(payload, type, contextId ?? null),
  );
}

/** User-level update (`SyncSettings`, `LogOut`, `SyncVault`, ...). */
export function publishUserUpdate(
  env: Env,
  userId: string,
  type: number,
  date: string,
  contextId?: string,
): void {
  publishToUser(env, userId, type, userPayload(userId, date), contextId);
  // Push always runs in parallel with the WebSocket fan-out.
  void sendPush(env, userId, type, userPushPayload(userId, date), contextId);
}

/** Session invalidation — always type `LogOut` (11). */
export function publishUserLogout(
  env: Env,
  userId: string,
  date: string,
  contextId?: string,
): void {
  publishToUser(env, userId, UPDATE_TYPE.LogOut, userPayload(userId, date), contextId);
  void sendPush(env, userId, UPDATE_TYPE.LogOut, userPushPayload(userId, date), contextId);
}

export function publishCipherUpdate(
  env: Env,
  userId: string,
  type: number,
  cipherId: string,
  date: string,
  contextId?: string,
): void {
  publishToUser(env, userId, type, cipherPayload(cipherId, userId, date), contextId);
}

export function publishFolderUpdate(
  env: Env,
  userId: string,
  type: number,
  folderId: string,
  date: string,
  contextId?: string,
): void {
  publishToUser(env, userId, type, folderPayload(folderId, userId, date), contextId);
}

export function publishSendUpdate(
  env: Env,
  userId: string,
  type: number,
  sendId: string,
  date: string,
  contextId?: string,
): void {
  publishToUser(env, userId, type, sendPayload(sendId, userId, date), contextId);
}

export function publishAuthUpdate(
  env: Env,
  userId: string,
  type: number,
  authRequestId: string,
  contextId?: string,
): void {
  publishToUser(env, userId, type, authPayload(authRequestId, userId), contextId);
}

/** Anonymous auth-request response (uses the request id as the tag token). */
export function publishAnonymousUpdate(
  env: Env,
  token: string,
  userId: string,
  authRequestId: string,
): void {
  dispatch(
    env,
    { kind: 'by_anonymous_token', token },
    createAnonymousUpdateFrame(
      authPayload(authRequestId, userId),
      UPDATE_TYPE.AuthRequestResponse,
      userId,
    ),
  );
}

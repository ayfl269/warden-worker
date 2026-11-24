import { encode, encodeTimestamp, frame, type MsgValue } from './msgpack';

/** Update types, identical to `notifications.rs::UpdateType`. */
export const UPDATE_TYPE = {
  SyncCipherUpdate: 0,
  SyncCipherCreate: 1,
  SyncLoginDelete: 2,
  SyncFolderDelete: 3,
  SyncCiphers: 4,
  SyncVault: 5,
  SyncOrgKeys: 6,
  SyncFolderCreate: 7,
  SyncFolderUpdate: 8,
  SyncSettings: 10,
  LogOut: 11,
  SyncSendCreate: 12,
  SyncSendUpdate: 13,
  SyncSendDelete: 14,
  AuthRequest: 15,
  AuthRequestResponse: 16,
  None: 100,
} as const;

export const RECORD_SEPARATOR = 0x1e;

/** Sent verbatim after the client's protocol handshake: `{}` + RS. */
export const INITIAL_RESPONSE = new Uint8Array([0x7b, 0x7d, 0x1e]);

/** `[1, {}, nil, "ReceiveMessage", [{ContextId, Type, Payload}]]` */
export function createUpdateFrame(
  payload: Record<string, MsgValue>,
  type: number,
  contextId: string | null,
): Uint8Array {
  const value: MsgValue = [
    1,
    {},
    null,
    'ReceiveMessage',
    [{ ContextId: contextId, Type: type, Payload: payload }],
  ];
  return frame(encode(value));
}

/**
 * `[1, {}, nil, "AuthRequestResponseRecieved", [{Type, Payload, UserId}]]`
 * Note the upstream misspelling of "Received" — kept for client compatibility.
 */
export function createAnonymousUpdateFrame(
  payload: Record<string, MsgValue>,
  type: number,
  userId: string,
): Uint8Array {
  const value: MsgValue = [
    1,
    {},
    null,
    'AuthRequestResponseRecieved',
    [{ Type: type, Payload: payload, UserId: userId }],
  ];
  return frame(encode(value));
}

/** `[6]` — keep-alive ping. */
export function createPingFrame(): Uint8Array {
  return frame(encode([6]));
}

export function userPayload(userId: string, date: string): Record<string, MsgValue> {
  return { UserId: userId, Date: encodeTimestamp(date) };
}

export function folderPayload(
  id: string,
  userId: string,
  revisionDate: string,
): Record<string, MsgValue> {
  return { Id: id, UserId: userId, RevisionDate: encodeTimestamp(revisionDate) };
}

export function cipherPayload(
  id: string,
  userId: string,
  revisionDate: string,
): Record<string, MsgValue> {
  return {
    Id: id,
    UserId: userId,
    OrganizationId: null,
    CollectionIds: null,
    RevisionDate: encodeTimestamp(revisionDate),
  };
}

export function sendPayload(
  id: string,
  userId: string,
  revisionDate: string,
): Record<string, MsgValue> {
  return { Id: id, UserId: userId, RevisionDate: encodeTimestamp(revisionDate) };
}

export function authPayload(id: string, userId: string): Record<string, MsgValue> {
  return { Id: id, UserId: userId };
}

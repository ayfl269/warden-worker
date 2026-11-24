import type { Env } from '../env';
import { AppError } from '../errors';
import { jwtSecret, signToken, verifyToken } from './jwt';

export interface AttachmentClaims {
  sub: string;
  device: string;
  cipher_id: string;
  attachment_id: string;
  exp: number;
}

export interface SendFileClaims {
  sub: string;
  device: string;
  send_id: string;
  file_id: string;
  exp: number;
}

export interface SendDownloadClaims {
  send_id: string;
  file_id: string;
  exp: number;
}

/** Attachment/Send URL TTLs default to 300s; tokens expire 60s earlier. */
export const DEFAULT_FILE_TTL_SECONDS = 300;

export function attachmentTtl(env: Env): number {
  const raw = env.ATTACHMENT_TTL_SECS;
  if (raw === undefined) return DEFAULT_FILE_TTL_SECONDS;
  const parsed = Number.parseInt(raw.trim(), 10);
  return Number.isSafeInteger(parsed) ? parsed : DEFAULT_FILE_TTL_SECONDS;
}

export function sendTtl(env: Env): number {
  const raw = env.SEND_TTL_SECS;
  if (raw === undefined) return DEFAULT_FILE_TTL_SECONDS;
  const parsed = Number.parseInt(raw.trim(), 10);
  return Number.isSafeInteger(parsed) ? parsed : DEFAULT_FILE_TTL_SECONDS;
}

function tokenLifetime(ttlSeconds: number): number {
  const lifetime = ttlSeconds - 60;
  if (lifetime <= 0) {
    throw AppError.internal();
  }
  return lifetime;
}

export async function signAttachmentToken(
  env: Env,
  claims: Omit<AttachmentClaims, 'exp'>,
  ttlSeconds: number,
): Promise<string> {
  return signToken({ ...claims }, jwtSecret(env, 'JWT_SECRET'), tokenLifetime(ttlSeconds));
}

export async function signSendFileToken(
  env: Env,
  claims: Omit<SendFileClaims, 'exp'>,
  ttlSeconds: number,
): Promise<string> {
  return signToken({ ...claims }, jwtSecret(env, 'JWT_SECRET'), tokenLifetime(ttlSeconds));
}

export async function verifyAttachmentToken(
  env: Env,
  token: string,
): Promise<AttachmentClaims | null> {
  return verifyToken<AttachmentClaims>(token, jwtSecret(env, 'JWT_SECRET'));
}

export async function verifySendFileToken(env: Env, token: string): Promise<SendFileClaims | null> {
  return verifyToken<SendFileClaims>(token, jwtSecret(env, 'JWT_SECRET'));
}

export async function signSendDownloadToken(
  env: Env,
  claims: Omit<SendDownloadClaims, 'exp'>,
  ttlSeconds: number,
): Promise<string> {
  return signToken({ ...claims }, jwtSecret(env, 'JWT_SECRET'), tokenLifetime(ttlSeconds));
}

export async function verifySendDownloadToken(
  env: Env,
  token: string,
): Promise<SendDownloadClaims | null> {
  return verifyToken<SendDownloadClaims>(token, jwtSecret(env, 'JWT_SECRET'));
}

import { Hono } from 'hono';

import { requireAuth } from './auth/middleware';
import { preloginHandler, registerHandler } from './handlers/accounts';
import { postKdfHandler } from './handlers/accountsKdf';
import {
  getProfileHandler,
  getTasksHandler,
  postProfileHandler,
  putAvatarHandler,
  revisionDateHandler,
} from './handlers/accountsProfile';
import { rotateUserKeysHandler } from './handlers/accountsRotate';
import {
  deleteAccountHandler,
  postPasswordHandler,
  postSecurityStampHandler,
} from './handlers/accountsSecurity';
import {
  createAttachmentV2Handler,
  deleteAttachmentHandler,
  getAttachmentHandler,
  uploadAttachmentLegacyHandler,
  uploadAttachmentV2DataHandler,
} from './handlers/attachments';
import {
  getAuthRequestHandler,
  getAuthRequestResponseHandler,
  listAuthRequestsHandler,
  postAuthRequestHandler,
  putAuthRequestHandler,
} from './handlers/authRequests';
import {
  createCipherHandler,
  getCipherHandler,
  hardDeleteCipherHandler,
  listCiphersHandler,
  partialCipherHandler,
  restoreCipherHandler,
  softDeleteCipherHandler,
  updateCipherHandler,
} from './handlers/ciphers';
import {
  archiveCipherHandler,
  bulkArchiveHandler,
  bulkHardDeleteHandler,
  bulkRestoreHandler,
  bulkSoftDeleteHandler,
  bulkUnarchiveHandler,
  moveCipherHandler,
  purgeVaultHandler,
  unarchiveCipherHandler,
} from './handlers/ciphersBulk';
import { configHandler } from './handlers/config';
import {
  deleteDeviceHandler,
  getDeviceHandler,
  getDevicesHandler,
  getKnownDeviceHandler,
  postClearDeviceTokenHandler,
  postDeviceTokenHandler,
  putClearDeviceTokenHandler,
  putDeviceTokenHandler,
} from './handlers/devices';
import {
  createFolderHandler,
  deleteFolderHandler,
  getFolderHandler,
  listFoldersHandler,
  updateFolderHandler,
} from './handlers/folders';
import { tokenHandler } from './handlers/identity';
import { importDataHandler } from './handlers/import';
import { aliveHandler, hibpBreachHandler, nowHandler, versionHandler } from './handlers/meta';
import {
  emptyListHandler,
  emptyWebauthnListHandler,
  passwordHintHandler,
  sendVerificationEmailHandler,
} from './handlers/misc';
import {
  accessFileSendHandler,
  accessFileSendWithTokenHandler,
  accessSendHandler,
  accessSendWithTokenHandler,
  createFileSendLegacyHandler,
  createFileSendV2Handler,
  createTextSendHandler,
  deleteSendHandler,
  getSendHandler,
  listSendsHandler,
  removeSendPasswordHandler,
  updateSendHandler,
  uploadFileSendDirectHandler,
} from './handlers/sends';
import {
  getDomainsHandler,
  getSyncDataHandler,
  postDomainsHandler,
  putDomainsHandler,
} from './handlers/sync';
import {
  activateAuthenticatorHandler,
  deleteAuthenticatorHandler,
  disableTwoFactorHandler,
  getAuthenticatorHandler,
  getRecoverHandler,
  getTwoFactorHandler,
} from './handlers/twofactor';
import type { AppEnv } from './types';

/**
 * API route table.
 *
 * Mirrors `src/router.rs`. Routes are added feature by feature
 * (P1: config/meta; P2: identity/accounts; P3+: vault, storage, platform).
 */
export function apiRouter(): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const auth = requireAuth();

  router.get('/api/config', (c) => configHandler(c.env, c.get('baseUrl')));

  // Identity / accounts (registration + KDF discovery)
  router.post('/identity/accounts/prelogin', preloginHandler);
  router.post('/identity/accounts/prelogin/password', preloginHandler);
  router.post('/identity/accounts/register', registerHandler);
  router.post('/identity/accounts/register/finish', registerHandler);
  router.post('/identity/accounts/register/send-verification-email', sendVerificationEmailHandler);
  router.post('/identity/connect/token', tokenHandler);
  router.post('/api/accounts/password-hint', passwordHintHandler);

  // Account profile / settings
  router.get('/api/accounts/profile', auth, getProfileHandler);
  router.post('/api/accounts/profile', auth, postProfileHandler);
  router.put('/api/accounts/profile', auth, postProfileHandler);
  router.put('/api/accounts/avatar', auth, putAvatarHandler);
  router.get('/api/accounts/revision-date', auth, revisionDateHandler);
  router.get('/api/tasks', getTasksHandler);

  // Password / session management
  router.post('/api/accounts/password', auth, postPasswordHandler);
  router.post('/api/accounts/kdf', auth, postKdfHandler);
  router.post('/api/accounts/key-management/rotate-user-account-keys', auth, rotateUserKeysHandler);
  router.post('/api/accounts/security-stamp', auth, postSecurityStampHandler);
  router.delete('/api/accounts', auth, deleteAccountHandler);
  router.post('/api/accounts/delete', auth, deleteAccountHandler);

  // Ciphers — static bulk routes must be registered before `/:id`.
  router.post('/api/ciphers/create', auth, createCipherHandler);
  router.post('/api/ciphers/import', auth, importDataHandler);
  router.put('/api/ciphers/delete', auth, bulkSoftDeleteHandler);
  router.post('/api/ciphers/delete', auth, bulkHardDeleteHandler);
  router.put('/api/ciphers/restore', auth, bulkRestoreHandler);
  router.put('/api/ciphers/archive', auth, bulkArchiveHandler);
  router.put('/api/ciphers/unarchive', auth, bulkUnarchiveHandler);
  router.post('/api/ciphers/move', auth, moveCipherHandler);
  router.put('/api/ciphers/move', auth, moveCipherHandler);
  router.post('/api/ciphers/purge', auth, purgeVaultHandler);
  router.get('/api/ciphers', auth, listCiphersHandler);
  router.post('/api/ciphers', auth, createCipherHandler);
  router.delete('/api/ciphers', auth, bulkHardDeleteHandler);

  router.get('/api/ciphers/:id/details', auth, getCipherHandler);
  router.get('/api/ciphers/:id', auth, getCipherHandler);
  router.post('/api/ciphers/:id/attachment/v2', auth, createAttachmentV2Handler);
  router.post('/api/ciphers/:id/attachment', auth, uploadAttachmentLegacyHandler);
  router.post('/api/ciphers/:id/attachment/:attachmentId', auth, uploadAttachmentV2DataHandler);
  router.get('/api/ciphers/:id/attachment/:attachmentId', auth, getAttachmentHandler);
  router.delete('/api/ciphers/:id/attachment/:attachmentId', auth, deleteAttachmentHandler);
  router.post('/api/ciphers/:id/attachment/:attachmentId/delete', auth, deleteAttachmentHandler);
  router.put('/api/ciphers/:id/partial', auth, partialCipherHandler);
  router.post('/api/ciphers/:id/partial', auth, partialCipherHandler);
  router.put('/api/ciphers/:id/delete', auth, softDeleteCipherHandler);
  router.post('/api/ciphers/:id/delete', auth, hardDeleteCipherHandler);
  router.put('/api/ciphers/:id/restore', auth, restoreCipherHandler);
  router.put('/api/ciphers/:id/archive', auth, archiveCipherHandler);
  router.put('/api/ciphers/:id/unarchive', auth, unarchiveCipherHandler);
  router.put('/api/ciphers/:id', auth, updateCipherHandler);
  router.post('/api/ciphers/:id', auth, updateCipherHandler);
  router.delete('/api/ciphers/:id', auth, hardDeleteCipherHandler);

  // Folders
  router.get('/api/folders', auth, listFoldersHandler);
  router.post('/api/folders', auth, createFolderHandler);
  router.get('/api/folders/:id', auth, getFolderHandler);
  router.put('/api/folders/:id', auth, updateFolderHandler);
  router.delete('/api/folders/:id', auth, deleteFolderHandler);
  router.post('/api/folders/:id/delete', auth, deleteFolderHandler);

  // Auth requests (login with device)
  router.post('/api/auth-requests', auth, postAuthRequestHandler);
  router.get('/api/auth-requests', auth, listAuthRequestsHandler);
  router.get('/api/auth-requests/pending', auth, listAuthRequestsHandler);
  router.get('/api/auth-requests/:id/response', getAuthRequestResponseHandler);
  router.get('/api/auth-requests/:id', auth, getAuthRequestHandler);
  router.put('/api/auth-requests/:id', auth, putAuthRequestHandler);

  // Devices
  router.get('/api/devices', auth, getDevicesHandler);
  router.get('/api/devices/knowndevice', getKnownDeviceHandler);
  router.get('/api/devices/identifier/:device_id', auth, getDeviceHandler);
  router.delete('/api/devices/:id', auth, deleteDeviceHandler);
  router.delete('/api/devices/identifier/:device_id', auth, deleteDeviceHandler);
  router.post('/api/devices/identifier/:device_id/token', auth, postDeviceTokenHandler);
  router.put('/api/devices/identifier/:device_id/token', auth, putDeviceTokenHandler);
  router.put('/api/devices/identifier/:device_id/clear-token', auth, putClearDeviceTokenHandler);
  router.post('/api/devices/identifier/:device_id/clear-token', auth, postClearDeviceTokenHandler);

  // Two-factor authentication
  router.get('/api/two-factor', auth, getTwoFactorHandler);
  router.post('/api/two-factor/get-authenticator', auth, getAuthenticatorHandler);
  router.post('/api/two-factor/authenticator', auth, activateAuthenticatorHandler);
  router.put('/api/two-factor/authenticator', auth, activateAuthenticatorHandler);
  router.delete('/api/two-factor/authenticator', auth, deleteAuthenticatorHandler);
  router.post('/api/two-factor/disable', auth, disableTwoFactorHandler);
  router.put('/api/two-factor/disable', auth, disableTwoFactorHandler);
  router.post('/api/two-factor/get-recover', auth, getRecoverHandler);

  // Sends
  router.get('/api/sends', auth, listSendsHandler);
  router.post('/api/sends', auth, createTextSendHandler);
  router.post('/api/sends/file/v2', auth, createFileSendV2Handler);
  router.post('/api/sends/file', auth, createFileSendLegacyHandler);
  router.post('/api/sends/:send_id/file/:file_id', auth, uploadFileSendDirectHandler);
  router.post('/api/sends/access', accessSendWithTokenHandler);
  router.post('/api/sends/access/file/:file_id', accessFileSendWithTokenHandler);
  router.post('/api/sends/access/:access_id', accessSendHandler);
  router.post('/api/sends/:send_id/access/file/:file_id', accessFileSendHandler);
  router.get('/api/sends/:send_id', auth, getSendHandler);
  router.put('/api/sends/:send_id', auth, updateSendHandler);
  router.delete('/api/sends/:send_id', auth, deleteSendHandler);
  router.put('/api/sends/:send_id/remove-password', auth, removeSendPasswordHandler);

  // Sync and settings
  router.get('/api/sync', auth, getSyncDataHandler);
  router.get('/api/settings/domains', auth, getDomainsHandler);
  router.post('/api/settings/domains', auth, postDomainsHandler);
  router.put('/api/settings/domains', auth, putDomainsHandler);

  // Not-supported stubs (return empty lists so clients do not 404)
  router.get('/api/emergency-access/trusted', auth, emptyListHandler);
  router.get('/api/emergency-access/granted', auth, emptyListHandler);
  router.get('/api/webauthn', auth, emptyWebauthnListHandler);

  // Meta endpoints (mirrors a subset of vaultwarden core/mod.rs)
  router.get('/api/alive', (c) => aliveHandler(c.env));
  router.get('/api/now', () => nowHandler());
  router.get('/api/version', () => versionHandler());
  router.get('/api/hibp/breach', () => hibpBreachHandler());

  return router;
}

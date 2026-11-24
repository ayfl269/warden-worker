/**
 * Minimal `node:crypto` surface used by the worker.
 *
 * `@cloudflare/workers-types` does not ship Node built-in types, and adding
 * `@types/node` would conflict with the Workers globals (Request/Response/
 * setTimeout). Only the primitives below are needed.
 *
 * Runtime availability: Workers provides `node:crypto` behind the
 * `nodejs_compat` compatibility flag; PBKDF2 and HMAC are implemented over
 * BoringSSL, so PBKDF2 is NOT subject to the WebCrypto 100k-iteration cap.
 */
declare module 'node:crypto' {
  export interface Hmac {
    update(data: Uint8Array): Hmac;
    digest(): Uint8Array;
  }

  export function createHmac(algorithm: string, key: Uint8Array): Hmac;

  export function pbkdf2Sync(
    password: Uint8Array | string,
    salt: Uint8Array | string,
    iterations: number,
    keylen: number,
    digest: string,
  ): Uint8Array;
}

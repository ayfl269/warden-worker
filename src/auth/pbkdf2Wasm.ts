/**
 * PBKDF2 backed by the hand-written AssemblyScript module.
 *
 * The module is injected once at startup (`initPbkdf2Wasm`) because Node-based
 * tests cannot import `.wasm` files directly; when it is unavailable the
 * caller falls back to `node:crypto` and then `@noble/hashes`.
 */

let instance: WebAssembly.Instance | null = null;

/** Scratch offsets must match the module's memory contract. */
const PW_OFFSET = 0x10000;
const SALT_OFFSET = 0x10100;
const OUT_OFFSET = 0x10200;
const MAX_SALT_BYTES = 256;

export function initPbkdf2Wasm(module: WebAssembly.Module): boolean {
  try {
    instance = new WebAssembly.Instance(module, {
      env: {
        abort: () => {
          throw new Error('pbkdf2 wasm aborted');
        },
      },
    });
    return true;
  } catch (error) {
    console.warn('[pbkdf2] wasm init failed; falling back', error);
    instance = null;
    return false;
  }
}

export function isPbkdf2WasmReady(): boolean {
  return instance !== null;
}

/** Returns null when the module is unavailable or the input is out of range. */
export function pbkdf2Wasm(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
): Uint8Array | null {
  if (instance === null) return null;
  if (salt.length > MAX_SALT_BYTES) return null;

  const exports = instance.exports as unknown as {
    pbkdf2: (
      pwPtr: number,
      pwLen: number,
      saltPtr: number,
      saltLen: number,
      iterations: number,
      out: number,
    ) => void;
    memory: WebAssembly.Memory;
  };

  const memory = new Uint8Array(exports.memory.buffer);
  memory.set(password, PW_OFFSET);
  memory.set(salt, SALT_OFFSET);

  exports.pbkdf2(PW_OFFSET, password.length, SALT_OFFSET, salt.length, iterations, OUT_OFFSET);

  return memory.slice(OUT_OFFSET, OUT_OFFSET + 32);
}

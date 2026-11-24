// PBKDF2-HMAC-SHA256 in AssemblyScript.
//
// All scratch buffers live at fixed offsets so the hot loop performs no heap
// allocation (managed arrays caused incorrect reads and an OOB trap).
//
//   BLK   0x2000  64 B   current message block
//   PAD   0x2100  64 B   HMAC key block (ipad/opad)
//   INNER 0x2200  32 B   inner digest
//   U     0x2300  32 B   PBKDF2 U value
//   W     0x2400 256 B   SHA-256 message schedule
//   SALT  0x2500 260 B   salt || 0x00000001
//
// Build with `--initialMemory 2` (128 KiB) so these offsets are always mapped.

const K: u32[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const BLK: usize = 0x2000;
const PAD: usize = 0x2100;
const INNER: usize = 0x2200;
const U: usize = 0x2300;
const W: usize = 0x2400;
const SALT: usize = 0x2500;
const ISTATE: usize = 0x2600;
const OSTATE: usize = 0x2640;

let h0: u32 = 0;
let h1: u32 = 0;
let h2: u32 = 0;
let h3: u32 = 0;
let h4: u32 = 0;
let h5: u32 = 0;
let h6: u32 = 0;
let h7: u32 = 0;
let bufLen: i32 = 0;
let totalLen: u64 = 0;

@inline
function rotr(x: u32, n: u32): u32 {
  return (x >>> n) | (x << (32 - n));
}

@inline
function compressBlock(): void {
  for (let i: i32 = 0; i < 16; i++) {
    const o = BLK + <usize>(i * 4);
    store<u32>(W + (<usize>i << 2), (load<u8>(o) << 24) | (load<u8>(o + 1) << 16) | (load<u8>(o + 2) << 8) | load<u8>(o + 3));
  }
  for (let i: i32 = 16; i < 64; i++) {
    const w15 = load<u32>(W + (<usize>(i - 15) << 2));
    const w2 = load<u32>(W + (<usize>(i - 2) << 2));
    const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3);
    const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10);
    store<u32>(W + (<usize>i << 2), load<u32>(W + (<usize>(i - 16) << 2)) + s0 + load<u32>(W + (<usize>(i - 7) << 2)) + s1);
  }

  let a = h0;
  let b = h1;
  let c = h2;
  let d = h3;
  let e = h4;
  let f = h5;
  let g = h6;
  let h = h7;

  for (let i: i32 = 0; i < 64; i++) {
    const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const ch = (e & f) ^ (~e & g);
    const t1 = h + s1 + ch + unchecked(K[i]) + load<u32>(W + (<usize>i << 2));
    const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  h0 += a;
  h1 += b;
  h2 += c;
  h3 += d;
  h4 += e;
  h5 += f;
  h6 += g;
  h7 += h;
}

function init(): void {
  h0 = 0x6a09e667;
  h1 = 0xbb67ae85;
  h2 = 0x3c6ef372;
  h3 = 0xa54ff53a;
  h4 = 0x510e527f;
  h5 = 0x9b05688c;
  h6 = 0x1f83d9ab;
  h7 = 0x5be0cd19;
  bufLen = 0;
  totalLen = 0;
}

function update(ptr: usize, len: i32): void {
  totalLen += <u64>len;
  let off: i32 = 0;

  if (bufLen > 0) {
    const need = 64 - bufLen;
    const take = len < need ? len : need;
    for (let i: i32 = 0; i < take; i++) store<u8>(BLK + <usize>(bufLen + i), load<u8>(ptr + <usize>i));
    bufLen += take;
    off += take;
    if (bufLen === 64) {
      compressBlock();
      bufLen = 0;
    }
  }

  while (len - off >= 64) {
    for (let i: i32 = 0; i < 64; i++) store<u8>(BLK + <usize>i, load<u8>(ptr + <usize>(off + i)));
    compressBlock();
    off += 64;
  }

  while (off < len) {
    store<u8>(BLK + <usize>bufLen, load<u8>(ptr + <usize>off));
    bufLen++;
    off++;
  }
}

@inline
function writeWord(out: usize, v: u32): void {
  store<u8>(out, <u8>(v >>> 24));
  store<u8>(out + 1, <u8>(v >>> 16));
  store<u8>(out + 2, <u8>(v >>> 8));
  store<u8>(out + 3, <u8>(v));
}

function final(out: usize): void {
  const bits = totalLen << 3;
  store<u8>(BLK + <usize>bufLen, 0x80);
  bufLen++;

  if (bufLen > 56) {
    while (bufLen < 64) {
      store<u8>(BLK + <usize>bufLen, 0);
      bufLen++;
    }
    compressBlock();
    bufLen = 0;
  }
  while (bufLen < 56) {
    store<u8>(BLK + <usize>bufLen, 0);
    bufLen++;
  }
  for (let i: i32 = 0; i < 8; i++) {
    store<u8>(BLK + <usize>(56 + i), <u8>(bits >>> <u32>((7 - i) * 8)));
  }
  compressBlock();

  writeWord(out, h0);
  writeWord(out + 4, h1);
  writeWord(out + 8, h2);
  writeWord(out + 12, h3);
  writeWord(out + 16, h4);
  writeWord(out + 20, h5);
  writeWord(out + 24, h6);
  writeWord(out + 28, h7);
}

function saveState(dst: usize): void {
  store<u32>(dst, h0);
  store<u32>(dst + 4, h1);
  store<u32>(dst + 8, h2);
  store<u32>(dst + 12, h3);
  store<u32>(dst + 16, h4);
  store<u32>(dst + 20, h5);
  store<u32>(dst + 24, h6);
  store<u32>(dst + 28, h7);
}

@inline
function loadState(src: usize): void {
  h0 = load<u32>(src);
  h1 = load<u32>(src + 4);
  h2 = load<u32>(src + 8);
  h3 = load<u32>(src + 12);
  h4 = load<u32>(src + 16);
  h5 = load<u32>(src + 20);
  h6 = load<u32>(src + 24);
  h7 = load<u32>(src + 28);
  bufLen = 0;
  totalLen = 64;
}

/** Precompute SHA-256 states after the ipad/opad blocks (key is constant). */
function hmacInit(keyPtr: usize, keyLen: i32): void {
  for (let i: i32 = 0; i < 64; i++) store<u8>(PAD + <usize>i, 0);

  if (keyLen > 64) {
    init();
    update(keyPtr, keyLen);
    final(INNER);
    for (let i: i32 = 0; i < 32; i++) store<u8>(PAD + <usize>i, load<u8>(INNER + <usize>i));
  } else {
    for (let i: i32 = 0; i < keyLen; i++) store<u8>(PAD + <usize>i, load<u8>(keyPtr + <usize>i));
  }

  for (let i: i32 = 0; i < 64; i++) store<u8>(PAD + <usize>i, load<u8>(PAD + <usize>i) ^ 0x36);
  init();
  update(PAD, 64);
  saveState(ISTATE);

  for (let i: i32 = 0; i < 64; i++) store<u8>(PAD + <usize>i, load<u8>(PAD + <usize>i) ^ (0x36 ^ 0x5c));
  init();
  update(PAD, 64);
  saveState(OSTATE);
}

/** One HMAC using the precomputed states: 2 compressions instead of 4. */
function hmacApply(msgPtr: usize, msgLen: i32, out: usize): void {
  loadState(ISTATE);
  update(msgPtr, msgLen);
  final(INNER);

  loadState(OSTATE);
  update(INNER, 32);
  final(out);
}

/** Build one 64-byte block from a 32-byte message plus SHA-256 padding. */
@inline
function blockFrom32(src: usize): void {
  for (let i: i32 = 0; i < 8; i++) {
    store<u32>(BLK + (<usize>i << 2), load<u32>(src + (<usize>i << 2)));
  }
  store<u8>(BLK + 32, 0x80);
  for (let i: i32 = 33; i < 56; i++) store<u8>(BLK + <usize>i, 0);
  // bit length = (64 + 32) * 8 = 768 = 0x0300, big-endian
  store<u8>(BLK + 56, 0);
  store<u8>(BLK + 57, 0);
  store<u8>(BLK + 58, 0);
  store<u8>(BLK + 59, 0);
  store<u8>(BLK + 60, 0);
  store<u8>(BLK + 61, 0);
  store<u8>(BLK + 62, 0x03);
  store<u8>(BLK + 63, 0);
}

/** HMAC over exactly 32 bytes with precomputed states (hot path, 2 compressions). */
function hmac32(msgPtr: usize, out: usize): void {
  loadState(ISTATE);
  blockFrom32(msgPtr);
  compressBlock();
  writeWord(INNER, h0);
  writeWord(INNER + 4, h1);
  writeWord(INNER + 8, h2);
  writeWord(INNER + 12, h3);
  writeWord(INNER + 16, h4);
  writeWord(INNER + 20, h5);
  writeWord(INNER + 24, h6);
  writeWord(INNER + 28, h7);

  loadState(OSTATE);
  blockFrom32(INNER);
  compressBlock();
  writeWord(out, h0);
  writeWord(out + 4, h1);
  writeWord(out + 8, h2);
  writeWord(out + 12, h3);
  writeWord(out + 16, h4);
  writeWord(out + 20, h5);
  writeWord(out + 24, h6);
  writeWord(out + 28, h7);
}
function hmac(keyPtr: usize, keyLen: i32, msgPtr: usize, msgLen: i32, out: usize): void {
  hmacInit(keyPtr, keyLen);
  hmacApply(msgPtr, msgLen, out);
}

/** PBKDF2-HMAC-SHA256, single 32-byte output block. Salt must be <= 256 bytes. */
export function pbkdf2(
  pwPtr: usize,
  pwLen: i32,
  saltPtr: usize,
  saltLen: i32,
  iterations: i32,
  out: usize,
): void {
  for (let i: i32 = 0; i < saltLen; i++) store<u8>(SALT + <usize>i, load<u8>(saltPtr + <usize>i));
  store<u8>(SALT + <usize>saltLen, 0);
  store<u8>(SALT + <usize>(saltLen + 1), 0);
  store<u8>(SALT + <usize>(saltLen + 2), 0);
  store<u8>(SALT + <usize>(saltLen + 3), 1);

  hmacInit(pwPtr, pwLen);
  hmacApply(SALT, saltLen + 4, U);
  for (let i: i32 = 0; i < 32; i++) store<u8>(out + <usize>i, load<u8>(U + <usize>i));

  for (let n: i32 = 1; n < iterations; n++) {
    hmac32(U, U);
    for (let i: i32 = 0; i < 32; i++) {
      store<u8>(out + <usize>i, load<u8>(out + <usize>i) ^ load<u8>(U + <usize>i));
    }
  }
}

/** Test hook: SHA-256 of a memory range. */
export function sha256(ptr: usize, len: i32, out: usize): void {
  init();
  update(ptr, len);
  final(out);
}

/** Test hook: HMAC-SHA256 of a memory range. */
export function hmacSha256(keyPtr: usize, keyLen: i32, msgPtr: usize, msgLen: i32, out: usize): void {
  hmac(keyPtr, keyLen, msgPtr, msgLen, out);
}

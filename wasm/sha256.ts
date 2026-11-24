// SHA-256 in AssemblyScript — probe that the toolchain and our implementation
// match a known vector. PBKDF2 will build on this.
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

const W: usize = 0x0000; // 64 * u32
const BLK: usize = 0x1000; // 64 bytes

let h0: u32 = 0;
let h1: u32 = 0;
let h2: u32 = 0;
let h3: u32 = 0;
let h4: u32 = 0;
let h5: u32 = 0;
let h6: u32 = 0;
let h7: u32 = 0;

function rotr(x: u32, n: u32): u32 {
  return (x >>> n) | (x << (32 - n));
}

function compress(): void {
  for (let i: i32 = 0; i < 16; i++) {
    store<u32>(W + (<usize>i << 2), (load<u8>(BLK + <usize>(i * 4)) << 24) | (load<u8>(BLK + <usize>(i * 4 + 1)) << 16) | (load<u8>(BLK + <usize>(i * 4 + 2)) << 8) | load<u8>(BLK + <usize>(i * 4 + 3)));
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
    const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const ch = (e & f) ^ (~e & g);
    const t1 = h + S1 + ch + K[i] + load<u32>(W + (<usize>i << 2));
    const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = S0 + maj;
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
}

function writeOut(out: usize): void {
  const hs = [h0, h1, h2, h3, h4, h5, h6, h7];
  for (let i: i32 = 0; i < 8; i++) {
    const v = hs[i];
    store<u8>(out + <usize>(i * 4), <u8>(v >>> 24));
    store<u8>(out + <usize>(i * 4 + 1), <u8>(v >>> 16));
    store<u8>(out + <usize>(i * 4 + 2), <u8>(v >>> 8));
    store<u8>(out + <usize>(i * 4 + 3), <u8>(v));
  }
}

/** Probe: SHA-256("abc") into `out` (32 bytes). */
export function sha256Abc(out: usize): void {
  init();
  store<u8>(BLK + 0, 0x61);
  store<u8>(BLK + 1, 0x62);
  store<u8>(BLK + 2, 0x63);
  store<u8>(BLK + 3, 0x80);
  for (let i: i32 = 4; i < 56; i++) store<u8>(BLK + <usize>i, 0);
  const bits: u64 = 24;
  for (let i: i32 = 0; i < 8; i++) store<u8>(BLK + <usize>(63 - i), <u8>(bits >>> (<u32>(i * 8))));
  compress();
  writeOut(out);
}

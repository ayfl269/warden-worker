/**
 * Minimal MessagePack encoder.
 *
 * Only the subset used by the Bitwarden notification protocol is implemented:
 * nil, booleans, integers, strings, arrays, maps and the `ext -1` timestamp.
 * Map key order is insertion order (matters for byte-level parity).
 */

export type MsgValue =
  | null
  | boolean
  | number
  | string
  | Uint8Array
  | MsgValue[]
  | { [key: string]: MsgValue }
  | { ext: number; data: Uint8Array };

class Writer {
  private readonly bytes: number[] = [];

  push(byte: number): void {
    this.bytes.push(byte & 0xff);
  }

  pushBytes(values: ArrayLike<number>): void {
    for (let index = 0; index < values.length; index += 1) {
      this.bytes.push(values[index] as number);
    }
  }

  pushUint16(value: number): void {
    this.push((value >>> 8) & 0xff);
    this.push(value & 0xff);
  }

  pushUint32(value: number): void {
    this.push((value >>> 24) & 0xff);
    this.push((value >>> 16) & 0xff);
    this.push((value >>> 8) & 0xff);
    this.push(value & 0xff);
  }

  finish(): Uint8Array {
    return new Uint8Array(this.bytes);
  }
}

function isExt(value: object): value is { ext: number; data: Uint8Array } {
  return 'ext' in value && 'data' in value;
}

function writeValue(writer: Writer, value: MsgValue): void {
  if (value === null) {
    writer.push(0xc0);
    return;
  }
  if (typeof value === 'boolean') {
    writer.push(value ? 0xc3 : 0xc2);
    return;
  }
  if (typeof value === 'number') {
    writeInteger(writer, value);
    return;
  }
  if (typeof value === 'string') {
    writeString(writer, value);
    return;
  }
  if (value instanceof Uint8Array) {
    writeBinary(writer, value);
    return;
  }
  if (Array.isArray(value)) {
    writeArrayHeader(writer, value.length);
    for (const item of value) writeValue(writer, item);
    return;
  }
  if (isExt(value)) {
    writeExt(writer, value.ext, value.data);
    return;
  }

  const entries = Object.entries(value);
  writeMapHeader(writer, entries.length);
  for (const [key, child] of entries) {
    writeString(writer, key);
    writeValue(writer, child);
  }
}

function writeInteger(writer: Writer, value: number): void {
  if (!Number.isInteger(value)) {
    // Protocol never uses floats; fall back to a 64-bit float encoding.
    writer.push(0xcb);
    const buffer = new Uint8Array(8);
    new DataView(buffer.buffer).setFloat64(0, value, false);
    writer.pushBytes(buffer);
    return;
  }
  if (value >= 0 && value < 0x80) {
    writer.push(value);
    return;
  }
  if (value < 0 && value >= -32) {
    writer.push(0xe0 | (value + 32));
    return;
  }
  if (value >= -128 && value < 128) {
    writer.push(0xd0);
    writer.push(value & 0xff);
    return;
  }
  if (value >= -32768 && value < 32768) {
    writer.push(0xd1);
    writer.pushUint16(value & 0xffff);
    return;
  }
  if (value >= -2147483648 && value < 2147483648) {
    writer.push(0xd2);
    writer.pushUint32(value >>> 0);
    return;
  }
  writer.push(0xd3);
  const buffer = new Uint8Array(8);
  new DataView(buffer.buffer).setBigInt64(0, BigInt(value), false);
  writer.pushBytes(buffer);
}

function writeString(writer: Writer, value: string): void {
  const encoded = new TextEncoder().encode(value);
  const length = encoded.length;

  if (length < 32) {
    writer.push(0xa0 | length);
  } else if (length < 256) {
    writer.push(0xd9);
    writer.push(length);
  } else {
    writer.push(0xda);
    writer.pushUint16(length);
  }
  writer.pushBytes(encoded);
}

function writeBinary(writer: Writer, value: Uint8Array): void {
  const length = value.length;
  if (length < 256) {
    writer.push(0xc4);
    writer.push(length);
  } else {
    writer.push(0xc5);
    writer.pushUint16(length);
  }
  writer.pushBytes(value);
}

function writeArrayHeader(writer: Writer, length: number): void {
  if (length < 16) {
    writer.push(0x90 | length);
  } else {
    writer.push(0xdc);
    writer.pushUint16(length);
  }
}

function writeMapHeader(writer: Writer, length: number): void {
  if (length < 16) {
    writer.push(0x80 | length);
  } else {
    writer.push(0xde);
    writer.pushUint16(length);
  }
}

function writeExt(writer: Writer, type: number, data: Uint8Array): void {
  if (data.length === 8) {
    writer.push(0xd7);
  } else if (data.length === 4) {
    writer.push(0xd6);
  } else {
    writer.push(0xc7);
    writer.push(data.length);
  }
  writer.push(type & 0xff);
  writer.pushBytes(data);
}

export function encode(value: MsgValue): Uint8Array {
  const writer = new Writer();
  writeValue(writer, value);
  return writer.finish();
}

/** `ext -1` timestamp: 8 bytes big-endian `(nanos << 34) | seconds`. */
export function encodeTimestamp(isoDate: string): MsgValue {
  const parsed = new Date(isoDate);
  const milliseconds = Number.isNaN(parsed.getTime()) ? Date.now() : parsed.getTime();
  const seconds = Math.floor(milliseconds / 1000);
  const nanos = (milliseconds % 1000) * 1_000_000;
  const value = (BigInt(nanos) << 34n) | BigInt(seconds);

  const data = new Uint8Array(8);
  new DataView(data.buffer).setBigUint64(0, value, false);
  return { ext: -1, data };
}

/** Unsigned LEB128 length prefix, matching the Rust frame writer. */
export function frame(body: Uint8Array): Uint8Array {
  const prefix: number[] = [];
  let size = body.length;

  do {
    let part = size & 0x7f;
    size >>>= 7;
    if (size > 0) part |= 0x80;
    prefix.push(part);
  } while (size > 0);

  const output = new Uint8Array(prefix.length + body.length);
  output.set(prefix, 0);
  output.set(body, prefix.length);
  return output;
}

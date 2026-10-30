'use strict';
/**
 * PSTScout M2.2 experimental compatibility hook.
 *
 * Loaded with: node --require ./vault_hook.cjs inspect.mjs archive.pstsc ...
 * Hooks ONLY `pst-extractor` PSTFile.prototype.readSync for one `.pstsc` file.
 * It does not touch fs.readSync, does not materialize a plaintext PST, and
 * does not affect normal `.pst` readers in a different process. Nevertheless,
 * runtime prototype patching is a POC; replace with a maintained byte-source
 * interface in pst-extractor before production.
 *
 * PSTSCV01 format matches src/pstscout/vault.py byte-for-byte.
 */
const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const { PSTFile } = require('pst-extractor');

const HEADER_BASE = 56;
const HEADER_TOTAL = 88;
const TAG_SIZE = 16;
const MAX_READ = 8 * 1024 * 1024;
const CACHE_COUNT = 4;
const VERSION = 1;
const KDF_N = 32768;
const KDF_R = 8;
const KDF_P = 1;

function readExact(fd, length, position) {
  const out = Buffer.alloc(length);
  let total = 0;
  while (total < length) {
    const received = fs.readSync(fd, out, total, length - total, position + total);
    if (received === 0) throw Error('E_TRUNCATED');
    total += received;
  }
  return out;
}
function inputPassword() {
  // The parent provides an in-memory password via a dedicated stdin pipe.
  // Never accept it through argv, environment variables, JSON events, or logs.
  const chunks = [];
  let total = 0;
  while (total <= 1024) {
    const buf = Buffer.alloc(256);
    const n = fs.readSync(0, buf, 0, buf.length, null);
    if (!n) throw Error('E_NO_PASSWORD');
    const newline = buf.subarray(0, n).indexOf(10);
    const take = newline < 0 ? n : newline;
    if (take) chunks.push(Buffer.from(buf.subarray(0, take)));
    total += take;
    buf.fill(0);
    if (newline >= 0) break;
  }
  if (!total || total > 1024) throw Error('E_PASSWORD_SIZE');
  const password = Buffer.concat(chunks);
  for (const x of chunks) x.fill(0);
  return password;
}
class EncryptedByteSource {
  constructor(archive, password) {
    this.fd = fs.openSync(archive, 'r');
    this.cache = new Map();
    this.key = null;
    try {
      const base = readExact(this.fd, HEADER_BASE, 0);
      const tag = readExact(this.fd, 32, HEADER_BASE);
      if (base.subarray(0, 8).toString('ascii') !== 'PSTSCV01'
          || base.readUInt32LE(8) !== VERSION) throw Error('E_FORMAT');
      this.chunkSize = base.readUInt32LE(12);
      if (this.chunkSize < 65536 || this.chunkSize > 4194304
          || (this.chunkSize & (this.chunkSize - 1)) !== 0) throw Error('E_CHUNK_SIZE');
      this.size = base.readBigUInt64LE(16);
      if (this.size > BigInt(Number.MAX_SAFE_INTEGER)) throw Error('E_UNSUPPORTED_SIZE');
      if (base.readUInt32LE(24) !== KDF_N || base.readUInt32LE(28) !== KDF_R
          || base.readUInt32LE(32) !== KDF_P) throw Error('E_KDF');
      const salt = base.subarray(36, 52);
      this.prefix = Buffer.from(base.subarray(52, 56));
      const root = crypto.scryptSync(password, salt, 32, {
        N: KDF_N, r: KDF_R, p: KDF_P, maxmem: 128 * 1024 * 1024,
      });
      const separated = Buffer.from(crypto.hkdfSync('sha256', root, salt,
        Buffer.from('PSTScout-M2.1-file-keys-v1', 'utf8'), 64));
      root.fill(0);
      this.key = Buffer.from(separated.subarray(0, 32));
      const macKey = separated.subarray(32, 64);
      const calculated = crypto.createHmac('sha256', macKey).update(base).digest();
      if (!crypto.timingSafeEqual(tag, calculated)) throw Error('E_AUTH');
      separated.fill(0);
      const count = this.size === 0n ? 0n
        : (this.size + BigInt(this.chunkSize) - 1n) / BigInt(this.chunkSize);
      const expected = BigInt(HEADER_TOTAL) + this.size + count * BigInt(TAG_SIZE);
      if (BigInt(fs.fstatSync(this.fd).size) !== expected) throw Error('E_LENGTH');
      this.base = base;
      this.count = Number(count);
      this.totalSize = Number(this.size);
    } catch (err) {
      this.close();
      throw err;
    }
  }
  close() {
    if (this.cache) {
      for (const item of this.cache.values()) item.fill(0);
      this.cache.clear();
    }
    if (this.key) { this.key.fill(0); this.key = null; }
    if (this.fd != null) { fs.closeSync(this.fd); this.fd = null; }
  }
  chunk(index) {
    const cached = this.cache.get(index);
    if (cached) { this.cache.delete(index); this.cache.set(index, cached); return cached; }
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.count) throw Error('E_INDEX');
    const length = Math.min(this.chunkSize, this.totalSize - index * this.chunkSize);
    const physicalOffset = HEADER_TOTAL + index * (this.chunkSize + TAG_SIZE);
    const encrypted = readExact(this.fd, length + TAG_SIZE, physicalOffset);
    const nonce = Buffer.alloc(12);
    this.prefix.copy(nonce, 0);
    nonce.writeBigUInt64BE(BigInt(index), 4);
    const aadInfo = Buffer.alloc(12);
    aadInfo.writeBigUInt64LE(BigInt(index), 0);
    aadInfo.writeUInt32LE(length, 8);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, nonce, {authTagLength: TAG_SIZE});
    decipher.setAAD(Buffer.concat([this.base, aadInfo]));
    decipher.setAuthTag(encrypted.subarray(length));
    const plain = Buffer.concat([decipher.update(encrypted.subarray(0, length)), decipher.final()]);
    this.cache.set(index, plain);
    if (this.cache.size > CACHE_COUNT) {
      const oldest = this.cache.keys().next().value;
      this.cache.get(oldest).fill(0);
      this.cache.delete(oldest);
    }
    return plain;
  }
  readAt(position, length) {
    if (!Number.isSafeInteger(position) || !Number.isSafeInteger(length)
        || position < 0 || length < 0 || length > MAX_READ) throw Error('E_READ');
    if (length === 0 || position >= this.totalSize) return Buffer.alloc(0);
    const end = Math.min(this.totalSize, position + length);
    const output = Buffer.alloc(end - position);
    let cursor = position;
    let written = 0;
    while (cursor < end) {
      const index = Math.floor(cursor / this.chunkSize);
      const block = this.chunk(index);
      const inside = cursor - index * this.chunkSize;
      const take = Math.min(end - cursor, block.length - inside);
      block.copy(output, written, inside, inside + take);
      cursor += take;
      written += take;
    }
    return output;
  }
}

const sourceArg = process.argv[2];
if (!sourceArg || !sourceArg.toLowerCase().endsWith('.pstsc')) {
  throw Error('E_EXPECTED_ENCRYPTED_ARCHIVE');
}
const archive = path.resolve(sourceArg);
let source;
try {
  const password = inputPassword();
  try { source = new EncryptedByteSource(archive, password); }
  finally { password.fill(0); }
} catch {
  // Prevent raw parser or decryptor errors from exposing mail/paths.
  process.stderr.write('E_VAULT_OPEN\n');
  process.exit(61);
}
const original = PSTFile.prototype.readSync;
if (typeof original !== 'function') {
  source.close();
  process.stderr.write('E_UNSUPPORTED_PARSER_API\n');
  process.exit(62);
}
PSTFile.prototype.readSync = function (buf, length, position) {
  if (typeof this._pstFilename === 'string' && path.resolve(this._pstFilename) === archive) {
    const contents = source.readAt(position, length);
    contents.copy(buf, 0);
    return contents.length;
  }
  return original.call(this, buf, length, position);
};
process.on('exit', () => { if (source) source.close(); });

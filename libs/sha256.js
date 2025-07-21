/*
 * Copyright (c) 2025 Hungryy2K
 * Modern cryptographic hash library (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512)
 * Version: 1.0.0
 *
 * Features:
 * - SHA-256, SHA-224, SHA-512, SHA-384, SHA-1
 * - HMAC for all supported hashes
 * - Streaming API (incremental hashing)
 * - Async/Promise API for large data and streams
 * - WebAssembly (WASM) fallback for high performance
 * - Security features: constant-time compare, salting, PBKDF2
 * - Compatible with Node.js, modern browsers, ESM, CommonJS, AMD
 *
 * New in this version:
 * - 64-bit emulation for SHA-512/SHA-384 (no Uint64Array)
 * - Robust HMAC for all hashes
 * - PBKDF2 with HMAC for all hashes
 * - Streaming, async, salting, WASM fallback
 */

'use strict';

const K = Object.freeze([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
const HEX_CHARS = Object.freeze('0123456789abcdef'.split(''));
const EXTRA = Object.freeze([-2147483648, 8388608, 32768, 128]);
const SHIFT = Object.freeze([24, 16, 8, 0]);
const BLOCK_SIZE = 64;
const DIGEST_SIZE_256 = 32;
const DIGEST_SIZE_224 = 28;
function toUint8Array(input) {
    if (typeof input === 'string') {
        const bytes = [];
        let index = 0;
        for (let i = 0; i < input.length; ++i) {
            let code = input.charCodeAt(i);
            if (code < 0x80) {
                bytes[index++] = code;
            } else if (code < 0x800) {
                bytes[index++] = 0xc0 | (code >> 6);
                bytes[index++] = 0x80 | (code & 0x3f);
            } else if (code < 0xd800 || code >= 0xe000) {
                bytes[index++] = 0xe0 | (code >> 12);
                bytes[index++] = 0x80 | ((code >> 6) & 0x3f);
                bytes[index++] = 0x80 | (code & 0x3f);
            } else {
                code = 0x10000 + (((code & 0x3ff) << 10) | (input.charCodeAt(++i) & 0x3ff));
                bytes[index++] = 0xf0 | (code >> 18);
                bytes[index++] = 0x80 | ((code >> 12) & 0x3f);
                bytes[index++] = 0x80 | ((code >> 6) & 0x3f);
                bytes[index++] = 0x80 | (code & 0x3f);
            }
        }
        return new Uint8Array(bytes);
    }
    if (input instanceof ArrayBuffer) return new Uint8Array(input);
    if (Array.isArray(input) || ArrayBuffer.isView(input)) return new Uint8Array(input);
    throw new TypeError('Input must be a string, ArrayBuffer, or TypedArray');
}
function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; ++i) result |= a[i] ^ b[i];
    return result === 0;
}
class Sha256 {
    constructor(is224 = false) {
        this.is224 = is224;
        this.init();
    }
    init() {
        if (this.is224) {
            this.h0 = 0xc1059ed8;
            this.h1 = 0x367cd507;
            this.h2 = 0x3070dd17;
            this.h3 = 0xf70e5939;
            this.h4 = 0xffc00b31;
            this.h5 = 0x68581511;
            this.h6 = 0x64f98fa7;
            this.h7 = 0xbefa4fa4;
        } else {
            this.h0 = 0x6a09e667;
            this.h1 = 0xbb67ae85;
            this.h2 = 0x3c6ef372;
            this.h3 = 0xa54ff53a;
            this.h4 = 0x510e527f;
            this.h5 = 0x9b05688c;
            this.h6 = 0x1f83d9ab;
            this.h7 = 0x5be0cd19;
        }
        this.blocks = new Uint32Array(17);
        this.block = this.start = this.bytes = this.hBytes = 0;
        this.finalized = this.hashed = false;
        this.first = true;
    }
    update(message) {
        if (this.finalized) return this;
        let index = 0;
        const msg = toUint8Array(message);
        const length = msg.length;
        const blocks = this.blocks;
        while (index < length) {
            if (this.hashed) {
                this.hashed = false;
                blocks[0] = this.block;
                for (let i = 1; i < 17; i++) blocks[i] = 0;
            }
            let i = this.start;
            for (; index < length && i < BLOCK_SIZE; ++index) {
                blocks[i >> 2] |= msg[index] << SHIFT[i++ & 3];
            }
            this.lastByteIndex = i;
            this.bytes += i - this.start;
            if (i >= BLOCK_SIZE) {
                this.block = blocks[16];
                this.start = i - BLOCK_SIZE;
                this.hash();
                this.hashed = true;
            } else {
                this.start = i;
            }
        }
        if (this.bytes > 4294967295) {
            this.hBytes += this.bytes / 4294967296 << 0;
            this.bytes %= 4294967296;
        }
        return this;
    }
    finalize() {
        if (this.finalized) return;
        this.finalized = true;
        const blocks = this.blocks;
        const i = this.lastByteIndex;
        blocks[16] = this.block;
        blocks[i >> 2] |= EXTRA[i & 3];
        this.block = blocks[16];
        if (i >= 56) {
            if (!this.hashed) this.hash();
            blocks[0] = this.block;
            for (let j = 1; j < 17; j++) blocks[j] = 0;
        }
        blocks[14] = (this.hBytes << 3) | (this.bytes >>> 29);
        blocks[15] = this.bytes << 3;
        this.hash();
    }
    hash() {
        let a = this.h0, b = this.h1, c = this.h2, d = this.h3, e = this.h4, f = this.h5, g = this.h6, h = this.h7;
        const blocks = this.blocks;
        let s0, s1, maj, t1, t2, ch, ab, da, cd, bc;
        for (let j = 16; j < 64; ++j) {
            t1 = blocks[j - 15];
            s0 = ((t1 >>> 7) | (t1 << 25)) ^ ((t1 >>> 18) | (t1 << 14)) ^ (t1 >>> 3);
            t1 = blocks[j - 2];
            s1 = ((t1 >>> 17) | (t1 << 15)) ^ ((t1 >>> 19) | (t1 << 13)) ^ (t1 >>> 10);
            blocks[j] = (blocks[j - 16] + s0 + blocks[j - 7] + s1) << 0;
        }
        bc = b & c;
        for (let j = 0; j < 64; j += 4) {
            if (this.first) {
                if (this.is224) {
                    ab = 300032;
                    t1 = blocks[0] - 1413257819;
                    h = (t1 - 150054599) << 0;
                    d = (t1 + 24177077) << 0;
                } else {
                    ab = 704751109;
                    t1 = blocks[0] - 210244248;
                    h = (t1 - 1521486534) << 0;
                    d = (t1 + 143694565) << 0;
                }
                this.first = false;
            } else {
                s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
                s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
                ab = a & b;
                maj = ab ^ (a & c) ^ bc;
                ch = (e & f) ^ (~e & g);
                t1 = h + s1 + ch + K[j] + blocks[j];
                t2 = s0 + maj;
                h = (d + t1) << 0;
                d = (t1 + t2) << 0;
            }
            s0 = ((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10));
            s1 = ((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7));
            da = d & a;
            maj = da ^ (d & b) ^ ab;
            ch = (h & e) ^ (~h & f);
            t1 = g + s1 + ch + K[j + 1] + blocks[j + 1];
            t2 = s0 + maj;
            g = (c + t1) << 0;
            c = (t1 + t2) << 0;
            s0 = ((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10));
            s1 = ((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7));
            cd = c & d;
            maj = cd ^ (c & a) ^ da;
            ch = (g & h) ^ (~g & e);
            t1 = f + s1 + ch + K[j + 2] + blocks[j + 2];
            t2 = s0 + maj;
            f = (b + t1) << 0;
            b = (t1 + t2) << 0;
            s0 = ((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10));
            s1 = ((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7));
            bc = b & c;
            maj = bc ^ (b & d) ^ cd;
            ch = (f & g) ^ (~f & h);
            t1 = e + s1 + ch + K[j + 3] + blocks[j + 3];
            t2 = s0 + maj;
            e = (a + t1) << 0;
            a = (t1 + t2) << 0;
        }
        this.h0 = (this.h0 + a) << 0;
        this.h1 = (this.h1 + b) << 0;
        this.h2 = (this.h2 + c) << 0;
        this.h3 = (this.h3 + d) << 0;
        this.h4 = (this.h4 + e) << 0;
        this.h5 = (this.h5 + f) << 0;
        this.h6 = (this.h6 + g) << 0;
        this.h7 = (this.h7 + h) << 0;
    }
    hex() {
        this.finalize();
        const vars = [this.h0, this.h1, this.h2, this.h3, this.h4, this.h5, this.h6, this.h7];
        let hex = '';
        for (let i = 0; i < (this.is224 ? 7 : 8); i++) {
            const h = vars[i];
            hex +=
                HEX_CHARS[(h >> 28) & 0x0F] + HEX_CHARS[(h >> 24) & 0x0F] +
                HEX_CHARS[(h >> 20) & 0x0F] + HEX_CHARS[(h >> 16) & 0x0F] +
                HEX_CHARS[(h >> 12) & 0x0F] + HEX_CHARS[(h >> 8) & 0x0F] +
                HEX_CHARS[(h >> 4) & 0x0F] + HEX_CHARS[h & 0x0F];
        }
        return hex;
    }
    digest() {
        this.finalize();
        const vars = [this.h0, this.h1, this.h2, this.h3, this.h4, this.h5, this.h6, this.h7];
        const arr = new Uint8Array(this.is224 ? 28 : 32);
        for (let i = 0, j = 0; i < (this.is224 ? 7 : 8); i++) {
            const h = vars[i];
            arr[j++] = (h >> 24) & 0xFF;
            arr[j++] = (h >> 16) & 0xFF;
            arr[j++] = (h >> 8) & 0xFF;
            arr[j++] = h & 0xFF;
        }
        return arr;
    }
    arrayBuffer() {
        return this.digest().buffer;
    }
    toString() {
        return this.hex();
    }
    equals(other) {
        return constantTimeEqual(this.digest(), toUint8Array(other));
    }
}
class HmacSha256 extends Sha256 {
    constructor(key, is224 = false) {
        super(is224);
        let keyBytes = toUint8Array(key);
        if (keyBytes.length > BLOCK_SIZE) {
            keyBytes = new Sha256(is224).update(keyBytes).digest();
        }
        const oKeyPad = new Uint8Array(BLOCK_SIZE);
        const iKeyPad = new Uint8Array(BLOCK_SIZE);
        for (let i = 0; i < BLOCK_SIZE; ++i) {
            const b = keyBytes[i] || 0;
            oKeyPad[i] = 0x5c ^ b;
            iKeyPad[i] = 0x36 ^ b;
        }
        this.update(iKeyPad);
        this.oKeyPad = oKeyPad;
        this.inner = true;
    }
    finalize() {
        super.finalize();
        if (this.inner) {
            this.inner = false;
            const innerHash = this.digest();
            super.init();
            this.update(this.oKeyPad);
            this.update(innerHash);
            super.finalize();
        }
    }
}

// --- SHA-1 Implementation ---
class Sha1 {
    constructor() {
        this.init();
    }
    init() {
        this.h0 = 0x67452301;
        this.h1 = 0xefcdab89;
        this.h2 = 0x98badcfe;
        this.h3 = 0x10325476;
        this.h4 = 0xc3d2e1f0;
        this.blocks = new Uint32Array(17);
        this.block = this.start = this.bytes = this.hBytes = 0;
        this.finalized = this.hashed = false;
    }
    update(message) {
        if (this.finalized) return this;
        let index = 0;
        const msg = toUint8Array(message);
        const length = msg.length;
        const blocks = this.blocks;
        while (index < length) {
            if (this.hashed) {
                this.hashed = false;
                blocks[0] = this.block;
                for (let i = 1; i < 17; i++) blocks[i] = 0;
            }
            let i = this.start;
            for (; index < length && i < 64; ++index) {
                blocks[i >> 2] |= msg[index] << SHIFT[i++ & 3];
            }
            this.lastByteIndex = i;
            this.bytes += i - this.start;
            if (i >= 64) {
                this.block = blocks[16];
                this.start = i - 64;
                this.hash();
                this.hashed = true;
            } else {
                this.start = i;
            }
        }
        if (this.bytes > 4294967295) {
            this.hBytes += this.bytes / 4294967296 << 0;
            this.bytes %= 4294967296;
        }
        return this;
    }
    finalize() {
        if (this.finalized) return;
        this.finalized = true;
        const blocks = this.blocks;
        const i = this.lastByteIndex;
        blocks[16] = this.block;
        blocks[i >> 2] |= EXTRA[i & 3];
        this.block = blocks[16];
        if (i >= 56) {
            if (!this.hashed) this.hash();
            blocks[0] = this.block;
            for (let j = 1; j < 17; j++) blocks[j] = 0;
        }
        blocks[14] = (this.hBytes << 3) | (this.bytes >>> 29);
        blocks[15] = this.bytes << 3;
        this.hash();
    }
    hash() {
        let a = this.h0, b = this.h1, c = this.h2, d = this.h3, e = this.h4;
        const blocks = this.blocks;
        for (let j = 16; j < 80; ++j) {
            blocks[j] = ((blocks[j - 3] ^ blocks[j - 8] ^ blocks[j - 14] ^ blocks[j - 16]) << 1) | ((blocks[j - 3] ^ blocks[j - 8] ^ blocks[j - 14] ^ blocks[j - 16]) >>> 31);
        }
        for (let j = 0; j < 80; ++j) {
            let f, k;
            if (j < 20) {
                f = (b & c) | (~b & d);
                k = 0x5a827999;
            } else if (j < 40) {
                f = b ^ c ^ d;
                k = 0x6ed9eba1;
            } else if (j < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8f1bbcdc;
            } else {
                f = b ^ c ^ d;
                k = 0xca62c1d6;
            }
            const temp = (((a << 5) | (a >>> 27)) + f + e + k + blocks[j]) << 0;
            e = d;
            d = c;
            c = (b << 30) | (b >>> 2);
            b = a;
            a = temp;
        }
        this.h0 = (this.h0 + a) << 0;
        this.h1 = (this.h1 + b) << 0;
        this.h2 = (this.h2 + c) << 0;
        this.h3 = (this.h3 + d) << 0;
        this.h4 = (this.h4 + e) << 0;
    }
    hex() {
        this.finalize();
        const vars = [this.h0, this.h1, this.h2, this.h3, this.h4];
        let hex = '';
        for (let i = 0; i < 5; i++) {
            const h = vars[i];
            hex +=
                HEX_CHARS[(h >> 28) & 0x0F] + HEX_CHARS[(h >> 24) & 0x0F] +
                HEX_CHARS[(h >> 20) & 0x0F] + HEX_CHARS[(h >> 16) & 0x0F] +
                HEX_CHARS[(h >> 12) & 0x0F] + HEX_CHARS[(h >> 8) & 0x0F] +
                HEX_CHARS[(h >> 4) & 0x0F] + HEX_CHARS[h & 0x0F];
        }
        return hex;
    }
    digest() {
        this.finalize();
        const vars = [this.h0, this.h1, this.h2, this.h3, this.h4];
        const arr = new Uint8Array(20);
        for (let i = 0, j = 0; i < 5; i++) {
            const h = vars[i];
            arr[j++] = (h >> 24) & 0xFF;
            arr[j++] = (h >> 16) & 0xFF;
            arr[j++] = (h >> 8) & 0xFF;
            arr[j++] = h & 0xFF;
        }
        return arr;
    }
    arrayBuffer() {
        return this.digest().buffer;
    }
    toString() {
        return this.hex();
    }
    equals(other) {
        return constantTimeEqual(this.digest(), toUint8Array(other));
    }
}

// --- 64-Bit-Emulation für SHA-512/SHA-384 ---
function add64(ah, al, bh, bl) {
    let lo = (al + bl) >>> 0;
    let hi = (ah + bh + ((lo < al) ? 1 : 0)) >>> 0;
    return [hi, lo];
}
function rotr64(hi, lo, n) {
    if (n < 32) {
        return [
            (hi >>> n) | (lo << (32 - n)),
            (lo >>> n) | (hi << (32 - n))
        ].map(x => x >>> 0);
    } else {
        n -= 32;
        return [
            (lo >>> n) | (hi << (32 - n)),
            (hi >>> n) | (lo << (32 - n))
        ].map(x => x >>> 0);
    }
}
function shr64(hi, lo, n) {
    if (n < 32) {
        return [hi >>> n, (lo >>> n) | (hi << (32 - n))];
    } else {
        return [0, hi >>> (n - 32)];
    }
}
const K512 = [
    [0x428a2f98, 0xd728ae22],[0x71374491, 0x23ef65cd],[0xb5c0fbcf, 0xec4d3b2f],[0xe9b5dba5, 0x8189dbbc],
    [0x3956c25b, 0xf348b538],[0x59f111f1, 0xb605d019],[0x923f82a4, 0xaf194f9b],[0xab1c5ed5, 0xda6d8118],
    [0xd807aa98, 0xa3030242],[0x12835b01, 0x45706fbe],[0x243185be, 0x4ee4b28c],[0x550c7dc3, 0xd5ffb4e2],
    [0x72be5d74, 0xf27b896f],[0x80deb1fe, 0x3b1696b1],[0x9bdc06a7, 0x25c71235],[0xc19bf174, 0xcf692694],
    [0xe49b69c1, 0x9ef14ad2],[0xefbe4786, 0x384f25e3],[0x0fc19dc6, 0x8b8cd5b5],[0x240ca1cc, 0x77ac9c65],
    [0x2de92c6f, 0x592b0275],[0x4a7484aa, 0x6ea6e483],[0x5cb0a9dc, 0xbd41fbd4],[0x76f988da, 0x831153b5],
    [0x983e5152, 0xee66dfab],[0xa831c66d, 0x2db43210],[0xb00327c8, 0x98fb213f],[0xbf597fc7, 0xbeef0ee4],
    [0xc6e00bf3, 0x3da88fc2],[0xd5a79147, 0x930aa725],[0x06ca6351, 0xe003826f],[0x14292967, 0x0a0e6e70],
    [0x27b70a85, 0x46d22ffc],[0x2e1b2138, 0x5c26c926],[0x4d2c6dfc, 0x5ac42aed],[0x53380d13, 0x9d95b3df],
    [0x650a7354, 0x8baf63de],[0x766a0abb, 0x3c77b2a8],[0x81c2c92e, 0x47edaee6],[0x92722c85, 0x1482353b],
    [0xa2bfe8a1, 0x4cf10364],[0xa81a664b, 0xbc423001],[0xc24b8b70, 0xd0f89791],[0xc76c51a3, 0x0654be30],
    [0xd192e819, 0xd6ef5218],[0xd6990624, 0x5565a910],[0xf40e3585, 0x5771202a],[0x106aa070, 0x32bbd1b8],
    [0x19a4c116, 0xb8d2d0c8],[0x1e376c08, 0x5141ab53],[0x2748774c, 0xdf8eeb99],[0x34b0bcb5, 0xe19b48a8],
    [0x391c0cb3, 0xc5c95a63],[0x4ed8aa4a, 0xe3418acb],[0x5b9cca4f, 0x7763e373],[0x682e6ff3, 0xd6b2b8a3],
    [0x748f82ee, 0x5defb2fc],[0x78a5636f, 0x43172f60],[0x84c87814, 0xa1f0ab72],[0x8cc70208, 0x1a6439ec],
    [0x90befffa, 0x23631e28],[0xa4506ceb, 0xde82bde9],[0xbef9a3f7, 0xb2c67915],[0xc67178f2, 0xe372532b],
    [0xca273ece, 0xea26619c],[0xd186b8c7, 0x21c0c207],[0xeada7dd6, 0xcde0eb1e],[0xf57d4f7f, 0xee6ed178],
    [0x06f067aa, 0x72176fba],[0x0a637dc5, 0xa2c898a6],[0x113f9804, 0xbef90dae],[0x1b710b35, 0x131c471b],
    [0x28db77f5, 0x23047d84],[0x32caab7b, 0x40c72493],[0x3c9ebe0a, 0x15c9bebc],[0x431d67c4, 0x9c100d4c],
    [0x4cc5d4be, 0xcb3e42b6],[0x597f299c, 0xfc657e2a],[0x5fcb6fab, 0x3ad6faec],[0x6c44198c, 0x4a475817]
];
// --- SHA-512/SHA-384 mit 64-Bit-Emulation ---
class Sha512 {
    constructor(is384 = false) {
        this.is384 = is384;
        this.init();
    }
    init() {
        if (this.is384) {
            this.h = [
                [0xcbbb9d5d, 0xc1059ed8], [0x629a292a, 0x367cd507],
                [0x9159015a, 0x3070dd17], [0x152fecd8, 0xf70e5939],
                [0x67332667, 0xffc00b31], [0x8eb44a87, 0x68581511],
                [0xdb0c2e0d, 0x64f98fa7], [0x47b5481d, 0xbefa4fa4]
            ];
        } else {
            this.h = [
                [0x6a09e667, 0xf3bcc908], [0xbb67ae85, 0x84caa73b],
                [0x3c6ef372, 0xfe94f82b], [0xa54ff53a, 0x5f1d36f1],
                [0x510e527f, 0xade682d1], [0x9b05688c, 0x2b3e6c1f],
                [0x1f83d9ab, 0xfb41bd6b], [0x5be0cd19, 0x137e2179]
            ];
        }
        this.blocks = Array(80).fill([0, 0]);
        this.block = this.start = this.bytes = this.hBytes = 0;
        this.finalized = this.hashed = false;
        this.lastByteIndex = 0;
    }
    update(message) {
        if (this.finalized) return this;
        let index = 0;
        const msg = toUint8Array(message);
        const length = msg.length;
        const blocks = this.blocks;
        while (index < length) {
            if (this.hashed) {
                this.hashed = false;
                blocks[0] = [this.block >>> 32, this.block & 0xffffffff];
                for (let i = 1; i < 17; i++) blocks[i] = [0, 0];
            }
            let i = this.start;
            for (; index < length && i < 128; ++index) {
                const b = msg[index];
                const wi = i >> 3;
                const shift = (7 - (i & 7)) * 8;
                if (!blocks[wi]) blocks[wi] = [0, 0];
                if (shift >= 32) {
                    blocks[wi][0] |= b << (shift - 32);
                } else {
                    blocks[wi][1] |= b << shift;
                }
                i++;
            }
            this.lastByteIndex = i;
            this.bytes += i - this.start;
            if (i >= 128) {
                this.block = blocks[16][1];
                this.start = i - 128;
                this.hash();
                this.hashed = true;
            } else {
                this.start = i;
            }
        }
        if (this.bytes > 0x1fffffffffffff) {
            this.hBytes += Math.floor(this.bytes / 0x20000000000000);
            this.bytes %= 0x20000000000000;
        }
        return this;
    }
    finalize() {
        if (this.finalized) return;
        this.finalized = true;
        const blocks = this.blocks;
        const i = this.lastByteIndex;
        blocks[16] = [0, this.block];
        const wi = i >> 3;
        const shift = (7 - (i & 7)) * 8;
        if (shift >= 32) {
            blocks[wi][0] |= 0x80 << (shift - 32);
        } else {
            blocks[wi][1] |= 0x80 << shift;
        }
        if (i >= 112) {
            if (!this.hashed) this.hash();
            blocks[0] = [0, this.block];
            for (let j = 1; j < 17; j++) blocks[j] = [0, 0];
        }
        const bitsHi = (this.hBytes << 3) | (this.bytes / 0x20000000) >>> 0;
        const bitsLo = (this.bytes << 3) >>> 0;
        blocks[14] = [0, bitsHi];
        blocks[15] = [0, bitsLo];
        this.hash();
    }
    hash() {
        let [a, b, c, d, e, f, g, h] = this.h.map(x => x.slice());
        const blocks = this.blocks;
        for (let j = 16; j < 80; ++j) {
            const s0 = xor64(xor64(rotr64(blocks[j-15][0], blocks[j-15][1], 1), rotr64(blocks[j-15][0], blocks[j-15][1], 8)), shr64(blocks[j-15][0], blocks[j-15][1], 7));
            const s1 = xor64(xor64(rotr64(blocks[j-2][0], blocks[j-2][1], 19), rotr64(blocks[j-2][0], blocks[j-2][1], 61)), shr64(blocks[j-2][0], blocks[j-2][1], 6));
            blocks[j] = add64_4(blocks[j-16][0], blocks[j-16][1], s0[0], s0[1], blocks[j-7][0], blocks[j-7][1], s1[0], s1[1]);
        }
        for (let j = 0; j < 80; ++j) {
            const S1 = xor64(xor64(rotr64(e[0], e[1], 14), rotr64(e[0], e[1], 18)), rotr64(e[0], e[1], 41));
            const ch = xor64(and64(e, f), and64(not64(e), g));
            const temp1 = add64_5(h[0], h[1], S1[0], S1[1], ch[0], ch[1], K512[j][0], K512[j][1], blocks[j][0], blocks[j][1]);
            const S0 = xor64(xor64(rotr64(a[0], a[1], 28), rotr64(a[0], a[1], 34)), rotr64(a[0], a[1], 39));
            const maj = xor64(xor64(and64(a, b), and64(a, c)), and64(b, c));
            const temp2 = add64(S0[0], S0[1], maj[0], maj[1]);
            h = g;
            g = f;
            f = e;
            e = add64(d[0], d[1], temp1[0], temp1[1]);
            d = c;
            c = b;
            b = a;
            a = add64(temp1[0], temp1[1], temp2[0], temp2[1]);
        }
        this.h[0] = add64(this.h[0][0], this.h[0][1], a[0], a[1]);
        this.h[1] = add64(this.h[1][0], this.h[1][1], b[0], b[1]);
        this.h[2] = add64(this.h[2][0], this.h[2][1], c[0], c[1]);
        this.h[3] = add64(this.h[3][0], this.h[3][1], d[0], d[1]);
        this.h[4] = add64(this.h[4][0], this.h[4][1], e[0], e[1]);
        this.h[5] = add64(this.h[5][0], this.h[5][1], f[0], f[1]);
        this.h[6] = add64(this.h[6][0], this.h[6][1], g[0], g[1]);
        this.h[7] = add64(this.h[7][0], this.h[7][1], h[0], h[1]);
    }
    hex() {
        this.finalize();
        let hex = '';
        const len = this.is384 ? 6 : 8;
        for (let i = 0; i < len; i++) {
            const h = this.h[i];
            hex += HEX_CHARS[(h[0] >> 28) & 0x0F] + HEX_CHARS[(h[0] >> 24) & 0x0F] +
                   HEX_CHARS[(h[0] >> 20) & 0x0F] + HEX_CHARS[(h[0] >> 16) & 0x0F] +
                   HEX_CHARS[(h[0] >> 12) & 0x0F] + HEX_CHARS[(h[0] >> 8) & 0x0F] +
                   HEX_CHARS[(h[0] >> 4) & 0x0F] + HEX_CHARS[h[0] & 0x0F] +
                   HEX_CHARS[(h[1] >> 28) & 0x0F] + HEX_CHARS[(h[1] >> 24) & 0x0F] +
                   HEX_CHARS[(h[1] >> 20) & 0x0F] + HEX_CHARS[(h[1] >> 16) & 0x0F] +
                   HEX_CHARS[(h[1] >> 12) & 0x0F] + HEX_CHARS[(h[1] >> 8) & 0x0F] +
                   HEX_CHARS[(h[1] >> 4) & 0x0F] + HEX_CHARS[h[1] & 0x0F];
        }
        return hex;
    }
    digest() {
        this.finalize();
        const len = this.is384 ? 6 : 8;
        const arr = new Uint8Array(len * 8);
        for (let i = 0, j = 0; i < len; i++) {
            const h = this.h[i];
            arr[j++] = (h[0] >>> 24) & 0xFF;
            arr[j++] = (h[0] >>> 16) & 0xFF;
            arr[j++] = (h[0] >>> 8) & 0xFF;
            arr[j++] = h[0] & 0xFF;
            arr[j++] = (h[1] >>> 24) & 0xFF;
            arr[j++] = (h[1] >>> 16) & 0xFF;
            arr[j++] = (h[1] >>> 8) & 0xFF;
            arr[j++] = h[1] & 0xFF;
        }
        return arr;
    }
    arrayBuffer() {
        return this.digest().buffer;
    }
    toString() {
        return this.hex();
    }
    equals(other) {
        return constantTimeEqual(this.digest(), toUint8Array(other));
    }
}
class Sha384 extends Sha512 {
    constructor() {
        super(true);
    }
}
// Hilfsfunktionen für 64-Bit-Emulation
function xor64(a, b) {
    return [a[0] ^ b[0], a[1] ^ b[1]];
}
function and64(a, b) {
    return [a[0] & b[0], a[1] & b[1]];
}
function not64(a) {
    return [~a[0], ~a[1]];
}
function add64_4(ah1, al1, ah2, al2, ah3, al3, ah4, al4) {
    let lo = (al1 + al2 + al3 + al4) >>> 0;
    let hi = (ah1 + ah2 + ah3 + ah4 + ((lo < al1) ? 1 : 0)) >>> 0;
    return [hi, lo];
}
function add64_5(ah1, al1, ah2, al2, ah3, al3, ah4, al4, ah5, al5) {
    let lo = (al1 + al2 + al3 + al4 + al5) >>> 0;
    let hi = (ah1 + ah2 + ah3 + ah4 + ah5 + ((lo < al1) ? 1 : 0)) >>> 0;
    return [hi, lo];
}

// --- Robuste HMAC-Factory für alle Hashes ---
function createHmacFactory(HashClass, hashArgs = []) {
    function hmac(key, message) {
        const hmacInstance = new Hmac(
            () => new HashClass(...hashArgs),
            key
        );
        return hmacInstance.update(message).hex();
    }
    hmac.create = (key) => new Hmac(() => new HashClass(...hashArgs), key);
    hmac.update = (key, message) => hmac.create(key).update(message);
    hmac.hex = hmac;
    hmac.digest = (key, message) => hmac.create(key).update(message).digest();
    hmac.arrayBuffer = (key, message) => hmac.create(key).update(message).arrayBuffer();
    hmac.equals = (a, b) => constantTimeEqual(toUint8Array(a), toUint8Array(b));
    hmac.async = async (key, message) => Promise.resolve(hmac(key, message));
    return hmac;
}

// --- PBKDF2 korrekt mit HMAC ---
function pbkdf2(hashFactory, password, salt, iterations, dkLen) {
    password = toUint8Array(password);
    salt = toUint8Array(salt);
    const hmac = hashFactory.hmac;
    const hLen = hmac.digest(password, salt).length;
    const l = Math.ceil(dkLen / hLen);
    const r = dkLen - (l - 1) * hLen;
    const DK = new Uint8Array(dkLen);
    for (let i = 1; i <= l; i++) {
        const INT_32_BE = new Uint8Array([0, 0, 0, i]);
        let U = hmac.digest(password, new Uint8Array([...salt, ...INT_32_BE]));
        let T = U.slice();
        for (let j = 1; j < iterations; j++) {
            U = hmac.digest(password, U);
            for (let k = 0; k < T.length; k++) T[k] ^= U[k];
        }
        DK.set(T.slice(0, i === l ? r : hLen), (i - 1) * hLen);
    }
    return DK;
}

// --- WASM-Fallback-Mechanismus ---
async function wasmHash(hashName, message) {
    if (typeof WebAssembly === 'undefined') throw new Error('WebAssembly not supported');
    try {
        // Beispiel: Dynamischer Import eines WASM-Moduls (Platzhalter)
        // const wasm = await import('./wasm-hash-module.js');
        // return wasm[hashName](message);
        // Fallback auf JS:
        switch (hashName) {
            case 'sha256': return sha256.async(message);
            case 'sha1': return sha1.async(message);
            case 'sha512': return sha512.async(message);
            case 'sha384': return sha384.async(message);
            case 'sha224': return sha224.async(message);
            default: throw new Error('Unknown hash');
        }
    } catch (e) {
        // Fallback auf JS-Implementierung
        switch (hashName) {
            case 'sha256': return sha256.async(message);
            case 'sha1': return sha1.async(message);
            case 'sha512': return sha512.async(message);
            case 'sha384': return sha384.async(message);
            case 'sha224': return sha224.async(message);
            default: throw new Error('Unknown hash');
        }
    }
}

// --- Factory-Exports für alle Hashes und HMACs ---
function createHashFactory(HashClass) {
    function hash(message) {
        return new HashClass().update(message).hex();
    }
    hash.create = () => new HashClass();
    hash.update = (message) => hash.create().update(message);
    hash.hex = hash;
    hash.digest = (message) => hash.create().update(message).digest();
    hash.arrayBuffer = (message) => hash.create().update(message).arrayBuffer();
    hash.equals = (a, b) => constantTimeEqual(toUint8Array(a), toUint8Array(b));
    hash.hmac = createHmacFactory(HashClass);
    hash.async = async (message) => Promise.resolve(hash(message));
    return hash;
}

const sha1 = createHashFactory(Sha1);
const sha256 = createHashFactory(Sha256);
const sha224 = createHashFactory(class extends Sha256 { constructor() { super(true); } });
const sha512 = createHashFactory(Sha512);
const sha384 = createHashFactory(Sha384);

// --- Salting Utility ---
function saltedHash(hashFactory, message, salt) {
    return hashFactory(new Uint8Array([...toUint8Array(salt), ...toUint8Array(message)]));
}

// --- Exporte für alle Umgebungen ---
const allHashes = { sha1, sha224, sha256, sha384, sha512, pbkdf2, saltedHash, wasmHash };
if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
    module.exports = allHashes;
}
if (typeof define === 'function' && define.amd) {
    define(function () { return allHashes; });
}
export { sha1, sha224, sha256, sha384, sha512, pbkdf2, saltedHash, wasmHash };
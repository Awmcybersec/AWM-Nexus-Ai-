/**
 * Cryptographic & Tamper-Evident Hashing Utilities
 * Universal SHA-256 computation supporting both Node runtime and Browser environments
 */

export async function sha256(data: string): Promise<string> {
  // Try Node.js crypto if available
  try {
    if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      // Dynamic import to avoid bundling issues
      const nodeCrypto = await import('node:crypto');
      return nodeCrypto.createHash('sha256').update(data).digest('hex');
    }
  } catch {
    // Fall back to Web Crypto API
  }

  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Fallback simple deterministic FNV/SHA simulation if neither is available (pure JS fallback)
  return fallbackSha256(data);
}

export function syncSha256(data: string): string {
  try {
    if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const nodeCrypto = require('node:crypto');
      return nodeCrypto.createHash('sha256').update(data).digest('hex');
    }
  } catch {
    // Fall back
  }
  return fallbackSha256(data);
}

function fallbackSha256(ascii: string): string {
  function rightRotate(value: number, amount: number) {
    return (value >>> amount) | (value << (32 - amount));
  }

  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  const lengthProperty = 'length';
  let i = 0, j = 0;
  let result = '';

  const words: number[] = [];
  const asciiBitLength = ascii[lengthProperty] * 8;

  let hash = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0x0bef9a3f, 0xc67178f2
  ];

  const compositeLength = (asciiBitLength + 64 >>> 9 << 4) + 15;
  for (i = 0; i < compositeLength; i++) words[i] = 0;

  for (i = 0; i < ascii[lengthProperty]; i++) {
    words[i >> 2] |= (ascii.charCodeAt(i) & 0xff) << ((3 - (i % 4)) * 8);
  }
  words[i >> 2] |= 0x80 << ((3 - (i % 4)) * 8);
  words[compositeLength] = asciiBitLength;

  const w: number[] = new Array(64);
  for (i = 0; i < words[lengthProperty]; i += 16) {
    const [a, b, c, d, e, f, g, h] = hash;
    let [tempA, tempB, tempC, tempD, tempE, tempF, tempG, tempH] = [a, b, c, d, e, f, g, h];

    for (j = 0; j < 64; j++) {
      if (j < 16) {
        w[j] = words[j + i];
      } else {
        const gamma0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
        const gamma1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
        w[j] = (w[j - 16] + gamma0 + w[j - 7] + gamma1) | 0;
      }

      const s1 = rightRotate(tempE, 6) ^ rightRotate(tempE, 11) ^ rightRotate(tempE, 25);
      const ch = (tempE & tempF) ^ (~tempE & tempG);
      const temp1 = (tempH + s1 + ch + k[j] + w[j]) | 0;
      const s0 = rightRotate(tempA, 2) ^ rightRotate(tempA, 13) ^ rightRotate(tempA, 22);
      const maj = (tempA & tempB) ^ (tempA & tempC) ^ (tempB & tempC);
      const temp2 = (s0 + maj) | 0;

      tempH = tempG;
      tempG = tempF;
      tempF = tempE;
      tempE = (tempD + temp1) | 0;
      tempD = tempC;
      tempC = tempB;
      tempB = tempA;
      tempA = (temp1 + temp2) | 0;
    }

    hash = [
      (hash[0] + tempA) | 0,
      (hash[1] + tempB) | 0,
      (hash[2] + tempC) | 0,
      (hash[3] + tempD) | 0,
      (hash[4] + tempE) | 0,
      (hash[5] + tempF) | 0,
      (hash[6] + tempG) | 0,
      (hash[7] + tempH) | 0
    ];
  }

  for (i = 0; i < 8; i++) {
    for (j = 3; j >= 0; j--) {
      const b = (hash[i] >> (8 * j)) & 255;
      result += (b < 16 ? '0' : '') + b.toString(16);
    }
  }
  return result;
}

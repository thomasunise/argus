// Minimal QR code encoder: byte mode, error correction level L, versions 1 to 10, automatic mask.
// Enough for an otpauth:// provisioning URI. Returns a square boolean matrix or an SVG string.

const TOTAL = [26, 44, 70, 100, 134, 172, 196, 242, 292, 346];
const EC_PER_BLOCK = [7, 10, 15, 20, 26, 18, 20, 24, 30, 18];
const BLOCKS = [1, 1, 1, 1, 1, 2, 2, 2, 2, 4];
const ALIGN = [[], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();
const mul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);

function rsRemainder(data, degree) {
  let gen = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(gen.length + 1).fill(0);
    for (let j = 0; j < gen.length; j++) { next[j] ^= gen[j]; next[j + 1] ^= mul(gen[j], EXP[i]); }
    gen = next;
  }
  const rem = new Array(degree).fill(0);
  for (const byte of data) {
    const factor = byte ^ rem.shift();
    rem.push(0);
    for (let j = 0; j < degree; j++) rem[j] ^= mul(gen[j + 1], factor);
  }
  return rem;
}

function chooseVersion(length) {
  for (let v = 1; v <= 10; v++) {
    const dataBytes = TOTAL[v - 1] - EC_PER_BLOCK[v - 1] * BLOCKS[v - 1];
    const countBits = v < 10 ? 8 : 16;
    if (dataBytes * 8 >= 4 + countBits + length * 8) return v;
  }
  throw new Error('text too long for this QR encoder');
}

function encodeData(bytes, version) {
  const dataBytes = TOTAL[version - 1] - EC_PER_BLOCK[version - 1] * BLOCKS[version - 1];
  const bits = [];
  const push = (value, count) => { for (let i = count - 1; i >= 0; i--) bits.push((value >>> i) & 1); };
  push(4, 4);
  push(bytes.length, version < 10 ? 8 : 16);
  for (const b of bytes) push(b, 8);
  push(0, Math.min(4, dataBytes * 8 - bits.length));
  while (bits.length % 8) bits.push(0);
  const out = [];
  for (let i = 0; i < bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8).join(''), 2));
  for (let pad = 0xec; out.length < dataBytes; pad ^= 0xec ^ 0x11) out.push(pad);
  // split into blocks, compute ec, interleave
  const blocks = BLOCKS[version - 1];
  const ecLen = EC_PER_BLOCK[version - 1];
  const shortLen = Math.floor(dataBytes / blocks);
  const longBlocks = dataBytes % blocks;
  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;
  for (let b = 0; b < blocks; b++) {
    const len = shortLen + (b >= blocks - longBlocks ? 1 : 0);
    const chunk = out.slice(offset, offset + len);
    offset += len;
    dataBlocks.push(chunk);
    ecBlocks.push(rsRemainder(chunk, ecLen));
  }
  const result = [];
  for (let i = 0; i <= shortLen; i++) for (const block of dataBlocks) if (i < block.length) result.push(block[i]);
  for (let i = 0; i < ecLen; i++) for (const block of ecBlocks) result.push(block[i]);
  return result;
}

export function qrMatrix(text) {
  const bytes = Array.from(new TextEncoder().encode(text));
  const version = chooseVersion(bytes.length);
  const size = 17 + 4 * version;
  const modules = Array.from({ length: size }, () => new Array(size).fill(false));
  const isFunction = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, dark) => { modules[y][x] = dark; isFunction[y][x] = true; };

  const finder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx, y = cy + dy;
      if (x < 0 || y < 0 || x >= size || y >= size) continue;
      const dist = Math.max(Math.abs(dx), Math.abs(dy));
      set(x, y, dist !== 2 && dist !== 4);
    }
  };
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
  for (let i = 8; i < size - 8; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  const centers = ALIGN[version - 1];
  for (const cy of centers) for (const cx of centers) {
    const corner = (cx === 6 && cy === 6) || (cx === 6 && cy === centers[centers.length - 1]) || (cy === 6 && cx === centers[centers.length - 1]);
    if (corner) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  // reserve format and version areas
  for (let i = 0; i < 9; i++) { set(8, i, false); set(i, 8, false); }
  for (let i = 0; i < 8; i++) { set(size - 1 - i, 8, false); set(8, size - 1 - i, false); }
  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = ((bits >>> i) & 1) === 1;
      const a = size - 11 + (i % 3), b = Math.floor(i / 3);
      set(a, b, bit); set(b, a, bit);
    }
  }

  const codewords = encodeData(bytes, version);
  const bits = [];
  for (const cw of codewords) for (let i = 7; i >= 0; i--) bits.push((cw >>> i) & 1);
  let index = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
      const x = right - j;
      const upward = ((right + 1) & 2) === 0;
      const y = upward ? size - 1 - vert : vert;
      if (!isFunction[y][x] && index < bits.length) { modules[y][x] = bits[index] === 1; index++; }
    }
  }

  const MASKS = [
    (x, y) => (x + y) % 2 === 0, (x, y) => y % 2 === 0, (x) => x % 3 === 0, (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0, (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
    (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0, (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
  ];
  const applyMask = (mask) => { for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!isFunction[y][x] && MASKS[mask](x, y)) modules[y][x] = !modules[y][x]; };
  const drawFormat = (mask) => {
    const data = (1 << 3) | mask; // ECC L = 01
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const bits = ((data << 10) | rem) ^ 0x5412;
    const bit = (i) => ((bits >>> i) & 1) === 1;
    for (let i = 0; i <= 5; i++) set(8, i, bit(i));
    set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8));
    for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
    set(8, size - 8, true);
  };
  const penalty = () => {
    let score = 0;
    const run = (line) => {
      let total = 0;
      for (let i = 0; i < size;) { let j = i; while (j < size && line[j] === line[i]) j++; if (j - i >= 5) total += 3 + (j - i - 5); i = j; }
      return total;
    };
    for (let y = 0; y < size; y++) score += run(modules[y]);
    for (let x = 0; x < size; x++) score += run(modules.map((row) => row[x]));
    for (let y = 0; y < size - 1; y++) for (let x = 0; x < size - 1; x++) {
      const c = modules[y][x];
      if (c === modules[y][x + 1] && c === modules[y + 1][x] && c === modules[y + 1][x + 1]) score += 3;
    }
    const finderLike = (line) => {
      let total = 0;
      const text = line.map((d) => (d ? '1' : '0')).join('');
      for (const p of ['00001011101', '10111010000']) { let at = text.indexOf(p); while (at !== -1) { total += 40; at = text.indexOf(p, at + 1); } }
      return total;
    };
    for (let y = 0; y < size; y++) score += finderLike(modules[y]);
    for (let x = 0; x < size; x++) score += finderLike(modules.map((row) => row[x]));
    let dark = 0;
    for (const row of modules) for (const d of row) if (d) dark++;
    const total = size * size;
    score += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
    return score;
  };
  let best = 0, bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    applyMask(mask); drawFormat(mask);
    const score = penalty();
    if (score < bestScore) { bestScore = score; best = mask; }
    applyMask(mask);
  }
  applyMask(best); drawFormat(best);
  return modules;
}

export function qrSvg(text, { module = 4, margin = 2 } = {}) {
  const matrix = qrMatrix(text);
  const size = matrix.length;
  const dim = (size + margin * 2) * module;
  let path = '';
  matrix.forEach((row, y) => row.forEach((dark, x) => { if (dark) path += `M${(x + margin) * module} ${(y + margin) * module}h${module}v${module}h-${module}z`; }));
  return `<svg class="qr" width="${dim}" height="${dim}" viewBox="0 0 ${dim} ${dim}" role="img" aria-label="QR code" shape-rendering="crispEdges"><rect width="${dim}" height="${dim}" fill="#fff"/><path d="${path}" fill="#000"/></svg>`;
}

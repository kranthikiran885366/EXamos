// Pure JavaScript dependency-free QR Code Generator (ISO/IEC 18004 Byte Mode)
// Generates SVG QR codes for otpauth:// URIs and authenticator apps.

// Galois Field GF(256) with primitive polynomial 0x11d (285)
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(function initGF() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    EXP[i + 255] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
})();

function gfMul(x, y) {
  if (x === 0 || y === 0) return 0;
  return EXP[LOG[x] + LOG[y]];
}

function rsGeneratorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= gfMul(poly[j], EXP[i]);
      next[j + 1] ^= poly[j];
    }
    poly = Array.from(next);
  }
  return poly;
}

function rsComputeRemainder(data, poly) {
  const remainder = new Uint8Array(poly.length - 1);
  for (let i = 0; i < data.length; i++) {
    const factor = data[i] ^ remainder[0];
    for (let j = 0; j < remainder.length - 1; j++) {
      remainder[j] = remainder[j + 1] ^ gfMul(factor, poly[j + 1]);
    }
    remainder[remainder.length - 1] = gfMul(factor, poly[remainder.length]);
  }
  return Array.from(remainder);
}

// Version table for Level L/M (Data codewords, EC codewords, EC blocks)
// Level M is the industry standard for 2FA / Google Authenticator
const VERSIONS = [
  null,
  // v1: 21x21, 16 data, 10 ec, 1 block
  { version: 1, size: 21, totalCodewords: 26, dataCodewords: 16, ecPerBlock: 10, blocks: 1, align: [] },
  // v2: 25x25, 28 data, 16 ec, 1 block
  { version: 2, size: 25, totalCodewords: 44, dataCodewords: 28, ecPerBlock: 16, blocks: 1, align: [6, 18] },
  // v3: 29x29, 44 data, 26 ec, 1 block
  { version: 3, size: 29, totalCodewords: 70, dataCodewords: 44, ecPerBlock: 26, blocks: 1, align: [6, 22] },
  // v4: 33x33, 64 data, 18 ec, 2 blocks
  { version: 4, size: 33, totalCodewords: 100, dataCodewords: 64, ecPerBlock: 18, blocks: 2, align: [6, 26] },
  // v5: 37x37, 86 data, 24 ec, 2 blocks
  { version: 5, size: 37, totalCodewords: 134, dataCodewords: 86, ecPerBlock: 24, blocks: 2, align: [6, 30] },
  // v6: 41x41, 108 data, 16 ec, 4 blocks
  { version: 6, size: 41, totalCodewords: 172, dataCodewords: 108, ecPerBlock: 16, blocks: 4, align: [6, 34] },
  // v7: 45x45, 124 data, 18 ec, 4 blocks
  { version: 7, size: 45, totalCodewords: 196, dataCodewords: 124, ecPerBlock: 18, blocks: 4, align: [6, 22, 38] },
  // v8: 49x49, 154 data, 22 ec, 4 blocks
  { version: 8, size: 49, totalCodewords: 242, dataCodewords: 154, ecPerBlock: 22, blocks: 4, align: [6, 24, 42] },
  // v9: 53x53, 182 data, 22 ec, 5 blocks
  { version: 9, size: 53, totalCodewords: 292, dataCodewords: 182, ecPerBlock: 22, blocks: 5, align: [6, 26, 46] },
  // v10: 57x57, 216 data, 26 ec, 5 blocks
  { version: 10, size: 57, totalCodewords: 346, dataCodewords: 216, ecPerBlock: 26, blocks: 5, align: [6, 28, 50] },
];

function selectVersion(dataLen) {
  // Byte mode header: 4 bits mode (0100) + 8/16 bits length
  for (let v = 1; v < VERSIONS.length; v++) {
    const info = VERSIONS[v];
    const headerBits = 4 + (v <= 9 ? 8 : 16);
    const requiredBytes = Math.ceil((headerBits + dataLen * 8 + 4) / 8);
    if (requiredBytes <= info.dataCodewords) return info;
  }
  return VERSIONS[VERSIONS.length - 1];
}

export function generateQrMatrix(text) {
  const bytes = new TextEncoder().encode(text);
  const info = selectVersion(bytes.length);
  const size = info.size;

  // 1. Bit stream
  const bits = [];
  const addBits = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
  };

  // Byte mode indicator: 0100
  addBits(0b0100, 4);
  // Character count indicator
  addBits(bytes.length, info.version <= 9 ? 8 : 16);
  // Payload
  for (let i = 0; i < bytes.length; i++) addBits(bytes[i], 8);
  // Terminator: up to 4 zero bits
  const termLen = Math.min(4, info.dataCodewords * 8 - bits.length);
  addBits(0, termLen);
  // Pad to byte boundary
  while (bits.length % 8 !== 0) bits.push(0);
  // Pad bytes: alternating 0xEC, 0x11
  const padPatterns = [0xec, 0x11];
  let padIdx = 0;
  while (bits.length < info.dataCodewords * 8) {
    addBits(padPatterns[padIdx % 2], 8);
    padIdx++;
  }

  // Convert bits to data codewords
  const dataCodewords = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
    dataCodewords.push(byte);
  }

  // Divide into blocks and compute EC
  const numBlocks = info.blocks;
  const dataPerBlock = Math.floor(info.dataCodewords / numBlocks);
  const remainderData = info.dataCodewords % numBlocks;
  const poly = rsGeneratorPoly(info.ecPerBlock);

  const blockData = [];
  const blockEc = [];
  let offset = 0;
  for (let b = 0; b < numBlocks; b++) {
    const len = dataPerBlock + (b >= numBlocks - remainderData ? 1 : 0);
    const slice = dataCodewords.slice(offset, offset + len);
    offset += len;
    blockData.push(slice);
    blockEc.push(rsComputeRemainder(slice, poly));
  }

  // Interleave data codewords then EC codewords
  const finalCodewords = [];
  const maxDataLen = Math.max(...blockData.map((b) => b.length));
  for (let i = 0; i < maxDataLen; i++) {
    for (let b = 0; b < numBlocks; b++) {
      if (i < blockData[b].length) finalCodewords.push(blockData[b][i]);
    }
  }
  for (let i = 0; i < info.ecPerBlock; i++) {
    for (let b = 0; b < numBlocks; b++) {
      if (i < blockEc[b].length) finalCodewords.push(blockEc[b][i]);
    }
  }

  // 2. Initialize matrix
  // 0 = unset, 1 = white, 2 = black, 3 = reserved
  const matrix = Array.from({ length: size }, () => new Uint8Array(size));

  // Helper: place finder pattern
  const placeFinder = (row, col) => {
    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 7; c++) {
        const isBlack =
          r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4);
        matrix[row + r][col + c] = isBlack ? 2 : 1;
      }
    }
    // Separator
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        if (r >= 0 && r < 7 && c >= 0 && c < 7) continue;
        const nr = row + r;
        const nc = col + c;
        if (nr >= 0 && nr < size && nc >= 0 && nc < size) matrix[nr][nc] = 1;
      }
    }
  };

  placeFinder(0, 0);
  placeFinder(0, size - 7);
  placeFinder(size - 7, 0);

  // Timing patterns
  for (let i = 8; i < size - 8; i++) {
    matrix[6][i] = i % 2 === 0 ? 2 : 1;
    matrix[i][6] = i % 2 === 0 ? 2 : 1;
  }

  // Dark module
  matrix[4 * info.version + 9][8] = 2;

  // Alignment patterns
  if (info.align && info.align.length > 0) {
    const coords = info.align;
    for (let r = 0; r < coords.length; r++) {
      for (let c = 0; c < coords.length; c++) {
        const row = coords[r];
        const col = coords[c];
        // Skip finders
        if (
          (row === 6 && col === 6) ||
          (row === 6 && col === coords[coords.length - 1] && coords.length > 1) ||
          (row === coords[coords.length - 1] && col === 6 && coords.length > 1)
        )
          continue;
        for (let dr = -2; dr <= 2; dr++) {
          for (let dc = -2; dc <= 2; dc++) {
            const isBlack =
              Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0);
            matrix[row + dr][col + dc] = isBlack ? 2 : 1;
          }
        }
      }
    }
  }

  // Reserve format information areas
  for (let i = 0; i < 9; i++) {
    if (matrix[8][i] === 0) matrix[8][i] = 3;
    if (matrix[i][8] === 0) matrix[i][8] = 3;
    if (matrix[size - 1 - i][8] === 0) matrix[size - 1 - i][8] = 3;
    if (matrix[8][size - 1 - i] === 0) matrix[8][size - 1 - i] = 3;
  }

  // 3. Place data bits using upward/downward snake
  let finalBits = [];
  for (let byte of finalCodewords) {
    for (let b = 7; b >= 0; b--) finalBits.push((byte >> b) & 1);
  }

  let bitIdx = 0;
  let upward = true;
  for (let rightCol = size - 1; rightCol > 0; rightCol -= 2) {
    if (rightCol === 6) rightCol--; // Skip vertical timing pattern
    const cols = [rightCol, rightCol - 1];
    const rowRange = upward
      ? Array.from({ length: size }, (_, i) => size - 1 - i)
      : Array.from({ length: size }, (_, i) => i);

    for (let row of rowRange) {
      for (let col of cols) {
        if (matrix[row][col] === 0) {
          const bit = bitIdx < finalBits.length ? finalBits[bitIdx++] : 0;
          matrix[row][col] = bit === 1 ? 2 : 1;
        }
      }
    }
    upward = !upward;
  }

  // 4. Apply Mask Pattern 0: (row + col) % 2 === 0
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      // Don't mask function patterns (finders, separators, timing, alignment, dark module, format area)
      const isFunction =
        (r <= 8 && c <= 8) ||
        (r <= 8 && c >= size - 8) ||
        (r >= size - 8 && c <= 8) ||
        r === 6 ||
        c === 6 ||
        matrix[r][c] === 3;
      if (!isFunction) {
        if ((r + c) % 2 === 0) {
          matrix[r][c] = matrix[r][c] === 2 ? 1 : 2;
        }
      }
    }
  }

  // 5. Format info for Mask 0 and EC Level M (0b00, mask 0b000 -> 0b00000)
  // Format string with BCH (15, 5) code for (Level M, Mask 0): 0x5412 ^ 0x5412 = 0x0000
  // Precomputed format bits for Level M, Mask 0: 101010000010010
  const formatBits = [1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0];
  // Top-left
  matrix[8][0] = formatBits[0] ? 2 : 1;
  matrix[8][1] = formatBits[1] ? 2 : 1;
  matrix[8][2] = formatBits[2] ? 2 : 1;
  matrix[8][3] = formatBits[3] ? 2 : 1;
  matrix[8][4] = formatBits[4] ? 2 : 1;
  matrix[8][5] = formatBits[5] ? 2 : 1;
  matrix[8][7] = formatBits[6] ? 2 : 1;
  matrix[8][8] = formatBits[7] ? 2 : 1;
  matrix[7][8] = formatBits[8] ? 2 : 1;
  matrix[5][8] = formatBits[9] ? 2 : 1;
  matrix[4][8] = formatBits[10] ? 2 : 1;
  matrix[3][8] = formatBits[11] ? 2 : 1;
  matrix[2][8] = formatBits[12] ? 2 : 1;
  matrix[1][8] = formatBits[13] ? 2 : 1;
  matrix[0][8] = formatBits[14] ? 2 : 1;

  // Split around top-right and bottom-left
  for (let i = 0; i < 7; i++) matrix[size - 1 - i][8] = formatBits[i] ? 2 : 1;
  for (let i = 0; i < 8; i++) matrix[8][size - 8 + i] = formatBits[7 + i] ? 2 : 1;

  return matrix;
}

export default function QrCodeSvg({
  value,
  size = 200,
  darkColor = '#000000',
  lightColor = '#ffffff',
  margin = 4,
  className = '',
}) {
  if (!value) return null;
  const matrix = generateQrMatrix(value);
  const matrixSize = matrix.length;
  const totalSize = matrixSize + margin * 2;

  const rects = [];
  for (let r = 0; r < matrixSize; r++) {
    for (let c = 0; c < matrixSize; c++) {
      if (matrix[r][c] === 2) {
        rects.push(
          <rect
            key={`${r}-${c}`}
            x={c + margin}
            y={r + margin}
            width={1}
            height={1}
            fill={darkColor}
          />
        );
      }
    }
  }

  return (
    <div
      className={className}
      style={{
        display: 'inline-block',
        padding: '10px',
        backgroundColor: lightColor,
        borderRadius: '8px',
        boxShadow: '0 4px 14px rgba(0,0,0,0.25)',
      }}
    >
      <svg
        viewBox={`0 0 ${totalSize} ${totalSize}`}
        width={size}
        height={size}
        shapeRendering="crispEdges"
        style={{ display: 'block' }}
      >
        <rect width={totalSize} height={totalSize} fill={lightColor} />
        {rects}
      </svg>
    </div>
  );
}

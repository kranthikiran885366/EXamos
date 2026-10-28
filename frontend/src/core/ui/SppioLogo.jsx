// SPPIO / Open Aperture Brand Mark Component
// Derived from C:\Users\krant\Downloads\SPPIO_Complete_Identity\SPPIO_Identity\build_identity.py
// Colors:
//   Aubergine (Ink):   #302337 (RGB 48, 35, 55)
//   Copper (Accent):   #B54F34 (RGB 181, 79, 52)
//   Porcelain (Paper): #F6F2ED (RGB 246, 242, 237)
//   White:             #FFFFFF

const ICON_PATHS = [
  'M 0 30 L 30 0 L 78 0 L 60 18 L 36 18 L 18 36 L 18 72 L 0 90 Z',
  'M 28 100 L 46 82 L 70 82 L 82 70 L 82 28 L 100 10 L 100 76 L 76 100 Z',
];

const LETTER_PATHS = [
  // S
  { d: 'M 70 8 C 58 1 49 -2 36 -2 C 14 -2 1 10 1 27 C 1 43 12 51 32 57 L 42 60 C 54 64 59 69 59 76 C 59 84 51 89 40 89 C 27 89 17 84 7 77 L 0 91 C 12 100 25 104 40 104 C 63 104 78 93 78 75 C 78 59 68 50 49 44 L 37 40 C 24 36 19 32 19 25 C 19 17 26 12 37 12 C 47 12 56 16 64 21 Z', x: 0 },
  // P
  { d: 'M 0 0 L 34 0 C 62 0 79 13 79 35 C 79 57 62 71 34 71 L 18 71 L 18 100 L 0 100 Z M 18 16 L 18 55 L 33 55 C 51 55 61 48 61 35 C 61 22 51 16 33 16 Z', x: 96 },
  // P
  { d: 'M 0 0 L 34 0 C 62 0 79 13 79 35 C 79 57 62 71 34 71 L 18 71 L 18 100 L 0 100 Z M 18 16 L 18 55 L 33 55 C 51 55 61 48 61 35 C 61 22 51 16 33 16 Z', x: 194 },
  // I
  { d: 'M 0 0 L 18 0 L 18 91 L 9 100 L 0 100 Z', x: 295 },
  // O
  { d: 'M 46 -2 C 18 -2 0 19 0 50 C 0 81 18 102 46 102 C 74 102 92 81 92 50 C 92 19 74 -2 46 -2 Z M 46 15 C 63 15 74 28 74 50 C 74 72 63 85 46 85 C 29 85 18 72 18 50 C 18 28 29 15 46 15 Z', x: 337 },
];

export function SppioSymbol({ size = 32, accent = '#B54F34', className = '' }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 140 140"
      className={className}
      role="img"
      aria-label="SPPIO Aperture"
    >
      <g transform="translate(20 20)">
        {ICON_PATHS.map((p, idx) => (
          <path key={idx} d={p} fill={accent} />
        ))}
      </g>
    </svg>
  );
}

export default function SppioLogo({
  width = 180,
  height,
  accent = '#B54F34',
  ink = '#302337',
  variant = 'horizontal', // 'horizontal' | 'symbol' | 'stacked'
  className = '',
}) {
  if (variant === 'symbol') {
    return <SppioSymbol size={width} accent={accent} className={className} />;
  }

  if (variant === 'stacked') {
    const computedHeight = height || Math.round((width * 300) / 469);
    return (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width={width}
        height={computedHeight}
        viewBox="0 0 469 300"
        className={className}
        role="img"
        aria-label="SPPIO"
      >
        <g transform="translate(184 20)">
          {ICON_PATHS.map((p, idx) => (
            <path key={idx} d={p} fill={accent} />
          ))}
        </g>
        <g transform="translate(20 166)">
          {LETTER_PATHS.map((l, idx) => (
            <path
              key={idx}
              transform={`translate(${l.x} 0)`}
              d={l.d}
              fill={ink}
              fillRule="evenodd"
            />
          ))}
        </g>
      </svg>
    );
  }

  // Default horizontal master (625 x 160)
  const computedHeight = height || Math.round((width * 160) / 625);
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={width}
      height={computedHeight}
      viewBox="0 0 625 160"
      className={className}
      role="img"
      aria-label="SPPIO"
    >
      <g transform="translate(20 20)">
        {ICON_PATHS.map((p, idx) => (
          <path key={idx} d={p} fill={accent} />
        ))}
      </g>
      <g transform="translate(166 38)">
        {LETTER_PATHS.map((l, idx) => (
          <path
            key={idx}
            transform={`translate(${l.x} 0)`}
            d={l.d}
            fill={ink}
            fillRule="evenodd"
          />
        ))}
      </g>
    </svg>
  );
}

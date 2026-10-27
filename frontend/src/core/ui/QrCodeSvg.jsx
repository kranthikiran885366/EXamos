import React, { useEffect, useState } from 'react';
import QRCode from 'qrcode';

export default function QrCodeSvg({
  value,
  size = 200,
  darkColor = '#000000',
  lightColor = '#ffffff',
  margin = 4,
  className = '',
}) {
  const [dataUrl, setDataUrl] = useState('');
  const [svgStr, setSvgStr] = useState('');

  useEffect(() => {
    if (!value) {
      setDataUrl('');
      setSvgStr('');
      return;
    }
    let cancelled = false;

    // Generate high-resolution (2x retina) PNG data URL for crystal-clear camera scan
    QRCode.toDataURL(value, {
      errorCorrectionLevel: 'M',
      margin,
      width: Math.max(360, size * 2),
      color: {
        dark: darkColor,
        light: lightColor,
      },
    })
      .then((url) => {
        if (!cancelled) setDataUrl(url);
      })
      .catch((err) => {
        console.error('Failed to generate QR data URL:', err);
      });

    // Also generate SVG as fallback
    QRCode.toString(value, {
      type: 'svg',
      errorCorrectionLevel: 'M',
      margin,
      color: {
        dark: darkColor,
        light: lightColor,
      },
    })
      .then((svg) => {
        if (!cancelled) setSvgStr(svg);
      })
      .catch(() => {});

    return () => {
      cancelled = true;
    };
  }, [value, size, darkColor, lightColor, margin]);

  if (!value) return null;

  return (
    <div
      className={className}
      style={{
        display: 'inline-block',
        padding: '12px',
        backgroundColor: '#ffffff',
        borderRadius: '12px',
        boxShadow: '0 4px 16px rgba(15, 23, 42, 0.08)',
        border: '1px solid #e2e8f0',
        lineHeight: 0,
      }}
    >
      {dataUrl ? (
        <img
          src={dataUrl}
          alt="2FA QR Code"
          width={size}
          height={size}
          style={{
            display: 'block',
            imageRendering: 'pixelated',
            borderRadius: '4px',
          }}
        />
      ) : svgStr ? (
        <div
          style={{ width: size, height: size }}
          dangerouslySetInnerHTML={{
            __html: svgStr.replace('<svg ', '<svg width="100%" height="100%" '),
          }}
        />
      ) : (
        <div
          style={{
            width: size,
            height: size,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#64748b',
            fontSize: '12px',
          }}
        >
          Generating QR code…
        </div>
      )}
    </div>
  );
}

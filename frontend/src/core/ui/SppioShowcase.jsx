import { useRef, useState } from 'react';
import { SppioSymbol } from './SppioLogo';

/**
 * Dimensional product showcase for the Open Aperture mark.
 *
 * The mark is extruded with stacked, Z-offset SVG layers inside a CSS 3D
 * context: no image assets, no 3D dependency, and the geometry stays crisp at
 * every viewport size. Pointer movement applies a small parallax tilt, and the
 * whole object drifts on a slow turntable loop that is disabled by the global
 * prefers-reduced-motion rule.
 *
 * The stage is intentionally transparent: only the mark, its soft ground
 * shadow, and the caption are rendered.
 */

const LAYER_COUNT = 18;
const LAYER_DEPTH = 2.4;

const EXTRUSION_LAYERS = Array.from({ length: LAYER_COUNT }, (_, index) => {
  const ratio = index / (LAYER_COUNT - 1);
  let accent = '#E08258';
  if (ratio > 0.08) accent = '#B54F34';
  if (ratio > 0.34) accent = '#8E3A22';
  if (ratio > 0.7) accent = '#5E2418';
  return { accent, z: -(index * LAYER_DEPTH) };
});

const CLAMP = (value, min, max) => Math.min(max, Math.max(min, value));

export default function SppioShowcase({
  compact = false,
  onSpecs = null,
  caption = 'One hardware-rooted platform, expressed as a single dimensional mark.',
}) {
  const stageRef = useRef(null);
  const [tilt, setTilt] = useState({ x: 0, y: 0 });

  const handlePointerMove = (event) => {
    if (event.pointerType && event.pointerType !== 'mouse') return;
    const stage = stageRef.current;
    if (!stage) return;
    const rect = stage.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const offsetX = (event.clientX - rect.left) / rect.width - 0.5;
    const offsetY = (event.clientY - rect.top) / rect.height - 0.5;
    setTilt({ x: CLAMP(-offsetY * 14, -7, 7), y: CLAMP(offsetX * 30, -16, 16) });
  };

  const resetTilt = () => setTilt({ x: 0, y: 0 });

  return (
    <figure className={`sppio-showcase${compact ? ' is-compact' : ''}`}>
      <div
        ref={stageRef}
        className="sppio-showcase-stage"
        onPointerMove={handlePointerMove}
        onPointerLeave={resetTilt}
      >
        <span className="sppio-showcase-shadow" aria-hidden="true" />

        <div
          className="sppio-showcase-logo"
          style={{ '--sppio-tilt-x': `${tilt.x}deg`, '--sppio-tilt-y': `${tilt.y}deg` }}
        >
          <div className="sppio-logo-tilt" aria-hidden="true">
            <div className="sppio-logo-spin">
              {EXTRUSION_LAYERS.map((layer, index) => (
                <span
                  key={index}
                  className="sppio-logo-layer"
                  style={{ transform: `translateZ(${layer.z}px)` }}
                >
                  <SppioSymbol size={200} accent={layer.accent} />
                </span>
              ))}
            </div>
          </div>
          <span className="sppio-sr-only">SPPIO Open Aperture brand mark</span>
        </div>
      </div>

      <figcaption className="sppio-showcase-caption">
        <span className="sppio-showcase-caption-text">
          <strong>Open Aperture</strong>
          <span>{caption}</span>
        </span>
        {onSpecs && (
          <button type="button" className="sppio-showcase-link" onClick={onSpecs}>
            Architectural specifications
            <span aria-hidden="true"> →</span>
          </button>
        )}
      </figcaption>
    </figure>
  );
}

export default function Spark({ data, color = '#2f9e6e', step = false }) {
  const w = 96, h = 32, min = Math.min(...data), max = Math.max(...data), r = max - min || 1;
  const pts = data.map((v, i) => [(i / (data.length - 1)) * w, h - 3 - ((v - min) / r) * (h - 6)]);
  const d = pts.map(([x, y], i) => (i === 0 ? `M${x},${y}` : step ? `H${x}V${y}` : `L${x},${y}`)).join('');
  return <svg className="spark" viewBox={`0 0 ${w} ${h}`} aria-hidden="true"><path d={d} fill="none" stroke={color} strokeWidth="1.6" /></svg>;
}

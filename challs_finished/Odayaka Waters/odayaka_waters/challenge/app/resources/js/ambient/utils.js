export const clamp = (v, a, b) => Math.min(b, Math.max(a, v));

export function deviceWantsLowMotion() {
  return window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
}

export function selectDefaultQuality() {
  // Simple heuristic: if deviceMemory low or battery saver, pick 'low'
  const dm = navigator.deviceMemory || 4;
  const isSaver = navigator.getBattery ? false : false; // keep simple for now
  return (dm < 4 || isSaver) ? 'low' : 'standard';
}

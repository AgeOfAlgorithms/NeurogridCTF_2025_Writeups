import { initAudio } from './audio';
import { WaterCanvas } from './waterCanvas';
import { deviceWantsLowMotion, selectDefaultQuality } from './utils';

export function initAmbient(rootEl, { quality = 'standard', audioSrc }) {
  const playBtn = document.getElementById('aw-play');
  const volRange = document.getElementById('aw-volume');
  const qualitySel = document.getElementById('aw-quality');

  // Respect reduced motion
  if (deviceWantsLowMotion()) quality = 'low';

  // Allow auto defaulting based on hardware if user hasn't chosen
  if (!quality) quality = selectDefaultQuality();

  // Audio (user-initiated)
  const audio = initAudio({ src: audioSrc, playBtn, volRange });

  // Visuals
  let water = new WaterCanvas(rootEl, { quality });
  water.start();

  // Quality switcher
  if (qualitySel) {
    qualitySel.value = quality;
    qualitySel.addEventListener('change', () => {
      const q = qualitySel.value;
      water.stop();
      water = new WaterCanvas(rootEl, { quality: q });
      water.start();
    });
  }

  // Clean up on page unload
  window.addEventListener('beforeunload', () => {
    water.stop();
    audio.dispose?.();
  });
}

const KEY = 'ow_volume';
const MIN_AUDIBLE = 0.08;
const FADE_MS = 1200;

function pickSupportedSrc(srcBase) {
  // srcBase like "/media/odayaka" -> we try .ogg then .mp3
  const test = document.createElement('audio');
  const canOgg = !!test.canPlayType && test.canPlayType('audio/ogg; codecs="vorbis"') !== '';
  const canMp3 = !!test.canPlayType && test.canPlayType('audio/mpeg') !== '';
  if (canOgg) return srcBase + '.ogg';
  if (canMp3) return srcBase + '.mp3';
  // fallback: return mp3 anyway; many browsers support it
  return srcBase + '.mp3';
}

export function initAudio({ src, playBtn, volRange, autoplay = true, fadeMs = FADE_MS }) {
  // src may be "/media/odayaka.ogg" — we'll normalize to base and re-pick
  const base = src.replace(/\.(ogg|mp3)$/i, '');
  const resolvedSrc = pickSupportedSrc(base);

  let audio = null;
  let fadeTimer = null;

  // Load saved volume or default
  const saved = Number(localStorage.getItem(KEY));
  let targetVol = Number.isFinite(saved) ? Math.min(1, Math.max(0, saved)) : 0.25;

  // Reflect in UI
  if (volRange) {
    volRange.disabled = true;
    volRange.value = Math.round(targetVol * 100);
  }
  if (playBtn) playBtn.textContent = 'Play';

  function clearFade() { if (fadeTimer) { cancelAnimationFrame(fadeTimer); fadeTimer = null; } }

  function fadeTo(vol, ms) {
    clearFade();
    const start = performance.now();
    const from = audio.volume;
    const delta = vol - from;
    const step = (t) => {
      const k = Math.min(1, (t - start) / ms);
      const eased = from + delta * (1 - Math.pow(1 - k, 3)); // ease-out
      audio.volume = Math.max(0, Math.min(1, eased));
      if (k < 1) fadeTimer = requestAnimationFrame(step);
      else fadeTimer = null;
    };
    fadeTimer = requestAnimationFrame(step);
  }

  function bindVolume() {
    volRange?.addEventListener('input', () => {
      const v = Math.min(100, Math.max(0, Number(volRange.value))) / 100;
      targetVol = v;
      localStorage.setItem(KEY, String(v));
      if (audio) audio.volume = v;
    });
  }

  function bindToggle() {
    if (!playBtn) return;
    playBtn.textContent = audio.paused ? 'Play' : 'Pause';
    playBtn.onclick = async () => {
      try {
        if (audio.paused) {
          // ensure audible when resuming
          if (audio.muted) audio.muted = false;
          if (targetVol <= 0) targetVol = MIN_AUDIBLE;
          audio.volume = Math.max(MIN_AUDIBLE, targetVol);
          await audio.play();
          playBtn.textContent = 'Pause';
        } else {
          audio.pause();
          playBtn.textContent = 'Play';
        }
      } catch { /* ignore */ }
    };
  }

  async function tryAutoplay() {
    audio = new Audio();
    audio.loop = true;
    audio.preload = 'auto';
    audio.autoplay = false;
    audio.playsInline = true;
    audio.src = resolvedSrc;

    // 1) Try unmuted autoplay at an audible volume
    audio.muted = false;
    audio.volume = Math.max(MIN_AUDIBLE, targetVol);
    try {
      await audio.play();
      // success unmuted
      volRange && (volRange.disabled = false);
      bindToggle(); bindVolume();
      return;
    } catch {
      // 2) Try muted autoplay, then unmute + fade to target
      try {
        audio.muted = true;
        audio.volume = 0;
        await audio.play();
        audio.muted = false;
        volRange && (volRange.disabled = false);
        // If user had set 0, still fade to a minimal audible level
        const dest = targetVol > 0 ? targetVol : MIN_AUDIBLE;
        fadeTo(dest, fadeMs);
        bindToggle(); bindVolume();
        return;
      } catch {
        // 3) Fully blocked → require click
        if (playBtn) {
          playBtn.textContent = 'Play';
          playBtn.onclick = async () => {
            try {
              if (!audio) {
                audio = new Audio();
                audio.loop = true;
                audio.preload = 'auto';
                audio.autoplay = false;
                audio.playsInline = true;
                audio.src = resolvedSrc;
              }
              audio.muted = false;
              audio.volume = Math.max(MIN_AUDIBLE, targetVol);
              await audio.play();
              volRange && (volRange.disabled = false);
              bindToggle(); bindVolume();
            } catch { /* user can try again */ }
          };
        }
      }
    }
  }

  if (autoplay) tryAutoplay();

  return {
    dispose() {
      clearFade();
      try { audio?.pause(); } catch {}
      if (audio) audio.src = '';
      audio = null;
      if (playBtn) { playBtn.textContent = 'Play'; playBtn.onclick = null; }
      if (volRange) volRange.disabled = true;
    }
  };
}

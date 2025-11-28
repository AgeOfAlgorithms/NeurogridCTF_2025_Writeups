
import { Leaves } from './leaves';

export class WaterCanvas {
  constructor(rootEl, opts = {}) {
    this.root = rootEl;
    this.quality = opts.quality ?? 'standard';

    // Canvas
    this.canvas = document.createElement('canvas');
    this.ctx = this.canvas.getContext('2d', { alpha: false });
    this.root.appendChild(this.canvas);

    // Parallax
    this.parallax = { x: 0, y: 0, targetX: 0, targetY: 0 };

    // Timing
    this.last = performance.now();
    this.running = false;

    // Leaves (authentic green/yellow, random-impact)
    this.leaves = new Leaves({
      rate: opts.rate ?? 4,
      maxActive: opts.maxActive ?? 80,
      impactMin: 0.20,
      impactMax: 0.92,
    });

    // Analytic ripple list (each impact adds one source)
    // Each ripple is {x, y, born, lifespan}
    this.ripples = [];

    // Ripple visual params
    this.ripple = {
      speed: 120,       // px/sec outward
      wavelength: 18,   // px between rings
      baseAlpha: 0.28,  // overall brightness
      lineWidth: 1.25,  // px
      lifespan: 3200,   // ms (fade-out)
    };

    // Listeners
    this._onResize = this.resize.bind(this);
    this._onPointer = this.onPointer.bind(this);
    window.addEventListener('resize', this._onResize);
    window.addEventListener('mousemove', this._onPointer, { passive: true });

    this.resize();
  }

  // ---------- sizing & input ----------
  resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = Math.floor(this.root.clientWidth || 800);
    const h = Math.floor(this.root.clientHeight || Math.round((w * 9) / 16));

    this.canvas.width = Math.max(1, w * dpr);
    this.canvas.height = Math.max(1, h * dpr);
    this.canvas.style.width = w + 'px';
    this.canvas.style.height = h + 'px';
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  onPointer(e) {
    const rect = this.canvas.getBoundingClientRect();
    const dx = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    const dy = ((e.clientY - rect.top) / rect.height) * 2 - 1;
    this.parallax.targetX = dx * 6;
    this.parallax.targetY = dy * 6;
  }

  // ---------- simulation ----------
  spawnRipple(x, y) {
    this.ripples.push({ x, y, born: performance.now(), lifespan: this.ripple.lifespan });
  }

  update(dt) {
    // Parallax easing
    this.parallax.x += (this.parallax.targetX - this.parallax.x) * 0.06;
    this.parallax.y += (this.parallax.targetY - this.parallax.y) * 0.06;

    const w = this.canvas.clientWidth;
    const h = this.canvas.clientHeight;

    // Leaves update; spawn ripple when a leaf hits its chosen impact Y
    this.leaves.update(dt, w, h, (x, y) => this.spawnRipple(x, y));

    // Cull old ripples
    const now = performance.now();
    this.ripples = this.ripples.filter(r => (now - r.born) < r.lifespan);
  }

  // ---------- rendering ----------
  drawBackground(ctx, w, h) {
    // Restore the previous deep-blue palette you liked
    const g = ctx.createLinearGradient(0, 0, 0, h);
    g.addColorStop(0, '#0f2b38'); // top
    g.addColorStop(1, '#0a1b27'); // bottom
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, w, h);
  }

  drawRipples(ctx, w, h) {
    if (this.ripples.length === 0) return;

    const now = performance.now();
    ctx.save();
    // Additive-ish blend for bright overlaps (superposition feel)
    ctx.globalCompositeOperation = 'screen';

    for (const r of this.ripples) {
      const age = now - r.born;                 // ms
      const travel = (age / 1000) * this.ripple.speed; // px
      const fade = 1 - (age / this.ripple.lifespan);   // 1..0

      // Draw outward rings every wavelength behind the frontier
      const maxRadius = Math.max(w, h) * 0.8;
      for (let rr = travel; rr > 0 && rr < maxRadius; rr -= this.ripple.wavelength) {
        const alpha = this.ripple.baseAlpha * fade * Math.exp(-rr / (maxRadius * 0.9));
        if (alpha < 0.02) break;

        ctx.beginPath();
        ctx.arc(r.x, r.y, rr, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(255,255,255,${alpha})`;
        ctx.lineWidth = this.ripple.lineWidth;
        ctx.stroke();
      }
    }
    ctx.restore();
  }

  draw() {
    const ctx = this.ctx;
    const w = this.canvas.clientWidth;
    const h = this.canvas.clientHeight;

    // Background
    this.drawBackground(ctx, w, h);

    // Parallax
    ctx.save();
    ctx.translate(this.parallax.x, this.parallax.y);

    // Crisp ripples under leaves
    this.drawRipples(ctx, w, h);

    // Leaves on top
    this.leaves.draw(ctx);

    ctx.restore();
  }

  // ---------- loop control ----------
  frame = () => {
    if (!this.running) return;
    const now = performance.now();
    const dt = Math.min(50, now - this.last);
    this.last = now;

    this.update(dt);
    this.draw();

    if (document.hidden) {
      setTimeout(() => requestAnimationFrame(this.frame), 400);
    } else {
      requestAnimationFrame(this.frame);
    }
  };

  start() {
    if (this.running) return;
    this.running = true;
    this.last = performance.now();
    requestAnimationFrame(this.frame);
  }

  stop() {
    this.running = false;
    window.removeEventListener('resize', this._onResize);
    window.removeEventListener('mousemove', this._onPointer);
    this.canvas.remove();
  }
}

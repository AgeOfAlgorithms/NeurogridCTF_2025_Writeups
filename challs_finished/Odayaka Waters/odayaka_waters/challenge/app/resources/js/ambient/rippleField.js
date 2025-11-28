export class RippleField {
    constructor(width, height, opts = {}) {
      this.w = Math.max(16, Math.floor(width));
      this.h = Math.max(16, Math.floor(height));
      this.damping = opts.damping ?? 0.985; // 0.98–0.995 looks good
      this.speed = opts.speed ?? 1.0;       // wave speed factor
      this.acc = 0;
  
      this.curr = new Float32Array(this.w * this.h);
      this.prev = new Float32Array(this.w * this.h);
  
      // For drawing
      this.canvas = document.createElement('canvas');
      this.canvas.width = this.w;
      this.canvas.height = this.h;
      this.ctx = this.canvas.getContext('2d', { willReadFrequently: false });
      this.img = this.ctx.createImageData(this.w, this.h);
    }
  
    index(x, y) { return y * this.w + x; }
  
    drop(x, y, radius = 6, strength = 0.8) {
      // map canvas coords (px) to grid coords
      const gx = Math.floor((x / this.viewW) * this.w);
      const gy = Math.floor((y / this.viewH) * this.h);
      const r2 = radius * radius;
  
      for (let iy = Math.max(1, gy - radius); iy < Math.min(this.h - 1, gy + radius); iy++) {
        for (let ix = Math.max(1, gx - radius); ix < Math.min(this.w - 1, gx + radius); ix++) {
          const dx = ix - gx, dy = iy - gy;
          if (dx*dx + dy*dy <= r2) {
            this.curr[this.index(ix, iy)] += strength;
          }
        }
      }
    }
  
    // dt in ms
    update(dt) {
      // integrate at ~60Hz steps so the sim stays stable
      this.acc += dt;
      const stepMs = 1000 / 60;
      while (this.acc >= stepMs) {
        this.step();
        this.acc -= stepMs;
      }
    }
  
    step() {
      const w = this.w, h = this.h;
      const next = new Float32Array(w * h);
  
      // discrete Laplacian + previous height (wave equation)
      for (let y = 1; y < h - 1; y++) {
        for (let x = 1; x < w - 1; x++) {
          const i = y * w + x;
          const lap =
            this.curr[i - 1] + this.curr[i + 1] +
            this.curr[i - w] + this.curr[i + w] - 4 * this.curr[i];
  
          // next = (2*curr - prev) + c^2 * lap; then apply damping
          next[i] = (2 * this.curr[i] - this.prev[i]) + (this.speed * this.speed) * lap;
          next[i] *= this.damping;
        }
      }
  
      this.prev = this.curr;
      this.curr = next;
    }
  
    // Prepare grid-to-canvas mapping
    setViewSize(viewW, viewH) {
      this.viewW = Math.max(1, viewW);
      this.viewH = Math.max(1, viewH);
    }
  
    drawTo(ctx, W, H) {
      // Convert height to grayscale (positive = highlight, negative = shadow)
      const data = this.img.data;
      for (let i = 0; i < this.curr.length; i++) {
        // scale height to visible brightness
        const v = this.curr[i] * 255 * 0.9; // sensitivity
        const c = 128 + Math.max(-110, Math.min(110, v)); // clamp
        data[i * 4 + 0] = c;
        data[i * 4 + 1] = c;
        data[i * 4 + 2] = c;
        data[i * 4 + 3] = 200; // alpha
      }
      this.ctx.putImageData(this.img, 0, 0);
  
      // Draw scaled with a light blend to look like water highlights
      ctx.save();
      ctx.globalAlpha = 0.25;
      ctx.globalCompositeOperation = 'screen';
      ctx.imageSmoothingEnabled = true;
      ctx.drawImage(this.canvas, 0, 0, W, H);
      ctx.restore();
    }
  }
  
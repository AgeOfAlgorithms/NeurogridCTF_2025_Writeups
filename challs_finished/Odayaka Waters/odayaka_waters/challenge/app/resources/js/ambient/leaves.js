export class Leaves {
    constructor(opts = {}) {
      this.items = [];
      this.spawnAcc = 0;
      this.rate = opts.rate ?? 4;              // leaves/sec
      this.maxActive = opts.maxActive ?? 80;
      this.impactMin = opts.impactMin ?? 0.20; // 20% height
      this.impactMax = opts.impactMax ?? 0.92; // 92% height
    }
  
    randHue() { return 55 + Math.random() * 30; } // green→yellow
  
    spawn(w, h) {
      const size = 11 + Math.random() * 15;
      const hue  = this.randHue();
      const x    = Math.random() * w;
      const y    = -20 - Math.random() * 60;
      const vx   = (-0.10 + Math.random() * 0.20);
      const vy   = 0.24 + Math.random() * 0.36;
      const rot  = Math.random() * Math.PI * 2;
      const vr   = (-0.004 + Math.random() * 0.008);
      const impactY = h * (this.impactMin + Math.random() * (this.impactMax - this.impactMin));
  
      this.items.push({
        x, y, vx, vy, rot, vr, size, hue,
        state: 'fall', alpha: 0.95, timer: 0, impactY
      });
    }
  
    update(dt, w, h, onImpact) {
      // spawn at configured rate
      const interval = 1000 / Math.max(0.001, this.rate);
      this.spawnAcc += dt;
      while (this.spawnAcc >= interval && this.items.length < this.maxActive) {
        this.spawn(w, h);
        this.spawnAcc -= interval;
      }
  
      const t = dt / 16.667;
      for (const L of this.items) {
        L.timer += dt;
  
        if (L.state === 'fall') {
          L.vx += Math.sin(L.timer * 0.0016) * 0.0009;
          L.x += L.vx * t * 1.1;
          L.y += L.vy * t * 1.1;
          L.rot += L.vr * t;
  
          if (L.y >= L.impactY) {
            L.y = L.impactY;
            L.state = 'sink';
            L.alpha = 0.85;
            L.sinkVy = 0.16 + Math.random() * 0.12;
            L.sinkVx = L.vx * 0.2;
            onImpact?.(L.x, L.y);
          }
        } else {
          L.y += L.sinkVy * t;
          L.x += L.sinkVx * t;
          L.rot += L.vr * 0.4 * t;
          L.alpha *= 0.986;
        }
      }
  
      // cull
      this.items = this.items.filter(L =>
        L.alpha > 0.02 && L.x > -80 && L.x < w + 80 && L.y < h + 120
      );
    }
  
    draw(ctx) {
      for (const L of this.items) {
        const s = L.size;
        ctx.save();
        ctx.globalAlpha = Math.max(0, Math.min(1, L.alpha));
        ctx.translate(L.x, L.y);
        ctx.rotate(L.rot);
  
        // blade gradient (green → yellow)
        const grd = ctx.createLinearGradient(-s, -s, s, s);
        grd.addColorStop(0, `hsla(${L.hue}, 70%, 60%, 0.95)`);
        grd.addColorStop(0.6, `hsla(${L.hue + 8}, 70%, 52%, 0.95)`);
        grd.addColorStop(1, `hsla(${L.hue + 12}, 65%, 46%, 0.92)`);
        ctx.fillStyle = grd;
  
        ctx.beginPath();
        // asymmetrical blade (two lobes to a point)
        ctx.moveTo(0, 0);
        ctx.bezierCurveTo(-s*0.75, -s*0.18, -s*0.55, -s*0.98, 0, -s);
        ctx.bezierCurveTo(s*0.55, -s*0.98, s*0.75, -s*0.18, 0, 0);
        ctx.quadraticCurveTo(-s*0.25, s*0.52, 0, s*0.78);
        ctx.quadraticCurveTo(s*0.25, s*0.52, 0, 0);
        ctx.closePath();
        ctx.fill();
  
        // midrib
        ctx.strokeStyle = 'rgba(0,0,0,0.18)';
        ctx.lineWidth = 0.9;
        ctx.beginPath();
        ctx.moveTo(0, -s * 0.92);
        ctx.quadraticCurveTo(0, -s*0.25, 0, s*0.58);
        ctx.stroke();
  
        // curved petiole (stalk)
        ctx.strokeStyle = 'rgba(0,0,0,0.25)';
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        ctx.moveTo(0, s*0.78);
        ctx.bezierCurveTo(s*0.15, s*0.95, s*0.35, s*1.10, s*0.10, s*1.35);
        ctx.stroke();
  
        ctx.restore();
        ctx.globalAlpha = 1;
      }
    }
  }
  
import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["canvas"]
  static values = {
    cell:   { type: Number, default: 56 },
    margin: { type: Number, default: 48 },
    paths:         { type: Number, default: 4 },
    busesPerPath:  { type: Number, default: 2 },
    minSpeed:      { type: Number, default: 60 },
    maxSpeed:      { type: Number, default: 120 },
    meanderFactor: { type: Number, default: 0.6 },
    eastBias:      { type: Number, default: 0.05 },

    seed: Number
  }

  connect() {
    this.canvas = this.element.querySelector(".bg-lines-canvas") || this.canvasTarget
    if (!this.canvas) { console.warn("[background] No canvas found"); return }

    this.ctx = this.canvas.getContext("2d", { alpha: true })
    this.pixelRatio = Math.min(window.devicePixelRatio || 1, 2)

    const s = (this.hasSeedValue ? this.seedValue : Date.now()) >>> 0
    this.rng = this.mulberry32(s)

    this.resize = this.resize.bind(this)
    this.tick   = this.tick.bind(this)

    this.buildAll()

    this.running = true
    this.last = performance.now()
    window.addEventListener("resize", this.resize)
    this.resize()
    requestAnimationFrame(this.tick)
  }

  disconnect() {
    this.running = false
    window.removeEventListener("resize", this.resize)
  }

  mulberry32(seed) {
    let t = seed >>> 0
    return () => {
      t += 0x6D2B79F5
      let r = Math.imul(t ^ (t >>> 15), 1 | t)
      r ^= r + Math.imul(r ^ (r >>> 7), 61 | r)
      return ((r ^ (r >>> 14)) >>> 0) / 4294967296
    }
  }
  rand(a=0,b=1){ return a + (b-a) * this.rng() }
  randi(n){ return (this.rng()*n)|0 }

  resize() {
    const w = window.innerWidth, h = window.innerHeight
    this.canvas.style.width = w + "px"
    this.canvas.style.height = h + "px"
    this.canvas.width  = Math.floor(w * this.pixelRatio)
    this.canvas.height = Math.floor(h * this.pixelRatio)
    this.ctx.setTransform(this.pixelRatio, 0, 0, this.pixelRatio, 0, 0)
  }

  buildAll() {
    this.buildGrid()
    this.buildRoutes()
    this.spawnBuses()
  }

  buildGrid() {
    const w = window.innerWidth, h = window.innerHeight
    const cell = this.cellValue, m = this.marginValue
    const innerW = Math.max(cell, w - m*2)
    const innerH = Math.max(cell, h - m*2)
    const cols = Math.max(3, Math.floor(innerW / cell))
    const rows = Math.max(3, Math.floor(innerH / cell))

    const nodes = []
    const idx = (r,c) => r*cols + c
    for (let r=0;r<rows;r++){
      for (let c=0;c<cols;c++){
        nodes.push({ id: idx(r,c), row:r, col:c, x: m + c*cell, y: m + r*cell })
      }
    }

    const edges = []
    for (let r=0;r<rows;r++){
      for (let c=0;c<cols;c++){
        const a = idx(r,c)
        if (c+1<cols){ const b=idx(r,c+1); edges.push(this.edgeFrom(nodes[a], nodes[b])) }
        if (r+1<rows){ const b=idx(r+1,c); edges.push(this.edgeFrom(nodes[a], nodes[b])) }
      }
    }

    this.grid = { nodes, edges, rows, cols, cell, margin:m, idx }

    window.__BUS_GRID = {
      nodes: nodes.map(n=>({id:n.id,row:n.row,col:n.col,x:n.x,y:n.y})),
      edges: edges.map(e=>({a:e.a,b:e.b,ax:e.ax,ay:e.ay,bx:e.bx,by:e.by,len:e.len})),
      rows, cols, cell, margin:m
    }
  }

  edgeFrom(A,B){ return { a:A.id,b:B.id, ax:A.x,ay:A.y, bx:B.x,by:B.y, len:Math.hypot(B.x-A.x,B.y-A.y) } }

  neighborsOf(id){
    const { rows, cols, idx, nodes } = this.grid
    const n = nodes[id]
    const ns = []
    if (n.col>0)        ns.push(idx(n.row, n.col-1))
    if (n.col+1<cols)   ns.push(idx(n.row, n.col+1))
    if (n.row>0)        ns.push(idx(n.row-1, n.col))
    if (n.row+1<rows)   ns.push(idx(n.row+1, n.col))
    return ns
  }

  stepCost(u, v){
    const { nodes } = this.grid
    const a = nodes[u], b = nodes[v]
    const east = (b.col - a.col) === 1 ? -this.eastBiasValue : 0
    const rnd  = this.meanderFactorValue * this.rand(0, 1)
    const cost = Math.max(0.001, 1 + rnd + east)
    return cost
  }

  dijkstra(startId, goalId){
    const N = this.grid.nodes.length
    const dist = new Float32Array(N).fill(Infinity)
    const prev = new Int32Array(N).fill(-1)
    const used = new Uint8Array(N).fill(0)
    dist[startId] = 0

    for (let iter=0; iter<N; iter++){
      let u=-1, best=Infinity
      for (let i=0;i<N;i++){ if(!used[i] && dist[i]<best){ best=dist[i]; u=i } }
      if (u===-1 || u===goalId) break
      used[u]=1
      for (const v of this.neighborsOf(u)){
        if (used[v]) continue
        const alt = dist[u] + this.stepCost(u,v)
        if (alt < dist[v]){ dist[v]=alt; prev[v]=u }
      }
    }

    if (prev[goalId]===-1){
      return [startId, goalId]
    }
    const path=[]
    for (let cur=goalId; cur!==-1; cur=prev[cur]){ path.push(cur); if(cur===startId) break }
    path.reverse()
    return path
  }

  buildRoutes(){
    const { rows, cols, idx, nodes } = this.grid
    const pathCount = Math.max(1, this.pathsValue|0)
    this.routes = []
    for (let i=0;i<pathCount;i++){
      const start = idx(this.randi(rows), 0)
      const goal  = idx(this.randi(rows), cols-1)
      const ids   = this.dijkstra(start, goal)

      const segs=[]
      for (let k=0;k<ids.length-1;k++){
        const A = nodes[ids[k]], B = nodes[ids[k+1]]
        segs.push({ ax:A.x, ay:A.y, bx:B.x, by:B.y, len:Math.hypot(B.x-A.x,B.y-A.y) })
      }
      const hue = 185 + this.rand(-12,12)*1
      this.routes.push({ ids, segs, hue })
    }
  }

  spawnBuses(){
    this.buses = []
    for (let r=0;r<this.routes.length;r++){
      for (let n=0;n<Math.max(1, this.busesPerPathValue|0); n++){
        this.buses.push(this.newBusOnRoute(r))
      }
    }
  }

  newBusOnRoute(routeIndex){
    const speed = this.rand(this.minSpeedValue, this.maxSpeedValue)
    return { route: routeIndex, seg: 0, t: 0, speed }
  }

  advanceBus(bus, dt){
    const route = this.routes[bus.route]
    if (!route || !route.segs.length){ return }

    let seg = route.segs[bus.seg]
    if (!seg || seg.len<=1e-4){
      bus.seg++; bus.t = 0
      if (bus.seg >= route.segs.length){
        const replaceIdx = bus.route
        const { rows, cols, idx, nodes } = this.grid
        const start = idx(this.randi(rows), 0), goal = idx(this.randi(rows), cols-1)
        const ids = this.dijkstra(start, goal)
        const segs=[]
        for (let k=0;k<ids.length-1;k++){
          const A = nodes[ids[k]], B = nodes[ids[k+1]]
          segs.push({ ax:A.x, ay:A.y, bx:B.x, by:B.y, len:Math.hypot(B.x-A.x,B.y-A.y) })
        }
        const hue = 185 + this.rand(-12,12)*1
        this.routes[replaceIdx] = { ids, segs, hue }

        bus.seg = 0; bus.t = 0
        return
      }
      seg = route.segs[bus.seg]
      if (!seg) return
    }

    const dist = bus.speed * dt
    bus.t += dist / seg.len
    if (bus.t >= 1){
      bus.seg++; bus.t = 0
      if (bus.seg >= route.segs.length){
        const replaceIdx = bus.route
        const { rows, cols, idx, nodes } = this.grid
        const start = idx(this.randi(rows), 0), goal = idx(this.randi(rows), cols-1)
        const ids = this.dijkstra(start, goal)
        const segs=[]
        for (let k=0;k<ids.length-1;k++){
          const A = nodes[ids[k]], B = nodes[ids[k+1]]
          segs.push({ ax:A.x, ay:A.y, bx:B.x, by:B.y, len:Math.hypot(B.x-A.x,B.y-A.y) })
        }
        const hue = 185 + this.rand(-12,12)*1
        this.routes[replaceIdx] = { ids, segs, hue }

        bus.seg = 0; bus.t = 0
        return
      }
    }
  }

  tick(now){
    if (!this.running) return
    const dt = Math.min(0.06, (now - this.last) / 1000)
    this.last = now
    this.drawFrame(dt)
    requestAnimationFrame(this.tick)
  }

  drawFrame(dt){
    const ctx = this.ctx
    const w = this.canvas.width / this.pixelRatio
    const h = this.canvas.height / this.pixelRatio
    ctx.clearRect(0,0,w,h)

    const { margin:m, cell, rows, cols } = this.grid

    ctx.strokeStyle = "rgba(255,255,255,0.06)"
    ctx.lineWidth = 1
    for (let c=0;c<cols;c++){
      const x = m + c*cell
      ctx.beginPath(); ctx.moveTo(x, m); ctx.lineTo(x, m + (rows-1)*cell); ctx.stroke()
    }
    for (let r=0;r<rows;r++){
      const y = m + r*cell
      ctx.beginPath(); ctx.moveTo(m, y); ctx.lineTo(m + (cols-1)*cell, y); ctx.stroke()
    }

    for (const rt of this.routes){
      ctx.lineWidth = 2
      ctx.strokeStyle = `hsla(${rt.hue}, 100%, 70%, 0.35)`
      for (const s of rt.segs){
        ctx.beginPath()
        ctx.moveTo(s.ax, s.ay)
        ctx.lineTo(s.bx, s.by)
        ctx.stroke()
      }
    }

    for (const bus of this.buses){
      this.advanceBus(bus, dt)
      const rt = this.routes[bus.route]; if (!rt) continue
      const seg = rt.segs[Math.min(bus.seg, rt.segs.length-1)]; if (!seg) continue
      const x = seg.ax + (seg.bx - seg.ax) * bus.t
      const y = seg.ay + (seg.by - seg.ay) * bus.t

      ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI*2)
      ctx.fillStyle = "rgba(43,212,199,0.95)"; ctx.fill()
      ctx.beginPath(); ctx.arc(x, y, 6.5, 0, Math.PI*2)
      ctx.strokeStyle = "rgba(43,212,199,0.25)"; ctx.stroke()
    }
  }
}
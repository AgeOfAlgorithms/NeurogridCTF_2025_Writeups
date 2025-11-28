import { Controller } from "@hotwired/stimulus"

const clamp = (v, a, b) => Math.max(a, Math.min(b, v))

export default class extends Controller {
  static targets = ["canvas", "seed", "metrics"]
  static values = {
    sourceUrl: String,
    pollMs:   { type: Number, default: 10000 },
    oneBased: { type: Boolean, default: false },
    routeAlpha: { type: Number, default: 0.4 },
    routeWidth: { type: Number, default: 2 },
    dotRadius:  { type: Number, default: 4 },
    mockBuses:  { type: Number, default: 5 },
    pixelRatioMax: { type: Number, default: 2 }
  }

  connect() {
    // Resolve canvas
    this.canvasEl = this.hasCanvasTarget
      ? this.canvasTarget
      : this.element.querySelector("[data-transit-map-target='canvas'], canvas")
    if (!this.canvasEl) { console.warn("[transit-map] No canvas target found"); return }

    this.ctx = this.canvasEl.getContext("2d", { alpha: true })
    this.pixelRatio = Math.min(window.devicePixelRatio || 1, this.pixelRatioMaxValue)

    this.resize = this.resize.bind(this)
    this.tick   = this.tick.bind(this)

    this.refreshGrid()

    this.routes = []
    this.colors = this.makePalette(12)

    this.pollOnce()
    this.pollTimer = setInterval(() => this.pollOnce(), this.pollMsValue)

    this.last = performance.now()
    window.addEventListener("resize", this.onWindowResize)
    this.resize()
    requestAnimationFrame(this.tick)
  }

  disconnect() {
    clearInterval(this.pollTimer)
    window.removeEventListener("resize", this.onWindowResize)
  }

  onWindowResize = () => {
    this.refreshGrid()
    this.resize()
  }
  refreshGrid() {
    const g = window.__BUS_GRID
    if (g && Array.isArray(g.nodes) && Array.isArray(g.edges) && g.nodes.length) {
      this.grid = g
    } else {
      this.grid = this.makeFallbackGrid()
    }
    this.buildAdjAndIndexes()
  }

  makeFallbackGrid() {
    const cell = 56, margin = 48
    const cols = 12, rows = 8
    const nodes = []
    const idx = (r, c) => r * cols + c
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        nodes.push({ id: idx(r, c), row: r, col: c, x: margin + c * cell, y: margin + r * cell })
      }
    }
    const edges = []
    for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
      const a = idx(r, c)
      if (c + 1 < cols) edges.push(edgeFrom(nodes[a], nodes[idx(r, c + 1)]))
      if (r + 1 < rows) edges.push(edgeFrom(nodes[a], nodes[idx(r + 1, c)]))
    }
    return { nodes, edges, rows, cols, cell, margin }
    function edgeFrom(A, B) {
      return { a: A.id, b: B.id, ax: A.x, ay: A.y, bx: B.x, by: B.y, len: Math.hypot(B.x - A.x, B.y - A.y) }
    }
  }

  buildAdjAndIndexes() {
    const { nodes, edges } = this.grid
    const N = nodes.length
    this.idToIdx   = new Map(nodes.map((n, i) => [n.id, i]))
    this.idxToNode = nodes

    this.adj = Array.from({ length: N }, () => [])
    for (const e of edges) {
      const ai = this.idToIdx.get(e.a)
      const bi = this.idToIdx.get(e.b)
      if (ai != null && bi != null) {
        this.adj[ai].push(bi)
        this.adj[bi].push(ai)
      }
    }

    this.rcToId = new Map()
    for (const n of nodes) {
      this.rcToId.set(`${n.row},${n.col}`, n.id)
    }
  }

  manhattanPathIds(startId, endId) {
    const A = this.idxToNode[this.idToIdx.get(startId)]
    const B = this.idxToNode[this.idToIdx.get(endId)]
    if (!A || !B) return []

    const path = []
    const pushRC = (r, c) => {
      const id = this.rcToId.get(`${r},${c}`)
      if (id != null && (path.length === 0 || path[path.length - 1] !== id)) path.push(id)
    }

    const dc = Math.sign(B.col - A.col) || 0
    pushRC(A.row, A.col)
    for (let c = A.col + dc; dc !== 0 && c !== B.col + dc; c += dc) pushRC(A.row, c)
    const dr = Math.sign(B.row - A.row) || 0
    for (let r = A.row + dr; dr !== 0 && r !== B.row + dr; r += dr) pushRC(r, B.col)

    if (path.length === 0) pushRC(A.row, A.col)
    return path
  }
  async pollOnce() {
    let matrix = null
    const url = this.sourceUrlValue
    if (url) {
      try {
        const resp = await fetch(url, { cache: "no-store" })
        if (resp.ok) {
          const data = await resp.json()
          if (Array.isArray(data)) matrix = data
          else if (data && Array.isArray(data.matrix)) matrix = data.matrix
        } else {
          console.warn("[transit-map] fetch error", resp.status)
        }
      } catch (err) {
        console.warn("[transit-map] fetch failed", err)
      }
    }
    if (!matrix) matrix = this.makeMockMatrix()

    if (!Array.isArray(matrix) || matrix.length < 3) {
      console.warn("[transit-map] invalid matrix; ignoring", matrix)
      return
    }
    const starts   = matrix[0] || []
    const currents = matrix[1] || []
    const ends     = matrix[2] || []

    const N = Math.min(starts.length, currents.length, ends.length)
    const buses = []
    for (let i = 0; i < N; i++) {
      let s = starts[i], c = currents[i], e = ends[i]
      if (this.oneBasedValue) { s = s - 1; c = c - 1; e = e - 1 }

      const sOk = this.idToIdx.has(s)
      const eOk = this.idToIdx.has(e)
      if (!sOk || !eOk) continue
      const path = this.manhattanPathIds(s, e)
      let cur = this.idToIdx.has(c) ? c : s

        if (path.length && !path.includes(cur)) {
        const curIdx = this.idToIdx.get(cur)
        if (curIdx != null) {
          const curNode = this.idxToNode[curIdx]
          cur = path.reduce((bestPid, pid) => {
            const best = this.idxToNode[this.idToIdx.get(bestPid)]
            const cand = this.idxToNode[this.idToIdx.get(pid)]
            const dBest = Math.hypot(best.x - curNode.x, best.y - curNode.y)
            const dCand = Math.hypot(cand.x - curNode.x, cand.y - curNode.y)
            return dCand < dBest ? pid : bestPid
          }, path[0])
        } else {
          cur = path[0]
        }
      }

      buses.push({
        startId: s,
        endId: e,
        currentId: cur,
        pathIds: path,
        color: this.colors[i % this.colors.length]
      })
    }
    this.routes = buses
    if (this.hasMetricsTarget) {
      this.metricsTarget.textContent = `buses=${buses.length} · gridNodes=${this.idxToNode.length}`
    }
  }

  makeMockMatrix() {
    const { rows, cols } = this.grid
    const M = this.mockBusesValue
    const starts = [], currents = [], ends = []
    for (let i = 0; i < M; i++) {
      const start = this.nodeIdAt(this.randInt(0, rows - 1), 0)
      const end   = this.nodeIdAt(this.randInt(0, rows - 1), cols - 1)
      const path  = this.manhattanPathIds(start, end)
      const pidx  = path.length ? this.randInt(0, path.length - 1) : 0
      const cur   = path.length ? path[pidx] : start
      starts.push(this.oneBasedValue ? start + 1 : start)
      currents.push(this.oneBasedValue ? cur + 1 : cur)
      ends.push(this.oneBasedValue ? end + 1 : end)
    }
    return [starts, currents, ends]
  }

  nodeIdAt(row, col) {
    for (const n of this.grid.nodes) if (n.row === row && n.col === col) return n.id
    const r = clamp(row, 0, this.grid.rows - 1)
    const c = clamp(col, 0, this.grid.cols - 1)
    for (const n of this.grid.nodes) if (n.row === r && n.col === c) return n.id
    return this.grid.nodes[0]?.id ?? 0
  }

  randInt(a, b) { return Math.floor(a + Math.random() * (b - a + 1)) }

  makePalette(n) {
    const arr = []
    for (let i = 0; i < n; i++) {
      const h = 180 + i * (360 / n) * 0.33
      arr.push({ h, s: 100, l: 70 })
    }
    return arr
  }

  resize() {
    const c = this.canvasEl
    const w = c.parentElement ? c.parentElement.clientWidth : window.innerWidth
    const h = Math.max(320, Math.floor(w * 0.5))
    c.style.width  = w + "px"
    c.style.height = h + "px"
    c.width  = Math.floor(w * this.pixelRatio)
    c.height = Math.floor(h * this.pixelRatio)
    this.ctx.setTransform(this.pixelRatio, 0, 0, this.pixelRatio, 0, 0)
  }

  tick(now) {
    const dt = Math.min(0.06, (now - this.last) / 1000)
    this.last = now
    this.draw()
    requestAnimationFrame(this.tick)
  }

  draw() {
    if (!this.canvasEl) return
    const ctx = this.ctx
    const W = this.canvasEl.width / this.pixelRatio
    const H = this.canvasEl.height / this.pixelRatio
    ctx.clearRect(0, 0, W, H)

    ctx.lineWidth = 1
    ctx.strokeStyle = "rgba(255,255,255,0.06)"
    for (const e of this.grid.edges) {
      ctx.beginPath()
      ctx.moveTo(e.ax, e.ay)
      ctx.lineTo(e.bx, e.by)
      ctx.stroke()
    }

    for (const r of this.routes) {
      ctx.lineWidth = this.routeWidthValue
      ctx.strokeStyle = `hsla(${r.color.h}, ${r.color.s}%, ${r.color.l}%, ${this.routeAlphaValue})`
      for (let i = 0; i < r.pathIds.length - 1; i++) {
        const A = this.idxToNode[this.idToIdx.get(r.pathIds[i])]
        const B = this.idxToNode[this.idToIdx.get(r.pathIds[i + 1])]
        if (!A || !B) continue
        ctx.beginPath()
        ctx.moveTo(A.x, A.y)
        ctx.lineTo(B.x, B.y)
        ctx.stroke()
      }

      const SA = this.idxToNode[this.idToIdx.get(r.startId)]
      const SB = this.idxToNode[this.idToIdx.get(r.endId)]
      if (SA) { ctx.beginPath(); ctx.arc(SA.x, SA.y, this.dotRadiusValue - 1, 0, Math.PI * 2); ctx.strokeStyle = `hsla(${r.color.h}, ${r.color.s}%, ${r.color.l}%, 0.7)`; ctx.stroke() }
      if (SB) { ctx.beginPath(); ctx.arc(SB.x, SB.y, this.dotRadiusValue - 1, 0, Math.PI * 2); ctx.strokeStyle = `hsla(${r.color.h}, ${r.color.s}%, ${r.color.l}%, 0.7)`; ctx.stroke() }
      const curIdx = this.idToIdx.get(r.currentId)
      const cur = curIdx != null ? this.idxToNode[curIdx] : null
      if (cur) {
        ctx.beginPath()
        ctx.arc(cur.x, cur.y, this.dotRadiusValue, 0, Math.PI * 2)
        ctx.fillStyle = `hsla(${r.color.h}, 70%, 60%, 0.95)`
        ctx.fill()
        ctx.beginPath()
        ctx.arc(cur.x, cur.y, this.dotRadiusValue + 3, 0, Math.PI * 2)
        ctx.strokeStyle = `hsla(${r.color.h}, 70%, 60%, 0.25)`
        ctx.stroke()
      }
    }
  }
}

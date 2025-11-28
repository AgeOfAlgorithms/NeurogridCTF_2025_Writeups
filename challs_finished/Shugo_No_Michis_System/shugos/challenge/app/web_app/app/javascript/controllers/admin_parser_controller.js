import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["jsonView", "tbody", "status"]
  static values = { url: String }

  async fetchNow() {
    this.statusTarget.textContent = "Fetching…"
    try {
      const resp = await fetch(this.urlValue, { headers: { Accept: "application/json" }, cache: "no-store" })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const data = await resp.json()
      this.renderJSON(data)
      this.renderTable(data.tickets || [])
      this.statusTarget.textContent = `Source: ${data.source || "unknown"} · ${data.fetched_at || ""}`
    } catch (e) {
      this.statusTarget.textContent = "Fetch failed (showing nothing)"
      this.renderJSON({ error: e.message })
      this.renderTable([])
      console.warn("[admin-parser]", e)
    }
  }

  renderJSON(obj) {
    this.jsonViewTarget.textContent = JSON.stringify(obj, null, 2)
  }

  renderTable(rows) {
    const fmt = (cents) => (typeof cents === "number" ? (cents/100).toFixed(2) : "—")
    this.tbodyTarget.innerHTML = rows.map(r => `
      <tr>
        <td>${escapeHtml(r.name || "")}</td>
        <td>${escapeHtml((r.bus_code || "").toString())}</td>
        <td>${escapeHtml(r.user_email || "—")}</td>
        <td>${escapeHtml(r.travel_date || "")}</td>
        <td>${escapeHtml((r.seats ?? 1).toString())}</td>
        <td>${escapeHtml(`${r.start_node ?? "?"} → ${r.end_node ?? "?"}`)}</td>
        <td>${fmt(r.total_cents)}</td>
      </tr>
    `).join("")
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))
}

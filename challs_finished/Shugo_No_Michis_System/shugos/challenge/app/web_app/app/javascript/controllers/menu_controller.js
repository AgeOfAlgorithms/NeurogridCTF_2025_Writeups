import { Controller } from "@hotwired/stimulus"
export default class extends Controller {
  static targets = ["list"]
  toggle(e){
    e.preventDefault()
    const open = this.listTarget.classList.toggle("open")
    const btn = e.currentTarget
    if (btn && btn.setAttribute) btn.setAttribute("aria-expanded", open ? "true" : "false")
  }
}

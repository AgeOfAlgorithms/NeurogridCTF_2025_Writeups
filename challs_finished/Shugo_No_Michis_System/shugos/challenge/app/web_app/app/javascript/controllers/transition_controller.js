import { Controller } from "@hotwired/stimulus"
export default class extends Controller {
  connect(){
    try {
      const main = document.querySelector(".page-enter")
      if (!main) return
      requestAnimationFrame(()=> main.classList.add("page-enter-active"))
    } catch(_) {}
  }
}

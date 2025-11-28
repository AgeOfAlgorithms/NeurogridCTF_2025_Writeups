document.addEventListener('DOMContentLoaded', () => {
  // Unseal cards on admin dashboard
  document.body.addEventListener('click', (e) => {
    const overlay = e.target.closest('[data-action="unseal-card"]');
    if (overlay) {
      const card = overlay.closest('.knowledge-card');
      if (card) {
        card.classList.remove('sealed');
        card.classList.add('unsealed');
        overlay.style.transition = 'all 0.5s ease';
        overlay.style.transform = 'scale(1.2)';
        setTimeout(() => { overlay.style.opacity = '0'; }, 100);
      }
    }

    const rowOverlay = e.target.closest('[data-action="unseal-row"]');
    if (rowOverlay) {
      const row = rowOverlay.closest('.sealed-row');
      if (row) {
        row.classList.remove('sealed-row');
        row.classList.add('unsealed-row');
      }
    }
  });
});



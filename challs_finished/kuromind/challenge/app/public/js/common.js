document.addEventListener('DOMContentLoaded', () => {
  document.body.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action="go-back"]');
    if (btn) {
      history.back();
    }
  });
});



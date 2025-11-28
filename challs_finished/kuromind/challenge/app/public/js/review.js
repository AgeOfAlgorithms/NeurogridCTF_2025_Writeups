document.addEventListener('DOMContentLoaded', function() {
  const form = document.querySelector('form');
  const reasonField = document.querySelector('#reason');
  
  form.addEventListener('submit', function(e) {
    const action = e.submitter.value;
    
    if (action === 'reject' && !reasonField.value.trim()) {
      e.preventDefault();
      alert('Please provide a reason for rejection');
      reasonField.focus();
    }
  });
});

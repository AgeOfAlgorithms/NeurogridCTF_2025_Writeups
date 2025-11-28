document.addEventListener('DOMContentLoaded', () => {
  // Tags editor logic (used on add/edit/draft-form pages)
  const categoryCheckboxes = document.querySelectorAll('[id^="cat-"]');
  const difficultySection = document.getElementById('difficulty-section');
  const difficultySelect = document.getElementById('difficulty');
  const elementSection = document.getElementById('element-section');
  const elementSelect = document.getElementById('element');
  const tagsJsonField = document.getElementById('tags-json');

  function updateConditionalFields() {
    if (!tagsJsonField) return;
    const selectedCategories = Array.from(categoryCheckboxes)
      .filter(cb => cb.checked)
      .map(cb => cb.value);

    const hasSpell = selectedCategories.includes('spell');
    const hasJutsu = selectedCategories.includes('jutsu');
    const needsRank = hasSpell || hasJutsu;

    if (difficultySection) difficultySection.style.display = needsRank ? 'block' : 'none';
    if (elementSection) elementSection.style.display = hasJutsu ? 'block' : 'none';

    if (!needsRank && difficultySelect) difficultySelect.value = '';
    if (!hasJutsu && elementSelect) elementSelect.value = '';
  }

  function updateJSON() {
    if (!tagsJsonField) return;
    const selectedCategories = Array.from(categoryCheckboxes)
      .filter(cb => cb.checked)
      .map(cb => cb.value);

    let currentTags = {};
    try {
      currentTags = JSON.parse(tagsJsonField.value || '{}');
    } catch (_) {}

    const updatedTags = { ...currentTags, categories: selectedCategories };
    const hasSpell = selectedCategories.includes('spell');
    const hasJutsu = selectedCategories.includes('jutsu');
    const needsRank = hasSpell || hasJutsu;
    
    if (needsRank && difficultySelect && difficultySelect.value) {
      updatedTags.difficulty = difficultySelect.value;
    } else {
      delete updatedTags.difficulty;
    }
    if (selectedCategories.includes('jutsu') && elementSelect && elementSelect.value) {
      updatedTags.element = elementSelect.value;
    } else {
      delete updatedTags.element;
    }

    tagsJsonField.value = JSON.stringify(updatedTags, null, 2);
  }

  function loadFromJSON() {
    if (!tagsJsonField) return;
    try {
      const tags = JSON.parse(tagsJsonField.value || '{}');
      categoryCheckboxes.forEach(cb => (cb.checked = false));
      if (tags.categories && Array.isArray(tags.categories)) {
        tags.categories.forEach(cat => {
          const checkbox = document.getElementById(`cat-${cat}`);
          if (checkbox) checkbox.checked = true;
        });
      }
      if (tags.difficulty && difficultySelect) difficultySelect.value = tags.difficulty;
      if (tags.element && elementSelect) elementSelect.value = tags.element;
      updateConditionalFields();
    } catch (_) {}
  }

  if (tagsJsonField) {
    categoryCheckboxes.forEach(cb => cb.addEventListener('change', () => { updateConditionalFields(); updateJSON(); }));
    if (difficultySelect) difficultySelect.addEventListener('change', updateJSON);
    if (elementSelect) elementSelect.addEventListener('change', updateJSON);
    loadFromJSON();
  }

  // Confirmation for draft deletion
  document.querySelectorAll('.js-confirm-delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      if (!confirm('Are you sure you want to delete this draft?')) {
        e.preventDefault();
      }
    });
  });
});



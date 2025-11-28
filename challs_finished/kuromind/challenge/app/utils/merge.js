export function deepMerge(target, source) {
  let depth = 0;
  function merge(currentTarget, currentSource) {
    if (depth > 10) return currentTarget;
    depth++;
    for (let key in currentSource) {
      if (typeof currentSource[key] === 'object' && currentSource[key] !== null) {
        currentTarget[key] = merge(currentTarget[key] || {}, currentSource[key]);
      } else {
        currentTarget[key] = currentSource[key];
      }
    }
    return currentTarget;
  }
  return merge(target, source);
}

// Runs before first paint to apply a saved theme choice and avoid a flash.
// Kept as an external file because the CSP forbids inline scripts.
(function () {
  try {
    var t = localStorage.getItem('theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) { /* storage blocked: follow the OS setting */ }
})();

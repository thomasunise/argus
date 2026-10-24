// Applied before first paint (classic script; the CSP forbids inline scripts). Dark mode is opt-in via data-theme.
(function () {
  try {
    var stored = localStorage.getItem('argus-theme');
    if (stored === 'dark' || stored === '"dark"') document.documentElement.dataset.theme = 'dark';
  } catch (e) { /* storage unavailable */ }
})();

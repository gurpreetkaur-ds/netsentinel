// Applies the saved theme before first paint (dark is the default). No inline script, so the CSP holds.
(function () {
  var t = null;
  try { t = localStorage.getItem("ns-theme"); } catch (e) { /* storage blocked */ }
  document.documentElement.setAttribute("data-theme", t === "light" ? "light" : "dark");
  document.documentElement.classList.add("js");
})();

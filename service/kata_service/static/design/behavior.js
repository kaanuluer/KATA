(function () {
  var root = document.documentElement;
  var stored = null;
  try {
    stored = localStorage.getItem("gab-direction-theme");
  } catch (err) {
    stored = null;
  }
  if (stored === "light" || stored === "dark") {
    root.setAttribute("data-theme", stored);
  }

  function paint() {
    var theme = root.getAttribute("data-theme") === "light" ? "light" : "dark";
    var button = document.getElementById("theme-toggle");
    if (!button) return;
    button.textContent = theme === "dark" ? "Light mode" : "Dark mode";
    button.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
  }

  var toggle = document.getElementById("theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      root.setAttribute("data-theme", next);
      try {
        localStorage.setItem("gab-direction-theme", next);
      } catch (err) {
        /* the page still switches for this view */
      }
      paint();
    });
  }
  paint();

  function show(specimen, verdict) {
    specimen.querySelectorAll("[data-outcome]").forEach(function (node) {
      var on = node.getAttribute("data-outcome") === verdict;
      node.hidden = !on;
    });
    specimen.querySelectorAll("[data-preset]").forEach(function (node) {
      node.setAttribute("aria-pressed", node.getAttribute("data-preset") === verdict ? "true" : "false");
    });
    specimen.setAttribute("data-verdict", verdict);
  }

  function decide(specimen) {
    var amount = Number(specimen.querySelector("[data-field='amount']").value);
    var ceiling = Number(specimen.querySelector("[data-field='ceiling']").value);
    var expiry = specimen.querySelector("[data-field='expiry']").checked;
    var verdict = "allow";
    if (!expiry) verdict = "step";
    else if (!(amount <= ceiling)) verdict = "deny";
    show(specimen, verdict);
  }

  document.querySelectorAll("[data-specimen]").forEach(function (specimen) {
    specimen.querySelectorAll("[data-preset]").forEach(function (button) {
      button.addEventListener("click", function () {
        var preset = button.getAttribute("data-preset");
        var amount = specimen.querySelector("[data-field='amount']");
        var item = specimen.querySelector("[data-field='item']");
        var expiry = specimen.querySelector("[data-field='expiry']");
        if (preset === "deny") {
          amount.value = "4200";
          item.value = "MacBook Pro 14-inch";
          expiry.checked = true;
        } else if (preset === "step") {
          amount.value = "1300";
          item.value = "Laptop";
          expiry.checked = false;
        } else {
          amount.value = "1300";
          item.value = "Laptop";
          expiry.checked = true;
        }
        show(specimen, preset);
      });
    });
    var form = specimen.querySelector("form");
    if (form) {
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        decide(specimen);
      });
    }
  });
})();

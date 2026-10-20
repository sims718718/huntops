(function () {
  "use strict";

  function showError() {
    var toast = document.getElementById("hx-error");
    var message = document.getElementById("hx-error-message");
    message.textContent = "";
    toast.hidden = false;
    // Update an existing, visible live region so assistive technology announces it.
    window.requestAnimationFrame(function () {
      message.textContent = "The request could not be completed. Check your connection and reload the page before trying again.";
    });
  }

  ["htmx:responseError", "htmx:sendError", "htmx:timeout", "htmx:swapError"].forEach(function (name) {
    document.addEventListener(name, showError);
  });

  document.addEventListener("click", function (event) {
    if (event.target.closest("[data-dismiss-hx-error]")) {
      document.getElementById("hx-error").hidden = true;
      document.getElementById("hx-error-message").textContent = "";
    }
  });

  document.addEventListener("htmx:beforeOnLoad", function (event) {
    var xhr = event.detail.xhr;
    var login = new URL(document.body.dataset.loginUrl, window.location.href);
    var response = new URL(xhr.responseURL || window.location.href, window.location.href);
    // XHR follows Django's login redirect and receives a 200 full login page.
    // Cancel before response processing so it cannot replace a results fragment.
    if (xhr.status === 401 || (response.origin === login.origin && response.pathname === login.pathname)) {
      event.preventDefault();
      login.searchParams.set("next", window.location.pathname + window.location.search + window.location.hash);
      window.location.assign(login.href);
    }
  });
})();

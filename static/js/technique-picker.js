(() => {
  "use strict";

  // Progressive enhancement over the plain <select multiple> HuntForm already
  // renders (~860 techniques) - same contract as board.js's drag-and-drop: the
  // native select stays the only thing that submits, this just builds a nicer
  // UI on top of it and keeps the two in sync via option.selected + a dispatched
  // change event. Technique.__str__ already renders "T1055 Process Injection",
  // so every option's own text is all the data this needs - no fetch involved.
  const MAX_MATCHES = 40;

  function enhance(select) {
    select.hidden = true;

    const wrap = document.createElement("div");
    wrap.className = "technique-picker";

    const chips = document.createElement("div");
    chips.className = "technique-picker-chips";

    const inputWrap = document.createElement("div");
    inputWrap.className = "technique-picker-wrap";

    const input = document.createElement("input");
    input.type = "text";
    const noun = select.dataset.noun || "techniques";
    input.placeholder = `Search ${noun}…`;
    input.setAttribute("aria-label", `Search ${noun} to add`);

    const matches = document.createElement("div");
    matches.className = "technique-picker-matches";
    matches.hidden = true;

    inputWrap.append(input, matches);
    wrap.append(chips, inputWrap);
    select.after(wrap);

    function options() {
      return Array.from(select.options);
    }

    function renderChips() {
      chips.replaceChildren();
      for (const option of options()) {
        if (!option.selected) continue;
        const chip = document.createElement("span");
        chip.className = "chip removable";
        const label = document.createElement("span");
        label.textContent = option.text;
        const remove = document.createElement("button");
        remove.type = "button";
        remove.textContent = "×";
        remove.setAttribute("aria-label", `Remove ${option.text}`);
        remove.addEventListener("click", () => {
          option.selected = false;
          select.dispatchEvent(new Event("change"));
          renderChips();
        });
        chip.append(label, remove);
        chips.append(chip);
      }
    }

    function renderMatches() {
      const query = input.value.trim().toLowerCase();
      matches.replaceChildren();
      if (!query) {
        matches.hidden = true;
        return;
      }

      const found = options()
        .filter(option => !option.selected && option.text.toLowerCase().includes(query))
        .slice(0, MAX_MATCHES);

      for (const option of found) {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = option.text;
        button.addEventListener("click", () => {
          option.selected = true;
          select.dispatchEvent(new Event("change"));
          input.value = "";
          renderChips();
          renderMatches();
          input.focus();
        });
        matches.append(button);
      }
      matches.hidden = found.length === 0;
    }

    input.addEventListener("input", renderMatches);
    input.addEventListener("keydown", event => {
      if (event.key === "Escape") { input.value = ""; renderMatches(); return; }
      if (event.key !== "Enter") return;
      // This input lives inside the Hunt form - Enter must never fall through to
      // its submit button, whether or not there's a match to pick.
      event.preventDefault();
      const first = matches.querySelector("button");
      if (first) first.click();
    });
    input.addEventListener("blur", () => {
      // Deferred so a click on a match button fires before the dropdown closes.
      setTimeout(() => { matches.hidden = true; }, 150);
    });
    input.addEventListener("focus", renderMatches);

    renderChips();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("select.technique-picker").forEach(enhance);
  });
})();

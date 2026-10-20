(() => {
  "use strict";

  let card = null;
  let pendingFocusHuntId = null;
  let pendingScrollLeft = null;

  function clearDropTargets() {
    document.querySelectorAll(".board-column.is-drop-target").forEach(function (column) {
      column.classList.remove("is-drop-target");
    });
  }

  // Drag-and-drop is a progressive enhancement over the .move-hunt <select> + submit
  // button already in every card, so it drives that same form via requestSubmit()
  // rather than issuing its own request. Delegated on document so htmx's outerHTML
  // swaps of #board never leave a card's listeners detached.
  document.addEventListener("dragstart", event => {
    if (event.target.closest("a, button, input, select")) return event.preventDefault();
    card = event.target.closest('.hunt-card[draggable="true"]');
    if (!card) return;
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", card.dataset.huntId);
  });

  document.addEventListener("dragover", event => {
    if (card && event.target.closest(".board-column")) event.preventDefault();
  });

  document.addEventListener("dragenter", event => {
    if (!card) return;
    const column = event.target.closest(".board-column");
    if (column) column.classList.add("is-drop-target");
  });

  document.addEventListener("dragleave", event => {
    const column = event.target.closest(".board-column");
    if (!column || column.contains(event.relatedTarget)) return;
    column.classList.remove("is-drop-target");
  });

  document.addEventListener("drop", event => {
    const column = event.target.closest(".board-column");
    if (!card || !column) { clearDropTargets(); return; }
    event.preventDefault();
    // The card stays in its original DOM column until the server responds: only the
    // hidden select's value changes here, then reverts, so a blocked drop (the
    // feasibility gate, a network failure) leaves the card exactly where it was,
    // with the foundation toast or the returned move_error explaining why.
    const form = card.querySelector(".move-hunt");
    const select = form.elements.status;
    if (select.disabled) { card = null; clearDropTargets(); return; }
    const previous = select.value;
    select.value = column.dataset.stage;
    form.requestSubmit();
    select.value = previous;
    card = null;
    clearDropTargets();
  });

  document.addEventListener("dragend", () => {
    card = null;
    clearDropTargets();
  });

  // Remember which hunt's move control was used so focus can return to it (or to the
  // board heading, if that hunt is no longer on the board) after the swap replaces
  // #board's contents wholesale.
  document.addEventListener("submit", event => {
    const form = event.target.closest(".move-hunt");
    if (!form) return;
    const originCard = form.closest(".hunt-card");
    pendingFocusHuntId = originCard ? originCard.dataset.huntId : null;
  });

  document.addEventListener("htmx:beforeSwap", event => {
    if (event.target.id !== "board") return;
    const columns = event.target.querySelector(".board-columns");
    pendingScrollLeft = columns ? columns.scrollLeft : null;
  });

  document.addEventListener("htmx:afterSwap", () => {
    const board = document.getElementById("board");
    if (!board) return;

    const columns = board.querySelector(".board-columns");
    if (columns && pendingScrollLeft !== null) columns.scrollLeft = pendingScrollLeft;
    pendingScrollLeft = null;

    if (pendingFocusHuntId !== null) {
      const select = document.getElementById("move-" + pendingFocusHuntId);
      if (select) {
        // preventScroll: the browser's default focus-into-view behavior would otherwise
        // re-scroll .board-columns and undo the scrollLeft restore just above.
        select.focus({ preventScroll: true });
      } else {
        document.getElementById("board-heading")?.focus({ preventScroll: true });
      }
      pendingFocusHuntId = null;
    }
  });

  // A move request that fails at the transport level (server unavailable, timeout, a
  // swap error) never reaches htmx:afterSwap, so pendingFocusHuntId would otherwise
  // survive to steal focus on some later, unrelated board swap. htmx:afterRequest fires
  // after every request regardless of outcome, so clearing it there is sufficient; a
  // successful request has already consumed and cleared it in htmx:afterSwap by then.
  document.addEventListener("htmx:afterRequest", () => {
    pendingFocusHuntId = null;
  });
})();

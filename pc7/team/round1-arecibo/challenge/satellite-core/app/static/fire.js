// static/fire.js
(() => {
  const btn = document.getElementById("fireBtn");
  if (!btn) return;

  const cap = btn.dataset.cap;

  btn.addEventListener("click", async () => {
    try {
      const res = await fetch(cap, {
        method: "POST",
        headers: {
          // Marks this as the UI-triggered request
          "X-Requested-With": "button"
        }
      });

      // We expect 202 Accepted here
      if (!res.ok && res.status !== 202) {
        console.warn("Uplink rejected:", res.status);
        return;
      }

      // Subtle feedback only
      btn.disabled = true;
      btn.textContent = "COMMAND SENT";
    } catch (e) {
      console.error("Uplink failure", e);
    }
  });
})();
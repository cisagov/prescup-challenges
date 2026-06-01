(() => {
  const $ = (sel, el=document) => el.querySelector(sel);
  const $$ = (sel, el=document) => Array.from(el.querySelectorAll(sel));

  const bgLayer = $("#bgLayer");
  const contentBody = $("#contentBody");
  const contentTitle = $("#contentTitle");
  const buttons = $$(".menu__item");

  let activeEra = window.__INITIAL_ERA__ || "prehistoric";
  let busy = false;

  const setActiveButton = (era) => {
    buttons.forEach(b => {
      const on = b.dataset.era === era;
      b.classList.toggle("is-active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
    });
  };

  const setBackground = (era) => {
    bgLayer.className = `bg__layer bg__layer--${era}`;
  };

  const loadEra = async (era, {focusBtn=false} = {}) => {
    if (busy || era === activeEra) return;
    busy = true;

    // fade out content
    contentBody.classList.add("fade-out");
    await new Promise(r => setTimeout(r, 160));

    try {
      const res = await fetch(`/api/era/${encodeURIComponent(era)}`, {cache: "no-store"});
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      activeEra = data.era;
      setActiveButton(activeEra);
      setBackground(activeEra);

      contentTitle.textContent = data.title;
      contentBody.innerHTML = data.html;
    } catch (e) {
      contentBody.innerHTML = `<p><strong>Console error:</strong> failed to load briefing for <code>${era}</code>.</p>`;
    } finally {
      // fade in
      contentBody.classList.remove("fade-out");
      contentBody.classList.add("fade-in");
      setTimeout(() => contentBody.classList.remove("fade-in"), 240);

      if (focusBtn) {
        const btn = buttons.find(b => b.dataset.era === activeEra);
        if (btn) btn.focus();
      }
      busy = false;
    }
  };

  buttons.forEach(btn => {
    btn.addEventListener("click", () => loadEra(btn.dataset.era));
  });

  // keyboard navigation (game menu feel)
  const indexOfEra = (era) => buttons.findIndex(b => b.dataset.era === era);

  const move = (delta) => {
    const i = indexOfEra(activeEra);
    const next = Math.max(0, Math.min(buttons.length - 1, i + delta));
    const era = buttons[next]?.dataset.era;
    if (era) loadEra(era, {focusBtn:true});
  };

  window.addEventListener("keydown", (e) => {
    if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
    if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
    if (e.key === "Escape") { e.preventDefault(); loadEra("prehistoric", {focusBtn:true}); }
  }, {passive:false});

  // clock
  const clock = $("#clock");
  const tick = () => {
    const d = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    clock.textContent = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };
  tick();
  setInterval(tick, 1000);

  // init background
  setBackground(activeEra);
  setActiveButton(activeEra);
})();

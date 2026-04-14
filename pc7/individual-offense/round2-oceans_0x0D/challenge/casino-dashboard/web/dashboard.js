(function(){
  const elAlertLevel = document.getElementById("alertLevel");
  const elAlertState = document.getElementById("alertState");
  const elAlertScore = document.getElementById("alertScore");
  const elDegraded = document.getElementById("degraded");
  const elLockdown = document.getElementById("lockdown");

  const toggles = {
    1: document.getElementById("t1Toggle"),
    2: document.getElementById("t2Toggle"),
    3: document.getElementById("t3Toggle"),
    4: document.getElementById("t4Toggle"),
  };

  // Add Red Toggle for Compromise
  const casinoToggle = document.getElementById("casinoToggle");

  const elReveal = document.getElementById("revealTokenValue");
  const elFeed = document.getElementById("feed");

  const token1Overlay = document.getElementById("token1Overlay");
  const token2Overlay = document.getElementById("token2Overlay");
  const t1TokenValue = document.getElementById("t1TokenValue");
  const t2TokenValue = document.getElementById("t2TokenValue");

  const ghostOverlay = document.getElementById("ghostOverlay");
  const floorOverlay = document.getElementById("floorOverlay");
  const t3TokenValue = document.getElementById("t3TokenValue");
  const t4TokenValue = document.getElementById("t4TokenValue");

  const casinoRow = casinoToggle?.closest(".token-row");
  const seizureOverlay = document.getElementById("seizureOverlay");
  let seizureTriggered = false;

  function escapeHtml(s){
    return s.replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
  }
  function fmtTs(ts){
    const d = new Date(ts*1000);
    return d.toLocaleTimeString();
  }
  function renderFeed(events){
    elFeed.innerHTML = "";
    for(const e of events){
      const div = document.createElement("div");
      div.className = "feed-item";
      div.innerHTML = `<div class="meta">${fmtTs(e.ts || Math.floor(Date.now()/1000))} • ${escapeHtml(String(e.type||"EVENT"))}</div>
                       <div class="msg">${escapeHtml(JSON.stringify(e))}</div>`;
      elFeed.appendChild(div);
    }
  }

  function applyState(s){
    if(!s) return;

    if(s.degraded) elDegraded.classList.remove("hidden");
    else elDegraded.classList.add("hidden");

    const a = s.alert || {};
    elAlertLevel.textContent = String(a.level ?? 0);
    elAlertState.textContent = String(a.state ?? "NORMAL");
    elAlertScore.textContent = "score: " + String(a.score ?? 0);

    if((a.lockdown_until ?? 0) > Math.floor(Date.now()/1000)) elLockdown.classList.remove("hidden");
    else elLockdown.classList.add("hidden");

    const t = s.tokens || {};

    for(const i of [1,2,3,4]){
      const ti = t["token"+i] || {};
      if(ti.found) toggles[i].classList.add("on");
      else toggles[i].classList.remove("on");
    }

    // 🔑 FINAL STATE: purely DOM-driven
    const allOn = [1,2,3,4].every(i => {
      const el = document.getElementById(`t${i}Toggle`);
      return el && el.classList.contains("on");
    });

    if (casinoToggle) {
      if (allOn) {
        casinoToggle.classList.add("on", "compromised");
        casinoToggle.classList.remove("locked");

        const row = casinoToggle.closest(".token-row");
        if (row) row.classList.remove("dim");

        // FBI / seizure banner (once)
        if (!window.__seizureShown) {
          window.__seizureShown = true;
          const overlay = document.getElementById("seizureOverlay");
          if (overlay) overlay.classList.remove("hidden");
        }

      } else {
        casinoToggle.classList.remove("on", "compromised");
        casinoToggle.classList.add("locked");

        const row = casinoToggle.closest(".token-row");
        if (row) row.classList.add("dim");
      }
    }

    // Unified reveal window: prefer highest-number visible token
    let reveal = "";
    for(const i of [4,3,2,1]){
      const ti = (t["token"+i]||{});
      if(ti.visible && ti.value){ reveal = ti.value; break; }
    }
    elReveal.textContent = reveal ? reveal : "PCCC{0D-██...}";
 
   // Overlays

   // Token 1 overlay
    const t1 = t.token1 || {};
    if(t1.visible && t1.value){
      t1TokenValue.textContent = t1.value;
      token1Overlay.classList.remove("hidden");
    } else {
      token1Overlay.classList.add("hidden");
      t1TokenValue.textContent = "PCCC{0D-01██████████}";
    }

    // Token 2 overlay
    const t2 = t.token2 || {};
    if(t2.visible && t2.value){
      t2TokenValue.textContent = t2.value;
      token2Overlay.classList.remove("hidden");
    } else {
      token2Overlay.classList.add("hidden");
      t2TokenValue.textContent = "PCCC{0D-02██████████}";
    }

    const t3 = t.token3 || {};
    if(t3.visible && t3.value){
      t3TokenValue.textContent = t3.value;
      ghostOverlay.classList.remove("hidden");
    } else {
      ghostOverlay.classList.add("hidden");
      t3TokenValue.textContent = "PCCC{0D-03██████████}";
    }

    const t4 = t.token4 || {};
    if(t4.visible && t4.value){
      t4TokenValue.textContent = t4.value;
      floorOverlay.classList.remove("hidden");
    } else {
      floorOverlay.classList.add("hidden");
      t4TokenValue.textContent = "PCCC{0D-04██████████}";
    }

    // Compute completion from the UI toggles (most reliable, no backend assumptions)
    renderFeed(s.events || []);

  }


  (function forceCasinoSwitch() {
  const casinoToggle = document.getElementById("casinoToggle");
  if (!casinoToggle) {
    console.error("❌ casinoToggle not found");
    return;
  }

  const casinoRow = casinoToggle.closest(".token-row");
  const overlay = document.getElementById("seizureOverlay");

  function check() {
    const states = [1,2,3,4].map(i => {
      const el = document.getElementById(`t${i}Toggle`);
      return el && el.classList.contains("on");
    });

    console.log("TOKEN STATES:", states);

    if (states.every(Boolean)) {
      console.log("🔥 ALL TOKENS ON — FORCING CASINO SWITCH");

        casinoToggle.classList.add("on", "compromised");
        casinoToggle.classList.remove("locked");

        if (casinoRow) casinoRow.classList.remove("dim");
        if (overlay) overlay.classList.remove("hidden");
      }
    }

  // Run every 250ms so nothing can race it
    setInterval(check, 250);
  })();
	

  try{
    const wsProto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${wsProto}://${location.host}/ws`);
    ws.onmessage = (ev) => {
      try{
        const msg = JSON.parse(ev.data);
        if(msg.type === "STATE") applyState(msg.data);
      }catch(_){}
    };
    ws.onopen = () => ws.send("hi");
  }catch(_){}
})();

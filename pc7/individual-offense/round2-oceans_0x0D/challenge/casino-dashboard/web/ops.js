// -------------------------------------------------------------------
// Globals for rhythm timing
// -------------------------------------------------------------------
let lastStateTs = null;
let rhythmBucketSeconds = null;

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------
async function jsonFetch(url, opts = {}) {
  const r = await fetch(url, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  return { ok: r.ok, status: r.status, data };
}

function pretty(obj) {
  return JSON.stringify(obj, null, 2);
}

function handleStateUpdate(state) {
  if (!state || !state.ts) return;

  lastStateTs = state.ts;

  // Token 1 rhythm bucket duration (static for challenge)
  if (!rhythmBucketSeconds) {
    rhythmBucketSeconds = 45; // RHYTHM_BUCKET_SECONDS
  }
}

// -------------------------------------------------------------------
// STATE POLLING (authoritative, single source)
// -------------------------------------------------------------------
async function pollState() {
  try {
    const res = await jsonFetch("/terminal/state");
    if (!res.ok || !res.data) return;

    handleStateUpdate(res.data);

    const out = document.getElementById("stateOut");
    if (out) {
      out.textContent = `STATE (${res.status})\n` + pretty(res.data);
    }
  } catch (_) {}
}

// poll every second
setInterval(pollState, 1000);
pollState();


// -------------------------------------------------------------------
// SHIFT SYNC SUBMIT
// -------------------------------------------------------------------
document.getElementById("syncBtn").addEventListener("click", async () => {
  const sync = document.getElementById("syncCode").value.trim();
  const bucketRaw = document.getElementById("syncBucket")?.value.trim();

  if (!/^[0-9a-f]{16}$/i.test(sync)) {
    alert("Sync code must be exactly 16 hex characters");
    return;
  }

  const body = { sync: sync.toLowerCase() };

  if (bucketRaw && /^\d+$/.test(bucketRaw)) {
    body.bucket = Number(bucketRaw);
  }

  const out = document.getElementById("stateOut");
  const res = await jsonFetch("/terminal/shift/sync", {
    method: "POST",
    body: JSON.stringify(body),
  });

  out.textContent =
    `SHIFT SYNC RESPONSE (${res.status})\n` + pretty(res.data);
});

// -------------------------------------------------------------------
// RECEIPT
// -------------------------------------------------------------------
document.getElementById("receiptBtn").addEventListener("click", async () => {
  const out = document.getElementById("receiptOut");
  const res = await jsonFetch("/terminal/receipts/latest");
  out.textContent = `RECEIPT (${res.status})\n` + pretty(res.data);
});

// -------------------------------------------------------------------
// FIRMWARE
// -------------------------------------------------------------------
document.getElementById("fwCatalogBtn").addEventListener("click", async () => {
  const out = document.getElementById("fwCatalogOut");
  const res = await jsonFetch("/terminal/firmware/catalog");
  out.textContent = `CATALOG (${res.status})\n` + pretty(res.data);
});

document.getElementById("fwUploadBtn").addEventListener("click", async () => {
  const out = document.getElementById("fwUploadOut");
  const f = document.getElementById("fwFile").files[0];
  if (!f) {
    out.textContent = "Select a firmware bundle first.";
    return;
  }

  const fd = new FormData();
  fd.append("file", f);

  const r = await fetch("/terminal/firmware/drop", { method: "POST", body: fd });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }

  out.textContent = `UPLOAD (${r.status})\n` + pretty(data);
});

// -------------------------------------------------------------------
// BUCKET COUNTDOWN (CRITICAL FIX)
// -------------------------------------------------------------------
function startBucketCountdown() {
  const timerEl = document.getElementById("bucketTimer");
  const wrapEl  = document.getElementById("bucketCountdown");
  const bucketInput = document.getElementById("syncBucket");

  if (!timerEl || !wrapEl) return;

  setInterval(() => {
    if (!lastStateTs || !rhythmBucketSeconds) {
      timerEl.textContent = "--";
      return;
    }


    const now = Math.floor(Date.now() / 1000);
    const elapsed = now - lastStateTs;
    const remaining =
      rhythmBucketSeconds - (elapsed % rhythmBucketSeconds);

    timerEl.textContent = remaining;

    // auto-fill bucket exactly at rollover
    if (remaining === rhythmBucketSeconds - 1 && bucketInput) {
      const bucketNow = Math.floor(now / rhythmBucketSeconds);
      bucketInput.value = bucketNow;
    }

    wrapEl.classList.remove("good", "warn");

    if (remaining <= 5) {
      wrapEl.classList.add("good");   // SAFE submit window
    } else if (remaining <= 10) {
      wrapEl.classList.add("warn");   // caution
    }
  }, 1000);
}

setInterval(pollState, 1000);

startBucketCountdown();

const express = require("express");
const multer = require("multer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10_000_000 } });

// --------------------
// CONFIG
// --------------------

// Must match generate.js SECRET
const SECRET_MAC = Buffer.from("0123456789abcdef", "utf8"); // 16 bytes

// IMPORTANT: make AES key stable across restarts (recommended for CTF)
const AES_KEY = process.env.AES_KEY
  ? Buffer.from(process.env.AES_KEY, "hex")
  : crypto.randomBytes(16); // fallback (tokens break on restart if not set)

// Affine params (must match generator)
const AFFINE_A = 5;
const AFFINE_B = 0x22;
const AFFINE_A_INV = 205; // inverse of 5 mod 256

// Flags (set via env in docker-compose if you want)
const FLAG_Q1 = process.env.TOKEN1;
const FLAG_Q2 = process.env.TOKEN2;
const FLAG_Q3 = process.env.TOKEN3;
const FLAG_Q4 = process.env.TOKEN4;

// In-memory submission store: id -> { tracks, grade, createdAt }
const SUBMISSIONS = new Map();
const SUBMISSION_TTL_MS = 30 * 60 * 1000; // 30 minutes

// Cache original parsed tracks at startup
let ORIGINAL_TRACKS = null;

// --------------------
// HELPERS
// --------------------
function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}
function prefixMac(secret, message) {
  return sha256(Buffer.concat([secret, message]));
}
function timingSafeEq(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function isoFromMs(t_ms) {
  return new Date(t_ms).toISOString();
}

// Affine256 decode: p = a_inv*(c-b) mod 256
function affineDecode(buf) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i];
    const x = (c - AFFINE_B) & 0xff;
    out[i] = (AFFINE_A_INV * x) & 0xff;
  }
  return out;
}

// Parse wrapped file footer: [encodedMsg][payloadLen][mac]
function splitFileFooter(fileBuf) {
  const macLen = 32;
  const lenLen = 4;
  if (fileBuf.length < macLen + lenLen + 4) throw new Error("file too small");

  const mac = fileBuf.subarray(fileBuf.length - macLen);
  const payloadLen = fileBuf.readUInt32BE(fileBuf.length - macLen - lenLen);
  const encodedMsg = fileBuf.subarray(0, fileBuf.length - macLen - lenLen);
  return { encodedMsg, payloadLen, mac };
}

// Parse coords payload (original format)
function parseCoordsPayload(buf) {
  let off = 0;
  const need = (n) => {
    if (off + n > buf.length) throw new Error(`parse past end at 0x${off.toString(16)}`);
  };

  need(4);
  const trackCount = buf.readUInt32BE(off); off += 4;
  if (trackCount > 1000) throw new Error("trackCount too large");

  const tracks = [];
  for (let ti = 0; ti < trackCount; ti++) {
    need(4);
    const nameLen = buf.readUInt32BE(off); off += 4;
    if (nameLen > 256) throw new Error("nameLen too large");
    need(nameLen);
    const name = buf.subarray(off, off + nameLen).toString("utf8");
    off += nameLen;

    need(4);
    const pointCount = buf.readUInt32BE(off); off += 4;
    if (pointCount > 200000) throw new Error("pointCount too large");

    const points = [];
    for (let pi = 0; pi < pointCount; pi++) {
      need(8 + 8 + 8);
      const t_ms = Number(buf.readBigUInt64BE(off)); off += 8;
      const lat = buf.readDoubleBE(off); off += 8;
      const lon = buf.readDoubleBE(off); off += 8;
      points.push({ t_ms, lat, lon });
    }

    tracks.push({ name, points });
  }

  return { trackCount, tracks, bytesConsumed: off };
}

function flightStats(track) {
  const pts = track.points;
  if (pts.length < 2) return { start_ms: null, end_ms: null, duration_s: 0, start_iso: null, end_iso: null };

  const start_ms = pts[0].t_ms;
  const end_ms = pts[pts.length - 1].t_ms;
  const duration_s = Math.max(0, Math.round((end_ms - start_ms) / 1000));
  return {
    start_ms,
    end_ms,
    duration_s,
    start_iso: isoFromMs(start_ms),
    end_iso: isoFromMs(end_ms),
  };
}

// Token crypto (AES-CBC, intentionally no MAC)
function cbcEncryptToken(plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-128-cbc", AES_KEY, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return { iv, ct };
}
function cbcDecryptToken(iv, ct) {
  const decipher = crypto.createDecipheriv("aes-128-cbc", AES_KEY, iv);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt;
}

// KML: placemark per point
function xmlEscape(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}
function htmlEscape(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
function tracksToKmlPlacemarks(tracks) {
  const placemarks = [];

  for (const track of tracks) {
    const nameEsc = xmlEscape(track.name);
    for (const p of track.points) {
      const when = isoFromMs(p.t_ms);
      const coords = `${p.lon},${p.lat},0`;

      placemarks.push(`
    <Placemark>
      <name>${nameEsc} - ${xmlEscape(when)}</name>
      <TimeStamp><when>${xmlEscape(when)}</when></TimeStamp>
      <Point>
        <coordinates>${coords}</coordinates>
      </Point>
    </Placemark>`.trim());
    }
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>Skynet Flights</name>
${placemarks.join("\n")}
  </Document>
</kml>`;
}

// Basic cleanup to avoid unbounded memory growth
function cleanupSubmissions() {
  const now = Date.now();
  for (const [id, sub] of SUBMISSIONS.entries()) {
    if (!sub || !sub.createdAt || now - sub.createdAt > SUBMISSION_TTL_MS) {
      SUBMISSIONS.delete(id);
    }
  }
}

// --------------------
// GRADER HELPERS
// --------------------
function approxEq(a, b, eps = 1e-9) {
  return Math.abs(a - b) <= eps;
}

// Toronto box (deterministic “not in US” indicator)
function inTorontoBox(lat, lon) {
  // wide enough to include your Toronto track, but not the US tracks
  return (lat >= 43.4 && lat <= 44.1 && lon >= -80.2 && lon <= -78.5);
}

function durationMs(track) {
  const pts = track.points;
  if (pts.length < 2) return 0;
  return pts[pts.length - 1].t_ms - pts[0].t_ms;
}

// Haversine meters
function haversineMeters(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const toRad = (d) => (d * Math.PI) / 180;
  const p1 = toRad(lat1), p2 = toRad(lat2);
  const dphi = toRad(lat2 - lat1);
  const dl = toRad(lon2 - lon1);
  const a = Math.sin(dphi / 2) ** 2 + Math.cos(p1) * Math.cos(p2) * Math.sin(dl / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function pathDistanceMeters(track) {
  const pts = track.points;
  let total = 0;
  for (let i = 1; i < pts.length; i++) {
    total += haversineMeters(pts[i - 1].lat, pts[i - 1].lon, pts[i].lat, pts[i].lon);
  }
  return total;
}

function findIdxLastAlphabetical(tracks) {
  let bestIdx = 0;
  let bestName = tracks[0]?.name ?? "";
  for (let i = 1; i < tracks.length; i++) {
    if (tracks[i].name.localeCompare(bestName) > 0) {
      bestName = tracks[i].name;
      bestIdx = i;
    }
  }
  return bestIdx;
}

function findIdxToronto(tracks) {
  // “only drone not in US” = any point in toronto box (deterministic)
  for (let i = 0; i < tracks.length; i++) {
    const pts = tracks[i].points;
    if (pts.some(p => inTorontoBox(p.lat, p.lon))) return i;
  }
  return -1;
}

function findIdxLongestDuration(tracks) {
  let bestIdx = 0;
  let best = durationMs(tracks[0]);
  for (let i = 1; i < tracks.length; i++) {
    const d = durationMs(tracks[i]);
    if (d > best) { best = d; bestIdx = i; }
  }
  return bestIdx;
}

function findIdxLongestPath(tracks) {
  let bestIdx = 0;
  let best = pathDistanceMeters(tracks[0]);
  for (let i = 1; i < tracks.length; i++) {
    const d = pathDistanceMeters(tracks[i]);
    if (d > best) { best = d; bestIdx = i; }
  }
  return bestIdx;
}

function gradeSubmission(subTracks) {
  const base = ORIGINAL_TRACKS;
  if (!base) throw new Error("grader not initialized");

  if (!Array.isArray(subTracks) || subTracks.length !== base.length) {
    return {
      okAll: false,
      q1: { ok: false, msg: "Track count mismatch" },
      q2: { ok: false, msg: "Track count mismatch" },
      q3: { ok: false, msg: "Track count mismatch" },
      q4: { ok: false, msg: "Track count mismatch" },
    };
  }

  // Indices from ORIGINAL
  const idxQ1 = findIdxLastAlphabetical(base);
  const idxQ2 = findIdxToronto(base);
  const idxQ3 = findIdxLongestDuration(base);
  const idxQ4 = findIdxLongestPath(base);

  // ---- Q1: rename last alphabetical to Jet Streamer
  const q1ok = (subTracks[idxQ1]?.name === "Jet Streamer");
  const q1 = { ok: q1ok, msg: q1ok ? "OK" : `Expected tracks[${idxQ1}].name == "Jet Streamer"` };

  // ---- Q2: Toronto drone lat/lon -= 5 for every point, timestamps unchanged
  let q2ok = true;
  let q2msg = "OK";
  if (idxQ2 < 0) {
    q2ok = false; q2msg = "Could not find Toronto track in original";
  } else {
    const b = base[idxQ2].points;
    const s = subTracks[idxQ2].points;
    if (!s || s.length !== b.length) {
      q2ok = false; q2msg = `tracks[${idxQ2}] point count mismatch`;
    } else {
      for (let i = 0; i < b.length; i++) {
        const bt = b[i], st = s[i];
        if (st.t_ms !== bt.t_ms) { q2ok = false; q2msg = `tracks[${idxQ2}] timestamp changed at point ${i}`; break; }
        if (!approxEq(st.lat, bt.lat - 5, 1e-9) || !approxEq(st.lon, bt.lon - 5, 1e-9)) {
          q2ok = false; q2msg = `tracks[${idxQ2}] expected lat/lon -= 5 at point ${i}`; break;
        }
      }
    }
  }
  const q2 = { ok: q2ok, msg: q2msg };

  // ---- Q3: longest duration track add +3 seconds between each coordinate (cumulative)
  let q3ok = true;
  let q3msg = "OK";
  {
    const b = base[idxQ3].points;
    const s = subTracks[idxQ3].points;
    if (!s || s.length !== b.length) {
      q3ok = false; q3msg = `tracks[${idxQ3}] point count mismatch`;
    } else {
      for (let i = 0; i < b.length; i++) {
        const expectedT = b[i].t_ms + i * 3000;
        if (s[i].t_ms !== expectedT) {
          q3ok = false;
          q3msg = `tracks[${idxQ3}] expected t_ms[${i}] == orig + ${i}*3000`;
          break;
        }
      }
    }
  }
  const q3 = { ok: q3ok, msg: q3msg };

  // ---- Q4: longest path track reverse lat/lon order, keep timestamps increasing (original order)
  let q4ok = true;
  let q4msg = "OK";
  {
    const b = base[idxQ4].points;
    const s = subTracks[idxQ4].points;
    if (!s || s.length !== b.length) {
      q4ok = false; q4msg = `tracks[${idxQ4}] point count mismatch`;
    } else {
      const n = b.length;
      for (let i = 0; i < n; i++) {
        // timestamps must stay original order
        if (s[i].t_ms !== b[i].t_ms) {
          q4ok = false; q4msg = `tracks[${idxQ4}] timestamp must not be reversed (mismatch at point ${i})`;
          break;
        }
        // lat/lon must be reversed
        const br = b[n - 1 - i];
        if (!approxEq(s[i].lat, br.lat, 1e-9) || !approxEq(s[i].lon, br.lon, 1e-9)) {
          q4ok = false; q4msg = `tracks[${idxQ4}] expected reversed lat/lon at point ${i}`;
          break;
        }
      }
    }
  }
  const q4 = { ok: q4ok, msg: q4msg };

  const okAll = q1.ok && q2.ok && q3.ok && q4.ok;

  return { okAll, q1, q2, q3, q4 };
}

// Load ORIGINAL tracks from /app/uploads/coords.bin at startup
function loadOriginalTracksOrThrow() {
  const filePath = path.join(__dirname, "uploads", "coords.bin");
  if (!fs.existsSync(filePath)) throw new Error(`Missing original coords.bin at ${filePath}`);

  const buf = fs.readFileSync(filePath);
  const { encodedMsg, payloadLen } = splitFileFooter(buf);
  const decoded = affineDecode(encodedMsg);
  const payload = decoded.subarray(0, payloadLen);
  const parsed = parseCoordsPayload(payload);
  return parsed.tracks;
}

// --------------------
// ROUTES
// --------------------
app.get("/", (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.setHeader("X-Encode", "affine256");
  res.end(`
<!doctype html>
<html>
<head>
  <title>Skynet</title>
  <meta name="encode" content="affine256">
</head>
<body>
  <h1>Skynet</h1>

  <p><a href="/uploads/coords.bin"><button>Download Flight Data</button></a></p>

  <h2>Preview</h2>
  <form action="/preview" method="post" enctype="multipart/form-data">
    <input type="file" name="file" />
    <button type="submit">Upload to Preview</button>
  </form>

  <h2>Submit</h2>
  <form action="/submit" method="post" enctype="multipart/form-data">
    <input type="file" name="file" />
    <button type="submit">Upload to Submit</button>
  </form>

</body>
</html>
  `);
});

// Serve challenge file from /app/uploads/coords.bin (since __dirname=/app)
app.get("/uploads/coords.bin", (req, res) => {
  const filePath = path.join(__dirname, "uploads", "coords.bin");
  if (!fs.existsSync(filePath)) return res.status(404).send("File not found");
  res.writeHead(200, {
    "Content-Type": "application/octet-stream",
    "Content-Disposition": 'attachment; filename="coords.bin"',
    "X-Encode": "affine256",
  });
  fs.createReadStream(filePath).pipe(res);
});

// Preview: decode + parse + pretty JSON (with ISO timestamps)
app.post("/preview", upload.single("file"), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const { encodedMsg, payloadLen } = splitFileFooter(req.file.buffer);
    const decodedMsg = affineDecode(encodedMsg);

    const payload = decodedMsg.subarray(0, payloadLen);
    const parsed = parseCoordsPayload(payload);

    const tracks = parsed.tracks.map(t => ({
      name: t.name,
      stats: flightStats(t),
      points: t.points.map(p => ({
        t_ms: p.t_ms,
        t_iso: isoFromMs(p.t_ms),
        lat: p.lat,
        lon: p.lon,
      })),
    }));

    res.setHeader("X-Encode", "affine256");
    res.json({
      mode: "preview",
      payloadLen,
      trackCount: parsed.trackCount,
      tracks,
    });
  } catch (e) {
    res.status(400).json({ error: "PREVIEW_FAILED", message: String(e.message || e) });
  }
});

// Submit: verify MAC + store tracks + grade + redirect to /map with CBC token
app.post("/submit", upload.single("file"), (req, res) => {
  try {
    cleanupSubmissions();
    if (!req.file) return res.status(400).send("No file uploaded");

    const { encodedMsg, payloadLen, mac } = splitFileFooter(req.file.buffer);
    const decodedMsg = affineDecode(encodedMsg);

    // MAC computed over plaintext payload only
    const payload = decodedMsg.subarray(0, payloadLen);
    const expected = prefixMac(SECRET_MAC, payload);
    const hashOk = timingSafeEq(expected, mac);

    // Parse tracks
    const parsed = parseCoordsPayload(payload);

    // Grade (based on ORIGINAL_TRACKS)
    const grade = gradeSubmission(parsed.tracks);

    // Store submission for /map
    const id = crypto.randomBytes(8).toString("hex"); // 16 hex chars
    SUBMISSIONS.set(id, { tracks: parsed.tracks, grade, createdAt: Date.now() });

    // chk is what players flip FAIL -> PASS via CBC bitflipping
    const chk = hashOk ? "PASS" : "FAIL";

    // Keep this block-structure stable for the bitflip challenge
    const tokenPlain = `Hash_Check=${chk} ` + `id=${id};`;

    const { iv, ct } = cbcEncryptToken(tokenPlain);
    const url = `/map?iv=${iv.toString("hex")}&t=${ct.toString("hex")}`;
    res.redirect(302, url);
  } catch (e) {
    res.status(400).send(`SUBMIT_FAILED: ${String(e.message || e)}`);
  }
});

// Map: decrypt token, gate on PASS, show flags + KML
app.get("/map", (req, res) => {
  try {
    const ivHex = req.query.iv;
    const tHex = req.query.t;
    if (!ivHex || !tHex) return res.status(400).send("Missing iv or t");

    const iv = Buffer.from(ivHex, "hex");
    const ct = Buffer.from(tHex, "hex");
    if (iv.length !== 16) return res.status(400).send("Bad IV length");

    let pt;
    try {
      pt = cbcDecryptToken(iv, ct);
    } catch {
      res.setHeader("Content-Type", "text/plain");
      return res.end("Invalid token (decrypt/padding error)\n");
    }

    const shown = pt.subarray(0, 16).toString("utf8", 0, 16);
    const full = pt.toString("utf8");

    // Oracle feedback (used for bitflip)
    if (!shown.includes("Hash_Check=PASS")) {
      res.setHeader("Content-Type", "text/plain");
      res.write(`Decrypted: ${shown}\n`);
      return res.end("Invalid Hash\n");
    }

    // Extract submission id
    const m = full.match(/id=([0-9a-f]{16})/);
    if (!m) {
      res.setHeader("Content-Type", "text/plain");
      res.write(`Decrypted: ${shown}\n`);
      return res.end("Missing id\n");
    }

    const id = m[1];
    const sub = SUBMISSIONS.get(id);
    if (!sub) {
      res.setHeader("Content-Type", "text/plain");
      res.write(`Decrypted: ${shown}\n`);
      return res.end("Unknown submission id (expired?)\n");
    }

    const kml = tracksToKmlPlacemarks(sub.tracks);

    // Optional raw output
    if (req.query.raw === "1") {
      res.setHeader("Content-Type", "application/vnd.google-earth.kml+xml");
      return res.end(kml);
    }

    const g = sub.grade || { okAll: false };

    // Show flags per-question when correct
    const flagsHtml = `
      <div style="margin:12px 0; padding:12px; border-radius:10px; background:#0b1220; color:#e7eefc;">
        <div style="font-weight:800; color:#22c55e;">Hash_Check=PASS</div>
        <div style="margin-top:8px; line-height:1.6;">
          <div>Q1: ${g.q1?.ok ? `<b style="color:#22c55e">${htmlEscape(FLAG_Q1)}</b>` : `<span style="color:#f87171">incorrect</span>`}</div>
          <div>Q2: ${g.q2?.ok ? `<b style="color:#22c55e">${htmlEscape(FLAG_Q2)}</b>` : `<span style="color:#f87171">incorrect</span>`}</div>
          <div>Q3: ${g.q3?.ok ? `<b style="color:#22c55e">${htmlEscape(FLAG_Q3)}</b>` : `<span style="color:#f87171">incorrect</span>`}</div>
          <div>Q4: ${g.q4?.ok ? `<b style="color:#22c55e">${htmlEscape(FLAG_Q4)}</b>` : `<span style="color:#f87171">incorrect</span>`}</div>
        </div>
      </div>
    `;

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.end(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Skynet Map Output</title>
  <style>
    body { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; margin: 20px; background:#070b12; color:#e5e7eb; }
    pre { white-space: pre-wrap; word-break: break-word; background: #111; color: #eee; padding: 14px; border-radius: 8px; }
    a { color: #60a5fa; }
  </style>
</head>
<body>
  ${flagsHtml}
  <p><a href="?iv=${encodeURIComponent(req.query.iv)}&t=${encodeURIComponent(req.query.t)}&raw=1">Download raw KML</a></p>
  <pre>${htmlEscape(kml)}</pre>
</body>
</html>`);
  } catch (e) {
    res.status(400).send(`MAP_FAILED: ${String(e.message || e)}`);
  }
});

// --------------------
// STARTUP
// --------------------
try {
  ORIGINAL_TRACKS = loadOriginalTracksOrThrow();
  console.log(`[grader] Loaded ORIGINAL_TRACKS: ${ORIGINAL_TRACKS.length} tracks`);
} catch (e) {
  console.error(`[grader] FAILED to load original tracks: ${e.message || e}`);
  // fail fast so you notice immediately
  process.exit(1);
}

app.listen(80, () => console.log("web started on port 80"));

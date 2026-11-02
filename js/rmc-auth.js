/* ==========================================================================
   RMC — shared session + password helpers
   --------------------------------------------------------------------------
   Plain (non-module) script so it loads before the page's own <script
   type="module">. Include it in every page, in <head> or before the page
   script:

       <script src="./js/rmc-auth.js"></script>

   Exposes window.RMC with:
     RMC.requireAuth()        redirect to index.html unless signed in
     RMC.requireAdmin()       redirect unless signed in AS an admin
     RMC.currentUser()        { id, username, name, role }
     RMC.signIn(user)         store the session after a successful login
     RMC.signOut()            clear the session and go back to index.html
     RMC.stamp()              { recordedById, recordedByName, recordedAtLocal }
                              -> spread into every Firestore write
     RMC.hashPassword(pw)     -> { algo, iterations, salt, hash }
     RMC.verifyPassword(pw, userDoc)  -> true/false
     RMC.userDocId(username)  -> the users/ document id for a username

   Password hashing is PBKDF2-HMAC-SHA256 with a random per-user salt. It
   uses the browser's native Web Crypto when that is available (fast) and
   falls back to the bundled pure-JS implementation otherwise — crypto.subtle
   does NOT exist on file:// or plain http://, so the fallback is what makes
   this work when the pages are opened straight off disk. Both paths produce
   byte-identical results, so a password hashed on one works on the other.
   ========================================================================== */
(function (global) {
  "use strict";

  /* ---------------------------------------------------------------- bytes */
  const enc = new TextEncoder();

  function concatBytes(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }
  function toB64(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function fromB64(b64) {
    const s = atob(b64);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  function randomBytes(n) {
    const out = new Uint8Array(n);
    if (global.crypto && global.crypto.getRandomValues) {
      global.crypto.getRandomValues(out);
    } else {
      for (let i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
    }
    return out;
  }

  /* ------------------------------------------------------ SHA-256 (pure JS) */
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

  function sha256(bytes) {
    const H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
      0x1f83d9ab, 0x5be0cd19,
    ]);
    const ml = bytes.length;
    const total = ((ml + 9 + 63) >> 6) << 6; // pad to a multiple of 64
    const m = new Uint8Array(total);
    m.set(bytes);
    m[ml] = 0x80;
    const dv = new DataView(m.buffer);
    dv.setUint32(total - 8, Math.floor(ml / 536870912)); // high 32 bits of ml*8
    dv.setUint32(total - 4, (ml * 8) >>> 0);

    const w = new Uint32Array(64);
    for (let off = 0; off < total; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const x = w[i - 15];
        const y = w[i - 2];
        const s0 = (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0;
        const s1 = (rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10)) >>> 0;
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let a = H[0], b = H[1], c = H[2], d = H[3];
      let e = H[4], f = H[5], g = H[6], h = H[7];
      for (let i = 0; i < 64; i++) {
        const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
        const ch = ((e & f) ^ (~e & g)) >>> 0;
        const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
        const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
        const t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e;
        e = (d + t1) >>> 0;
        d = c; c = b; b = a;
        a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i]);
    return out;
  }

  function hmacSha256(keyBytes, msgBytes) {
    let k = keyBytes;
    if (k.length > 64) k = sha256(k);
    const padded = new Uint8Array(64);
    padded.set(k);
    const inner = new Uint8Array(64);
    const outer = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      inner[i] = padded[i] ^ 0x36;
      outer[i] = padded[i] ^ 0x5c;
    }
    return sha256(concatBytes(outer, sha256(concatBytes(inner, msgBytes))));
  }

  function pbkdf2Js(passwordBytes, saltBytes, iterations, dkLen) {
    const hLen = 32;
    const blocks = Math.ceil(dkLen / hLen);
    const out = new Uint8Array(blocks * hLen);
    for (let b = 1; b <= blocks; b++) {
      const idx = new Uint8Array([
        (b >>> 24) & 255, (b >>> 16) & 255, (b >>> 8) & 255, b & 255,
      ]);
      let u = hmacSha256(passwordBytes, concatBytes(saltBytes, idx));
      const t = u.slice();
      for (let i = 1; i < iterations; i++) {
        u = hmacSha256(passwordBytes, u);
        for (let x = 0; x < hLen; x++) t[x] ^= u[x];
      }
      out.set(t, (b - 1) * hLen);
    }
    return out.slice(0, dkLen);
  }

  /* ------------------------------------------------------------- PBKDF2 API */
  const PW_ALGO = "PBKDF2-SHA256";
  const PW_ITERATIONS = 100000;
  const PW_LEN = 32;

  function subtleAvailable() {
    return !!(global.crypto && global.crypto.subtle && global.crypto.subtle.importKey);
  }

  async function derive(password, saltBytes, iterations) {
    const pwBytes = enc.encode(String(password));
    if (subtleAvailable()) {
      try {
        const key = await global.crypto.subtle.importKey(
          "raw", pwBytes, "PBKDF2", false, ["deriveBits"]
        );
        const bits = await global.crypto.subtle.deriveBits(
          { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
          key,
          PW_LEN * 8
        );
        return new Uint8Array(bits);
      } catch (e) {
        // Fall through to the JS implementation (identical output).
        console.warn("Web Crypto PBKDF2 unavailable, using JS fallback.", e);
      }
    }
    return pbkdf2Js(pwBytes, saltBytes, iterations, PW_LEN);
  }

  async function hashPassword(password) {
    const salt = randomBytes(16);
    const hash = await derive(password, salt, PW_ITERATIONS);
    return {
      pwAlgo: PW_ALGO,
      pwIterations: PW_ITERATIONS,
      pwSalt: toB64(salt),
      pwHash: toB64(hash),
    };
  }

  function sameBytes(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  async function verifyPassword(password, userDoc) {
    if (!userDoc || !userDoc.pwHash || !userDoc.pwSalt) return false;
    const iterations = Number(userDoc.pwIterations) || PW_ITERATIONS;
    const got = await derive(password, fromB64(userDoc.pwSalt), iterations);
    return sameBytes(got, fromB64(userDoc.pwHash));
  }

  /* -------------------------------------------------------------- session */
  const SS = global.sessionStorage;
  const K_AUTH = "rmcAuth";
  const K_USER = "rmcUser";      // username — kept for backwards compatibility
  const K_ID   = "rmcUserId";
  const K_NAME = "rmcUserName";
  const K_ROLE = "rmcUserRole";
  const K_AT   = "rmcLoginAt";

  function isSignedIn() {
    try { return SS.getItem(K_AUTH) === "1"; } catch (e) { return false; }
  }

  function currentUser() {
    try {
      const username = SS.getItem(K_USER) || "";
      return {
        id: SS.getItem(K_ID) || username || null,
        username: username,
        // Sessions created before users existed only carry "admin".
        name: SS.getItem(K_NAME) || username || "admin",
        role: SS.getItem(K_ROLE) || (username === "admin" ? "admin" : "user"),
      };
    } catch (e) {
      return { id: null, username: "", name: "admin", role: "admin" };
    }
  }

  function signIn(user) {
    SS.setItem(K_AUTH, "1");
    SS.setItem(K_USER, user.username || "");
    SS.setItem(K_ID, user.id || user.username || "");
    SS.setItem(K_NAME, user.name || user.username || "");
    SS.setItem(K_ROLE, user.role || "user");
    SS.setItem(K_AT, String(Date.now()));
  }

  function signOut() {
    [K_AUTH, K_USER, K_ID, K_NAME, K_ROLE, K_AT].forEach((k) => {
      try { SS.removeItem(k); } catch (e) {}
    });
    global.location.replace("index.html");
  }

  function requireAuth() {
    if (!isSignedIn()) {
      global.location.replace("index.html");
      return false;
    }
    return true;
  }

  function requireAdmin() {
    if (!requireAuth()) return false;
    if (currentUser().role !== "admin") {
      alert("This page is for administrators only.");
      global.location.replace("Main.html");
      return false;
    }
    return true;
  }

  /* Spread into every Firestore write so each record carries its author. */
  function stamp() {
    const u = currentUser();
    return {
      recordedById: u.id || null,
      recordedByName: u.name || null,
      recordedAtLocal: new Date(),
    };
  }

  /* users/{id} — the document id is the lowercased username, which makes the
     username unique without needing an extra query or index. */
  function userDocId(username) {
    return String(username || "").trim().toLowerCase();
  }

  /* Render "Signed in as X" into an element, if the page has one. */
  function paintWhoAmI(selector) {
    const el = document.querySelector(selector || "#whoAmI");
    if (el) el.textContent = currentUser().name || "—";
  }

  global.RMC = {
    // passwords
    hashPassword, verifyPassword, userDocId,
    PW_ALGO, PW_ITERATIONS,
    // session
    isSignedIn, currentUser, signIn, signOut, requireAuth, requireAdmin,
    stamp, paintWhoAmI,
    // exposed for debugging / tests
    _sha256: sha256, _pbkdf2Js: pbkdf2Js, _toB64: toB64,
  };
})(window);

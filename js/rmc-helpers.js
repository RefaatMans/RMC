/* ==========================================================================
   RMC — shared formatting helpers.
   --------------------------------------------------------------------------
   A PLAIN (non-module) script on purpose. A relative `import` from a page
   opened as file:// is blocked by CORS, so shared code has to arrive this way
   to keep working whether the pages are served over http(s) or opened straight
   off disk. Include it before the page script:

       <script src="./js/rmc-helpers.js"></script>

   Everything hangs off window.RMCH.
   ========================================================================== */
(function (global) {
  "use strict";

  const pad2 = (n) => String(n).padStart(2, "0");

  /* Firestore hands back Timestamps; forms and seeds hand back Dates or
     strings. Normalise all of them to a Date (or null). */
  const toJsDate = (v) =>
    v && v.toDate ? v.toDate() : v instanceof Date ? v : v ? new Date(v) : null;

  const fmtMoney = (n) => {
    const v = Number(n || 0);
    return (v < 0 ? "-" : "") + Math.abs(v).toFixed(2);
  };

  const fmtDate = (d) =>
    d ? `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}` : "—";

  const fmtTime = (d) => {
    if (!d) return "—";
    const mer = d.getHours() >= 12 ? "PM" : "AM";
    const hh = d.getHours() % 12 || 12;
    return `${hh}:${pad2(d.getMinutes())} ${mer}`;
  };

  const fmtDateTime = (d) => (d ? `${fmtDate(d)} ${fmtTime(d)}` : "—");

  const todayISO = () => fmtDate(new Date());

  function dayBounds(dateStr) {
    const d = new Date(dateStr);
    return [
      new Date(d.getFullYear(), d.getMonth(), d.getDate(), 0, 0, 0, 0),
      new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1, 0, 0, 0, 0),
    ];
  }

  // Combine a date-only picker value with the current clock time, so an entry
  // is filed on the day you chose but still carries a real transaction time.
  function stampedDate(dateStr) {
    const now = new Date();
    const [y, m, d] = String(dateStr).split("-").map(Number);
    return new Date(y, m - 1, d, now.getHours(), now.getMinutes(), now.getSeconds(), now.getMilliseconds());
  }

  const byName = (a, b) =>
    (a.name || "").localeCompare(b.name || "", undefined, { sensitivity: "base" });

  /* A cash entry's real moment. Entries written before the time fix stored
     `date` at midnight, so fall back to createdAt for those. */
  function cashMoment(x) {
    const d = toJsDate(x.date);
    if (d && (d.getHours() || d.getMinutes() || d.getSeconds())) return d;
    const created = toJsDate(x.createdAt) || toJsDate(x.recordedAtLocal);
    if (created && d) {
      // Keep the entry on the day it was filed under, but show a real time.
      const sameDay =
        created.getFullYear() === d.getFullYear() &&
        created.getMonth() === d.getMonth() &&
        created.getDate() === d.getDate();
      return sameDay ? created : d;
    }
    return d || created;
  }

  /* Signed value of a cash row, tolerant of older docs without signedAmount. */
  function cashSigned(x) {
    if (x.signedAmount != null) return Number(x.signedAmount);
    const a = Math.abs(Number(x.amount || 0));
    return x.type === "out" ? -a : a;
  }

  /* One-time write ticket used as a Firestore document id, so a retried or
     double-clicked write lands on the SAME doc instead of creating a second. */
  function newOpId() {
    return global.crypto && global.crypto.randomUUID
      ? global.crypto.randomUUID()
      : Date.now() + "-" + Math.random().toString(36).slice(2, 10);
  }

  /* For pages that include <div class="toast" id="toast"></div> */
  function showToast(msg) {
    const el = document.getElementById("toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => el.classList.remove("show"), 2400);
  }

  /* An appointment whose note says it was called off. Matched on stems so
     "cancel", "canceled", "cancelled", "cancellation", "reschedule",
     "rescheduled", "postponed" all count. Add words here to extend it. */
  const VOID_NOTE_STEMS = ["cancel", "reschedul", "postpon"];
  function isVoidNote(comment) {
    const t = String(comment == null ? "" : comment).toLowerCase();
    return VOID_NOTE_STEMS.some((w) => t.includes(w));
  }

  /* Escape text before it goes into innerHTML. */
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );
  }

  /* The Firebase project this app talks to. */
  const firebaseConfig = {
    apiKey: "AIzaSyCy2-qGCMMlNsSuKrqSVUBELsiwQXUN19w",
    authDomain: "rmc-db-486f0.firebaseapp.com",
    projectId: "rmc-db-486f0",
    storageBucket: "rmc-db-486f0.firebasestorage.app",
    messagingSenderId: "711840343507",
    appId: "1:711840343507:web:21bf0e1c9448072ce47b26",
  };

  global.RMCH = {
    pad2, toJsDate, fmtMoney, fmtDate, fmtTime, fmtDateTime, todayISO,
    dayBounds, stampedDate, byName, cashMoment, cashSigned, newOpId,
    showToast, esc, firebaseConfig, isVoidNote, VOID_NOTE_STEMS,
  };
})(window);

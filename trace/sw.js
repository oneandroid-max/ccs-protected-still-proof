// trace/sw.js — the smallest service worker: it caches nothing and changes nothing. It exists so the
// traceable page can be installed as a web app on Android for research row 1 (does an installed web
// app get any capture refusal? expected: no).
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("fetch", () => {});

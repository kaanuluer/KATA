var CACHE = "gab-portal-shell-1";
var SHELL = [
  "/portal",
  "/assets/portal.js",
  "/assets/app.css",
  "/assets/gab-logo.svg",
  "/assets/gab-icon-192.png",
  "/assets/gab-icon-512.png",
  "/assets/gab-icon-180.png",
  "/manifest.webmanifest"
];
var OFFLINE = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Portal offline</title><style>body{margin:0;background:#13203B;color:#F3F7F7;font:17px/1.5 sans-serif;padding:32px}h1{font-weight:500}p{max-width:36em}</style></head><body><p>GAB_</p><h1>The portal is offline</h1><p>Open it again when the connection returns. Nothing new is stored while this page is offline.</p></body></html>";

self.addEventListener("install", function (event) {
  event.waitUntil(caches.open(CACHE).then(function (cache) { return cache.addAll(SHELL); }));
  self.skipWaiting();
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.filter(function (key) { return key !== CACHE; }).map(function (key) { return caches.delete(key); }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener("fetch", function (event) {
  var request = event.request;
  if (request.method !== "GET") return;
  var url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.indexOf("/v1/") === 0) return;
  event.respondWith(
    fetch(request).then(function (response) {
      if (response.ok && SHELL.indexOf(url.pathname) !== -1) {
        var copy = response.clone();
        caches.open(CACHE).then(function (cache) { cache.put(request, copy); });
      }
      return response;
    }).catch(function () {
      return caches.match(request).then(function (cached) {
        if (cached) return cached;
        if (request.mode === "navigate") {
          return new Response(OFFLINE, { headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        return new Response("", { status: 503 });
      });
    })
  );
});

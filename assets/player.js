(function () {
'use strict';
var C = JSON.parse(document.getElementById('cfg').textContent);
var $ = function (s) { return document.querySelector(s); };
var app = $('#app'), v = $('#v'), spin = $('#spin'), msg = $('#msg'), msgt = $('#msgt'), retry = $('#retry');
var ENTRY = 'https://s.invalid/m.m3u8';
var hls = null, cur = 0, ticket = C.k, started = false, tripped = false, failCount = 0, tried = 1, idleT = null;

/* ---------------------------------------------------------------- helpers */
function fnv(s) { var h = 0x811c9dc5; for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; } return h.toString(16); }
function proof() { return fnv(C.c + '|' + C.sid + '|' + (tripped ? 'bad' : 'ok')); }
function beacon(o) {
  try {
    var b = new URLSearchParams(o); b.set('a', 'b'); b.set('s', C.sid);
    if (navigator.sendBeacon) { navigator.sendBeacon(C.x, b); } else { fetch(C.x, { method: 'POST', body: b, keepalive: true }); }
  } catch (e) {}
}
function showSpin(on) { spin.hidden = !on; }
function showMsg(t, canRetry) { showSpin(false); msgt.textContent = t; retry.hidden = !canRetry; msg.hidden = false; }
function hideMsg() { msg.hidden = true; }

/* ---------------------------------------------------------------- guard (devtools / tamper) */
var guardOn = !!C.guard;
function dbgTime() { var t = performance.now(); try { (function () {}).constructor('debugger')(); } catch (e) {} return performance.now() - t; }
function killPlayer() {
  try { if (hls) { hls.destroy(); hls = null; } v.pause(); v.removeAttribute('src'); v.load(); } catch (e) {}
  app.classList.remove('playing', 'shown');
}
function trip(why) {
  if (tripped) { return; }
  tripped = true;
  beacon({ w: why });
  killPlayer();
  $('#servers').innerHTML = '';
  showMsg(C.msg, false);
  setInterval(function () { try { (function () {}).constructor('debugger')(); } catch (e) {} }, 60);
}
function guardPass() {
  if (tripped) { return false; }
  if (guardOn && dbgTime() > 120) { trip('dbg'); return false; }
  return true;
}
function startGuard() {
  if (!guardOn) { return; }
  if (navigator.webdriver) { trip('wd'); return; }
  if (window.top === window && C.prot) { trip('top'); return; }
  try {
    var ao = window.location.ancestorOrigins;
    if (C.doms.length && ao && ao.length) {
      var ok = false;
      for (var i = 0; i < ao.length; i++) {
        var h = new URL(ao[i]).hostname.toLowerCase();
        for (var j = 0; j < C.doms.length; j++) { var d = C.doms[j]; if (h === d || h.slice(-d.length - 1) === '.' + d) { ok = true; } }
      }
      if (!ok) { trip('anc'); return; }
    }
  } catch (e) {}
  var bait = new Image();
  Object.defineProperty(bait, 'id', { get: function () { trip('con'); return ''; } });
  setInterval(function () { if (dbgTime() > 120) { trip('dbg'); } try { console.debug(bait); } catch (e) {} }, 700);
  document.addEventListener('contextmenu', function (e) { e.preventDefault(); });
  document.addEventListener('keydown', function (e) {
    var k = (e.key || '').toLowerCase();
    if (e.keyCode === 123 || (e.ctrlKey && e.shiftKey && 'ijc'.indexOf(k) > -1) || (e.ctrlKey && 'us'.indexOf(k) > -1 && k) || (e.metaKey && e.altKey && 'iju'.indexOf(k) > -1 && k)) {
      e.preventDefault(); return false;
    }
  }, true);
  document.addEventListener('dragstart', function (e) { e.preventDefault(); });
}

/* ---------------------------------------------------------------- ads (click triggers; network pop-under scripts run on their own) */
var adCount = 0, adLast = 0, clicks = 0;
function adClick(kind) {
  var A = C.ads;
  if (!A.links.length) { return; }
  clicks++;
  if (clicks % A.every !== 0) { return; }
  if (A.max && adCount >= A.max) { return; }
  var now = Date.now();
  if (adCount > 0 && now - adLast < A.cool * 1000) { return; }
  var u = A.links[adCount % A.links.length];
  adCount++; adLast = now;
  var w = null;
  try { w = window.open(u, '_blank'); } catch (e) {}
  try { if (w) { w.blur(); window.focus(); } } catch (e) {}
  beacon({ w: 'ad', k: kind });
}

/* ---------------------------------------------------------------- hls.js loader: everything goes through our tokenised endpoint */
function SLoader() { this.stats = newStats(); this.ac = null; this.context = null; }
function newStats() {
  return { aborted: false, loaded: 0, retry: 0, total: 0, chunkCount: 0, bwEstimate: 0,
    loading: { start: 0, first: 0, end: 0 }, parsing: { start: 0, end: 0 }, buffering: { start: 0, first: 0, end: 0 } };
}
SLoader.prototype.destroy = function () { this.abort(); this.ac = null; };
SLoader.prototype.abort = function () { if (this.ac && !this.stats.loading.end) { this.stats.aborted = true; try { this.ac.abort(); } catch (e) {} } };
SLoader.prototype.getCacheAge = function () { return null; };
SLoader.prototype.getResponseHeader = function () { return null; };
SLoader.prototype.load = function (ctx, cfg, cb) {
  var s = this.stats, done = false;
  this.context = ctx;
  s.loading.start = performance.now();
  var ac = this.ac = new AbortController();
  var tmo = (cfg && (cfg.maxLoadTimeMs || cfg.timeout)) || 20000;
  var timer = setTimeout(function () { if (done) { return; } done = true; try { ac.abort(); } catch (e) {} cb.onTimeout(s, ctx, null); }, tmo);
  var url = ctx.url, opts = { signal: ac.signal, cache: 'no-store', credentials: 'omit' }, isEntry = url === ENTRY;
  if (isEntry) {
    url = C.x; opts.method = 'POST';
    opts.body = new URLSearchParams({ a: 'p', s: C.sid, k: ticket, z: proof(), st: String(cur) });
  } else if (ctx.rangeEnd) {
    opts.headers = { Range: 'bytes=' + ctx.rangeStart + '-' + (ctx.rangeEnd - 1) };
  }
  fetch(url, opts).then(function (r) {
    s.loading.first = performance.now();
    if (isEntry) { var nk = r.headers.get('X-K'); if (nk) { ticket = nk; } }
    if (!r.ok && r.status !== 206) { throw { code: r.status, text: r.statusText }; }
    return (ctx.responseType === 'arraybuffer' ? r.arrayBuffer() : r.text()).then(function (data) { return { r: r, data: data }; });
  }).then(function (o) {
    if (done) { return; }
    done = true; clearTimeout(timer);
    s.loading.end = performance.now();
    s.loaded = s.total = o.data.byteLength !== undefined ? o.data.byteLength : o.data.length;
    cb.onSuccess({ url: ctx.url, data: o.data }, s, ctx, o.r);
  }).catch(function (e) {
    if (done) { return; }
    done = true; clearTimeout(timer);
    if (s.aborted || (e && e.name === 'AbortError')) { if (cb.onAbort) { cb.onAbort(s, ctx, null); } return; }
    cb.onError({ code: (e && e.code) || 0, text: (e && e.text) || String(e) }, ctx, null, s);
  });
};

/* ---------------------------------------------------------------- playback */
function destroyHls() { if (hls) { try { hls.destroy(); } catch (e) {} hls = null; } }
function startStream(i, auto) {
  if (!guardPass()) { return; }
  if (!auto) { tried = 1; }
  cur = i; failCount = 0;
  hideMsg(); showSpin(true); markServers();
  destroyHls();
  if (window.Hls && window.Hls.isSupported()) {
    hls = new window.Hls({
      loader: SLoader, enableWorker: true, lowLatencyMode: false,
      liveSyncDurationCount: 3, liveMaxLatencyDurationCount: 8,
      maxBufferLength: 20, maxMaxBufferLength: 40, backBufferLength: 30,
      manifestLoadingMaxRetry: 1, levelLoadingMaxRetry: 3, fragLoadingMaxRetry: 4,
      capLevelToPlayerSize: true, startLevel: -1
    });
    hls.on(window.Hls.Events.MANIFEST_PARSED, function () { buildQuality(); var p = v.play(); if (p && p.catch) { p.catch(function () {}); } });
    hls.on(window.Hls.Events.ERROR, onHlsError);
    hls.loadSource(ENTRY);
    hls.attachMedia(v);
  } else if (v.canPlayType('application/vnd.apple.mpegurl')) {
    v.src = C.x + '?a=n&s=' + C.sid + '&k=' + ticket + '&z=' + proof() + '&st=' + i;
    var p = v.play(); if (p && p.catch) { p.catch(function () {}); }
  } else {
    showMsg('المتصفح لا يدعم تشغيل هذا البث.', false);
  }
}
function nextServer() {
  var n = C.names.length;
  if (n > 1 && tried < n) { tried++; startStream((cur + 1) % n, true); return; }
  showMsg('تعذّر تشغيل البث حالياً. حاول مرة أخرى بعد لحظات.', true);
}
function onHlsError(_, d) {
  if (!d.fatal || tripped) { return; }
  failCount++;
  var T = window.Hls.ErrorTypes;
  if (d.type === T.MEDIA_ERROR && failCount <= 2) { hls.recoverMediaError(); return; }
  if (d.type === T.NETWORK_ERROR && failCount <= 2) { setTimeout(function () { if (hls) { hls.startLoad(); } }, 1500); return; }
  nextServer();
}

/* ---------------------------------------------------------------- UI */
function markServers() {
  var b = $('#servers').children;
  for (var i = 0; i < b.length; i++) { b[i].className = i === cur ? 'on' : ''; }
}
function buildServers() {
  var box = $('#servers');
  if (C.names.length < 2) { return; }
  C.names.forEach(function (n, i) {
    var b = document.createElement('button');
    b.textContent = n;
    b.onclick = function (e) { e.stopPropagation(); started = true; app.classList.add('started'); startStream(i, false); };
    box.appendChild(b);
  });
  markServers();
}
function buildQuality() {
  var m = $('#qmenu');
  m.innerHTML = '';
  if (!hls || !hls.levels || hls.levels.length < 2) { $('#bq').style.display = 'none'; return; }
  $('#bq').style.display = '';
  var items = [{ l: 'تلقائي', i: -1 }];
  hls.levels.map(function (lv, i) { return { l: (lv.height ? lv.height + 'p' : Math.round(lv.bitrate / 1000) + 'k'), i: i, h: lv.height || lv.bitrate }; })
    .sort(function (a, b) { return b.h - a.h; }).forEach(function (x) { items.push(x); });
  items.forEach(function (it) {
    var b = document.createElement('button');
    b.textContent = it.l;
    if (it.i === hls.currentLevel || (it.i === -1 && hls.autoLevelEnabled)) { b.className = 'on'; }
    b.onclick = function (e) { e.stopPropagation(); hls.currentLevel = it.i; m.hidden = true; buildQuality(); };
    m.appendChild(b);
  });
}
function goLive() {
  try {
    if (hls && hls.liveSyncPosition) { v.currentTime = hls.liveSyncPosition; }
    else if (isFinite(v.duration) && v.duration > 0) { v.currentTime = v.duration - 1; }
    var p = v.play(); if (p && p.catch) { p.catch(function () {}); }
  } catch (e) {}
}
function fullscreen() {
  var d = document;
  if (d.fullscreenElement || d.webkitFullscreenElement) { (d.exitFullscreen || d.webkitExitFullscreen).call(d); }
  else if (app.requestFullscreen) { app.requestFullscreen(); }
  else if (app.webkitRequestFullscreen) { app.webkitRequestFullscreen(); }
  else if (v.webkitEnterFullscreen) { v.webkitEnterFullscreen(); }
}
function toggle() { if (v.paused) { var p = v.play(); if (p && p.catch) { p.catch(function () {}); } } else { v.pause(); } }
function wake() {
  app.classList.remove('idle');
  clearTimeout(idleT);
  idleT = setTimeout(function () { if (!v.paused) { app.classList.add('idle'); $('#qmenu').hidden = true; } }, 3000);
}
function firstPlay() {
  if (tripped || started) { return; }
  if (!C.names.length) { showMsg('لم تتم إضافة سيرفر بث لهذه المباراة بعد.', false); return; }
  adClick('play');
  started = true; app.classList.add('started');
  startStream(0, false);
}

/* ---------------------------------------------------------------- wiring */
v.addEventListener('playing', function () { app.classList.add('playing', 'shown'); showSpin(false); hideMsg(); failCount = 0; tried = 1; wake(); });
v.addEventListener('pause', function () { app.classList.remove('playing'); app.classList.remove('idle'); });
v.addEventListener('waiting', function () { if (started && !tripped) { showSpin(true); } });
v.addEventListener('canplay', function () { showSpin(false); });
v.addEventListener('error', function () { if (!hls && started && !tripped) { nextServer(); } });
v.addEventListener('volumechange', function () { app.classList.toggle('muted', v.muted || v.volume === 0); });
v.addEventListener('timeupdate', function () {
  var behind = (hls && hls.liveSyncPosition) ? hls.liveSyncPosition - v.currentTime : 0;
  $('#live').classList.toggle('on', behind < 12);
});
$('#splash').addEventListener('click', firstPlay);
$('#bigplay').addEventListener('click', function (e) { e.stopPropagation(); firstPlay(); });
v.addEventListener('click', function () { if (!started) { return; } adClick('click'); toggle(); });
$('#bplay').onclick = function (e) { e.stopPropagation(); toggle(); };
$('#bmute').onclick = function (e) { e.stopPropagation(); v.muted = !v.muted; };
$('#vol').oninput = function () { v.volume = parseFloat(this.value); v.muted = v.volume === 0; };
$('#live').onclick = function (e) { e.stopPropagation(); goLive(); };
$('#bq').onclick = function (e) { e.stopPropagation(); var m = $('#qmenu'); m.hidden = !m.hidden; };
$('#bfs').onclick = function (e) { e.stopPropagation(); fullscreen(); };
$('#bpip').onclick = function (e) {
  e.stopPropagation();
  try {
    if (document.pictureInPictureElement) { document.exitPictureInPicture(); }
    else if (v.requestPictureInPicture) { v.requestPictureInPicture(); }
    else if (v.webkitSetPresentationMode) { v.webkitSetPresentationMode('picture-in-picture'); }
  } catch (err) {}
};
retry.onclick = function () { location.reload(); };
['mousemove', 'touchstart', 'keydown'].forEach(function (ev) { app.addEventListener(ev, wake, { passive: true }); });
document.addEventListener('keydown', function (e) {
  if (tripped || !started) { return; }
  var k = (e.key || '').toLowerCase();
  if (k === ' ' || k === 'k') { e.preventDefault(); toggle(); }
  else if (k === 'f') { fullscreen(); }
  else if (k === 'm') { v.muted = !v.muted; }
});
document.addEventListener('visibilitychange', function () {
  if (!document.hidden && started && hls && hls.liveSyncPosition && hls.liveSyncPosition - v.currentTime > 20 && !v.paused) { goLive(); }
});

/* ---------------------------------------------------------------- boot */
startGuard();
buildServers();
(function status() {
  var count = $('#count');
  if (C.status === 'ended') { $('#bigplay').style.display = 'none'; count.hidden = false; count.textContent = 'انتهى البث'; count.style.direction = 'rtl'; $('#splash').style.cursor = 'default'; $('#splash').removeEventListener('click', firstPlay); return; }
  if (C.status === 'upcoming' && C.start > C.now) {
    var off = C.now * 1000 - Date.now();
    $('#bigplay').style.display = 'none';
    $('#splash').removeEventListener('click', firstPlay);
    count.hidden = false;
    (function tick() {
      var left = C.start - Math.floor((Date.now() + off) / 1000);
      if (left <= 0) { location.reload(); return; }
      var d = Math.floor(left / 86400), h = Math.floor(left % 86400 / 3600), m = Math.floor(left % 3600 / 60), s = left % 60;
      function p(n) { return n < 10 ? '0' + n : '' + n; }
      count.textContent = (d ? d + ' : ' : '') + p(h) + ' : ' + p(m) + ' : ' + p(s);
      setTimeout(tick, 1000);
    })();
  }
})();
if (!window.Hls && !v.canPlayType('application/vnd.apple.mpegurl')) { showMsg('تعذّر تحميل مكوّنات المشغل. تحقق من الاتصال ثم أعد التحميل.', true); }
})();

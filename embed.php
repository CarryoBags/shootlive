<?php
/**
 * embed.php?m=<slug>  - the player page that goes inside the iframe.
 * Modes (per match):  protected = domain lock + devtools guard + tokenised stream
 *                     open      = plain iframe usable anywhere (stream URL still hidden)
 */
require __DIR__ . '/lib/boot.php';
maintenance();

function page_msg(string $title, string $msg, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    echo '<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<style>html,body{height:100%;margin:0;background:#07090d;color:#cbd5e1;font-family:system-ui,Segoe UI,Tahoma,sans-serif}'
        . 'div{height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:20px}'
        . 'h1{font-size:20px;margin:0 0 8px;color:#fff}p{margin:0;font-size:14px;opacity:.8}</style>'
        . '<div><h1>' . h($title) . '</h1><p>' . h($msg) . '</p></div></html>';
    exit;
}

$ip = client_ip();
if (is_banned($ip)) { page_msg('تم حظر الوصول', 'تم رصد نشاط غير طبيعي من شبكتك.', 403); }

$slug = preg_replace('/[^a-zA-Z0-9_-]/', '', (string)($_GET['m'] ?? ''));
$st = db()->prepare('SELECT * FROM matches WHERE slug = ?');
$st->execute([$slug]);
$M = $st->fetch();
if (!$M || $M['status'] === 'hidden') { page_msg('غير متاح', 'هذا البث غير متاح حالياً.', 404); }

$protected = $M['mode'] === 'protected';
$allowed = parse_domains($M['domains'] !== '' ? $M['domains'] : setting('allowed_domains'));
$admin = false;
if (!empty($_COOKIE['spadm'])) { // admin preview (session cookie of the admin panel)
    $sf = DATA . '/sess/sess_' . preg_replace('/[^a-zA-Z0-9,-]/', '', $_COOKIE['spadm']);
    if (is_file($sf) && strpos((string)@file_get_contents($sf), 'sp_admin') !== false) { $admin = true; }
}

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

if ($protected && !$admin) {
    $dest = $_SERVER['HTTP_SEC_FETCH_DEST'] ?? '';
    if ($dest === 'document') { // opened directly in a tab
        log_event('domain', 'direct-open', $M['id']);
        page_msg('محمي', 'هذا البث متاح فقط عبر المواقع المصرّح لها.', 403);
    }
    if ($allowed) {
        $ref = (string)($_SERVER['HTTP_REFERER'] ?? '');
        $rh = $ref !== '' ? (string)parse_url($ref, PHP_URL_HOST) : '';
        if ($rh === '' ? setting('allow_no_referer') !== '1' : !host_allowed($rh, $allowed)) {
            log_event('domain', 'blocked ref=' . $rh, $M['id']);
            page_msg('غير مصرّح', 'هذا الموقع غير مصرّح له بعرض البث.', 403);
        }
        $fa = ["'self'"];
        foreach ($allowed as $d) { $fa[] = $d; $fa[] = '*.' . $d; }
        header('Content-Security-Policy: frame-ancestors ' . implode(' ', $fa));
    }
}

/* ---- session ---- */
$sid = bin2hex(random_bytes(12));
$tk = bin2hex(random_bytes(12));
$chal = bin2hex(random_bytes(6));
$refHost = (string)parse_url((string)($_SERVER['HTTP_REFERER'] ?? ''), PHP_URL_HOST);
db()->prepare('INSERT INTO sessions(id, match_id, ip, ipp, uah, created, last_seen, chal, tk, ref_host, ua) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
    ->execute([$sid, $M['id'], $ip, ip_prefix($ip), ua_hash(), time(), time(), $chal, hash('sha256', $tk), $refHost, substr(ua(), 0, 180)]);

$st = db()->prepare('SELECT name FROM streams WHERE match_id = ? AND active = 1 ORDER BY sort, id');
$st->execute([$M['id']]);
$names = [];
foreach ($st->fetchAll() as $i => $r) { $names[] = $r['name'] !== '' ? $r['name'] : 'سيرفر ' . ($i + 1); }

$links = array_values(array_filter(array_map('trim', preg_split('/\R/', setting('ad_links')))));
$guard = $protected && setting('devtools_guard') === '1' && !$admin;
$cfg = [
    'sid' => $sid, 'k' => $tk, 'c' => $chal, 'x' => base_url() . '/x.php',
    'names' => $names, 'guard' => $guard ? 1 : 0, 'prot' => $protected ? 1 : 0,
    'doms' => ($protected && $allowed) ? $allowed : [],
    'title' => $M['title'], 'poster' => $M['poster'], 'status' => $M['status'],
    'start' => (int)$M['start_at'], 'now' => time(),
    'msg' => setting('msg_blocked'),
    'ads' => ['links' => $links, 'every' => max(1, (int)setting('ad_every')), 'cool' => max(0, (int)setting('ad_cooldown')), 'max' => max(0, (int)setting('ad_max'))],
];
$json = json_encode($cfg, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

$hlsLocal = is_file(__DIR__ . '/assets/hls.min.js') && filesize(__DIR__ . '/assets/hls.min.js') > 100000;
$hlsSrc = $hlsLocal ? 'assets/hls.min.js?v=' . filemtime(__DIR__ . '/assets/hls.min.js') : 'https://cdn.jsdelivr.net/npm/hls.js@1/dist/hls.min.js';
$accent = preg_match('/^#[0-9a-fA-F]{6}$/', setting('accent')) ? setting('accent') : '#e11d48';
$logo = setting('logo_url');
header('Content-Type: text/html; charset=utf-8');
?><!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#000000">
<title><?= h($M['title']) ?></title>
<link rel="stylesheet" href="assets/player.css?v=<?= SP_VERSION ?>">
<style>:root{--accent:<?= h($accent) ?>}</style>
<?= setting('ad_head') ?>
</head>
<body>
<div id="app" class="idle">
  <video id="v" playsinline webkit-playsinline preload="auto"></video>
  <div id="poster" <?= $M['poster'] !== '' ? 'style="background-image:url(\'' . h($M['poster']) . '\')"' : '' ?>></div>
  <?php if ($logo !== ''): ?><img id="wm" src="<?= h($logo) ?>" alt=""><?php endif; ?>
  <div id="splash">
    <div class="ttl"><?= h($M['title']) ?></div>
    <button id="bigplay" aria-label="تشغيل"><svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg></button>
    <div id="count" hidden></div>
  </div>
  <div id="spin" hidden></div>
  <div id="msg" hidden><p id="msgt"></p><button id="retry" hidden>إعادة المحاولة</button></div>
  <div id="servers"></div>
  <div id="bar">
    <button id="bplay" aria-label="تشغيل / إيقاف"><svg class="ip" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg><svg class="ia" viewBox="0 0 24 24"><path d="M6 5h4v14H6zm8 0h4v14h-4z"/></svg></button>
    <button id="bmute" aria-label="كتم"><svg class="im" viewBox="0 0 24 24"><path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3A4.5 4.5 0 0 0 14 8v8a4.5 4.5 0 0 0 2.5-4z"/></svg><svg class="iu" viewBox="0 0 24 24"><path d="M3 9v6h4l5 5V4L7 9H3zm13.6 3l2.2-2.2-1.4-1.4-2.2 2.2-2.2-2.2-1.4 1.4 2.2 2.2-2.2 2.2 1.4 1.4 2.2-2.2 2.2 2.2 1.4-1.4z"/></svg></button>
    <input id="vol" type="range" min="0" max="1" step="0.05" value="1" aria-label="الصوت">
    <button id="live" class="on" aria-label="العودة للمباشر"><i></i>مباشر</button>
    <span class="sp"></span>
    <div class="qwrap"><button id="bq" aria-label="الجودة"><svg viewBox="0 0 24 24"><path d="M19.4 13a7.7 7.7 0 0 0 0-2l2.1-1.6-2-3.5-2.5 1a7.5 7.5 0 0 0-1.7-1L15 3.3h-4l-.4 2.6a7.5 7.5 0 0 0-1.7 1l-2.5-1-2 3.5L6.6 11a7.7 7.7 0 0 0 0 2l-2.1 1.6 2 3.5 2.5-1c.5.4 1.1.7 1.7 1l.4 2.6h4l.4-2.6c.6-.3 1.2-.6 1.7-1l2.5 1 2-3.5zM13 15.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7z"/></svg></button><div id="qmenu" hidden></div></div>
    <button id="bpip" aria-label="صورة داخل صورة"><svg viewBox="0 0 24 24"><path d="M19 7h-8v6h8V7zm2-4H3a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h18a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2zm0 16H3V5h18v14z"/></svg></button>
    <button id="bfs" aria-label="ملء الشاشة"><svg viewBox="0 0 24 24"><path d="M7 14H5v5h5v-2H7v-3zm-2-4h2V7h3V5H5v5zm12 7h-3v2h5v-5h-2v3zM14 5v2h3v3h2V5h-5z"/></svg></button>
  </div>
</div>
<script type="application/json" id="cfg"><?= $json ?></script>
<script src="<?= h($hlsSrc) ?>"></script>
<script src="assets/player.js?v=<?= SP_VERSION ?>"></script>
<?= setting('ad_body') ?>
</body>
</html>

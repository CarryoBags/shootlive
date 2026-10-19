<?php
/**
 * x.php - the only endpoint the player talks to.
 *   POST a=p   : entry playlist (needs session + one-time ticket + proof)
 *   GET  a=n   : same, for native HLS players (Safari/iOS fallback)
 *   POST a=b   : beacon (tamper / ad click)
 *   GET  s=TOK : playlist / segment / key through an encrypted, expiring, session-bound token
 *   GET  d=N   : decoy segment
 * Anything that doesn't look right gets a decoy (static image first, then a fake stream).
 */
require __DIR__ . '/lib/stream.php';

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$a = (string)($_POST['a'] ?? $_GET['a'] ?? '');
$ip = client_ip();

if (isset($_GET['d'])) { fake_ts(); }
if (is_banned($ip)) { decoy(null, 'banned', isset($_GET['s']) ? 'f' : 'p'); }

if ($a === 'p' && $method === 'POST') { entry(false); }
elseif ($a === 'n') { entry(true); }
elseif ($a === 'b' && $method === 'POST') { beacon(); }
elseif (isset($_GET['s'])) { serve_token((string)$_GET['s']); }
decoy(null, 'bad-request', 'p');

/* ---------------------------------------------------------------- */
function fetch_guard(?array $S, string $want): void {
    $site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
    $mode = $_SERVER['HTTP_SEC_FETCH_MODE'] ?? '';
    if ($site === 'cross-site' || $site === 'none' || $mode === 'navigate') {
        decoy($S, 'fetchmeta ' . $site . '/' . $mode, $want);
    }
}
function bind_ok(string $ipp, string $uah, bool $native): bool {
    if (setting('bind_ip') === '1' && ip_prefix(client_ip()) !== $ipp) { return false; }
    if (!$native && ua_hash() !== $uah) { return false; }
    return true;
}

function entry(bool $native): void {
    $g = function ($k) { return (string)($_POST[$k] ?? $_GET[$k] ?? ''); };
    $sid = $g('s'); $tk = $g('k'); $z = $g('z'); $idx = max(0, (int)$g('st'));
    $S = sess_get($sid);
    if (!$S) { decoy(null, 'no-session', 'p'); }
    fetch_guard($S, 'p');
    if ((int)$S['revoked'] === 1) { decoy($S, 'revoked', 'p'); }
    if (!bind_ok((string)$S['ipp'], (string)$S['uah'], $native)) {
        log_event('badbind', 'entry', $S['match_id']);
        decoy($S, 'badbind', 'p');
    }
    $now = time();
    $age = $now - (int)$S['created'];
    if ($age < 1) { decoy($S, 'too-fast', 'p'); }
    if ($age > 6 * 3600) { decoy($S, 'old-session', 'p'); }
    if (!hash_equals(fnv($S['chal'] . '|' . $S['id'] . '|ok'), strtolower($z))) {
        log_event('tamper', 'proof', $S['match_id']);
        decoy($S, 'proof', 'p');
    }
    // one-time rotating ticket (previous one tolerated for 10s to survive retries)
    $kh = hash('sha256', $tk);
    $cur = hash_equals((string)$S['tk'], $kh);
    $prev = !$cur && (string)$S['tk_prev'] !== '' && hash_equals((string)$S['tk_prev'], $kh) && ($now - (int)$S['tk_ts']) <= 10;
    if (!$cur && !$prev) {
        log_event('replay', 'ticket', $S['match_id']);
        decoy($S, 'ticket', 'p');
    }
    $newk = bin2hex(random_bytes(12));
    if ($cur) {
        db()->prepare('UPDATE sessions SET tk_prev = tk, tk = ?, tk_ts = ?, last_seen = ?, hits = hits + 1 WHERE id = ?')
            ->execute([hash('sha256', $newk), $now, $now, $S['id']]);
    } else {
        db()->prepare('UPDATE sessions SET tk = ?, tk_ts = ?, last_seen = ?, hits = hits + 1 WHERE id = ?')
            ->execute([hash('sha256', $newk), $now, $now, $S['id']]);
    }

    $st = db()->prepare("SELECT s.*, m.status FROM streams s JOIN matches m ON m.id = s.match_id
                         WHERE s.match_id = ? AND s.active = 1 ORDER BY s.sort, s.id");
    $st->execute([$S['match_id']]);
    $list = $st->fetchAll();
    if (!$list) { http_response_code(404); header('X-K: ' . $newk); exit; }
    $row = $list[$idx] ?? $list[0];
    if ($row['status'] === 'hidden') { http_response_code(404); exit; }

    [$code, $body] = up_get($row['url'], (string)$row['ref'], (string)$row['ua'], (int)setting('pl_cache'));
    $body = ltrim($body, "\xEF\xBB\xBF \t\r\n");
    if ($code !== 200 || strpos($body, '#EXTM3U') !== 0) {
        log_event('upstream', 'bad playlist http=' . $code, $S['match_id']);
        http_response_code(502);
        header('X-K: ' . $newk);
        exit;
    }
    $ctx = [
        'sid' => $S['id'], 'ipp' => $S['ipp'], 'uah' => $S['uah'], 'native' => $native,
        'ref' => (string)$row['ref'], 'ua' => (string)$row['ua'], 'del' => $row['delivery'] === 'redirect' ? 'r' : 'p',
    ];
    if (is_master($body)) {
        $outp = rewrite_playlist($body, $row['url'], $ctx);
    } else {
        // wrap a media playlist in a synthetic master: the player re-fetches the media
        // playlist through its own long-lived token, so the one-time ticket is used once.
        $outp = "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=2500000,AVERAGE-BANDWIDTH=2000000\n" . mk_url($row['url'], 'p', $ctx) . "\n";
    }
    header('Content-Type: application/vnd.apple.mpegurl; charset=utf-8');
    header('X-K: ' . $newk);
    echo $outp;
    exit;
}

function serve_token(string $t): void {
    $p = tok_open($t);
    if (!$p) { decoy(null, 'bad-token', 'f'); }
    $want = $p['t'] === 'p' ? 'p' : 'f';
    fetch_guard(null, $want);
    $native = !empty($p['n']);
    if (!bind_ok((string)$p['i'], (string)$p['h'], $native)) {
        log_event('badbind', 'token ' . $p['t']);
        decoy(null, 'badbind-token', $want);
    }
    if ($p['t'] === 'p') {
        $S = sess_get((string)$p['s']);
        if (!$S || (int)$S['revoked'] === 1) { decoy($S, 'revoked-token', 'p'); }
        if (time() - (int)$S['last_seen'] >= 15) {
            db()->prepare('UPDATE sessions SET last_seen = ?, hits = hits + 1 WHERE id = ?')->execute([time(), $S['id']]);
        }
        [$code, $body] = up_get((string)$p['u'], (string)($p['r'] ?? ''), (string)($p['a'] ?? ''), (int)setting('pl_cache'));
        $body = ltrim($body, "\xEF\xBB\xBF \t\r\n");
        if ($code !== 200 || strpos($body, '#EXTM3U') !== 0) { http_response_code(502); exit; }
        $ctx = [
            'sid' => $p['s'], 'ipp' => $p['i'], 'uah' => $p['h'], 'native' => $native,
            'ref' => (string)($p['r'] ?? ''), 'ua' => (string)($p['a'] ?? ''), 'del' => (string)($p['d'] ?? 'p'),
        ];
        header('Content-Type: application/vnd.apple.mpegurl; charset=utf-8');
        echo rewrite_playlist($body, (string)$p['u'], $ctx);
        exit;
    }
    if ($p['t'] === 'f' && ($p['d'] ?? 'p') === 'r') {
        header('Location: ' . $p['u'], true, 302);
        exit;
    }
    proxy_out($p, $p['t'] === 'f');
}

function beacon(): void {
    $S = sess_get((string)($_POST['s'] ?? ''));
    if (!$S) { http_response_code(204); exit; }
    $w = (string)($_POST['w'] ?? '');
    if ($w === 'ad') {
        if ((int)$S['ads'] < 60) {
            db()->prepare('INSERT INTO adclicks(ts, match_id, sid, kind) VALUES(?,?,?,?)')
                ->execute([time(), $S['match_id'], $S['id'], substr((string)($_POST['k'] ?? 'click'), 0, 12)]);
            db()->prepare('UPDATE sessions SET ads = ads + 1 WHERE id = ?')->execute([$S['id']]);
        }
    } else {
        log_event('tamper', 'js:' . substr($w, 0, 40), $S['match_id']);
        db()->prepare('UPDATE sessions SET revoked = 1 WHERE id = ?')->execute([$S['id']]);
    }
    http_response_code(204);
    exit;
}

<?php
/**
 * Upstream fetching, playlist rewriting, segment proxy and decoys.
 */
require_once __DIR__ . '/boot.php';

/* ================= decoys ================= */
function decoy_png(): string {
    return base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==');
}
/**
 * First decoy hit  -> a static image (200 OK).
 * Later decoy hits -> a fake playlist / fake segment bytes.
 * $want: 'p' (playlist) or 'f' (file/segment)
 */
function decoy(?array $S, string $reason, string $want = 'p'): void {
    $n = 1;
    try {
        if ($S) {
            db()->prepare('UPDATE sessions SET decoys = decoys + 1 WHERE id = ?')->execute([$S['id']]);
            $n = (int)$S['decoys'] + 1;
        } else {
            $st = db()->prepare("SELECT COUNT(*) FROM events WHERE ip = ? AND ts > ? AND type = 'decoy'");
            $st->execute([client_ip(), time() - 600]);
            $n = (int)$st->fetchColumn() + 1;
        }
    } catch (Throwable $e) {}
    log_event('decoy', $reason . ' n=' . $n, $S ? $S['match_id'] : null);
    while (ob_get_level() > 0) { @ob_end_clean(); }
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    if ($n <= 1) {
        header('Content-Type: image/png');
        echo decoy_png();
        exit;
    }
    if ($want === 'p') {
        header('Content-Type: application/vnd.apple.mpegurl');
        $seq = (int)(time() / 6);
        $b = base_url() . '/x.php?d=';
        echo "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:6\n#EXT-X-MEDIA-SEQUENCE:$seq\n";
        for ($i = 0; $i < 5; $i++) { echo "#EXTINF:6.000,\n" . $b . ($seq + $i) . "\n"; }
        exit;
    }
    fake_ts();
}
function fake_ts(): void {
    while (ob_get_level() > 0) { @ob_end_clean(); }
    header('Content-Type: video/mp2t');
    header('Cache-Control: no-store');
    $pkt = "\x47\x1f\xff\x10" . str_repeat("\xff", 184);
    echo str_repeat($pkt, 400);
    exit;
}

/* ================= URL helpers ================= */
function resolve_url(string $base, string $rel): string {
    if (preg_match('#^https?://#i', $rel)) { return $rel; }
    $b = parse_url($base);
    $scheme = $b['scheme'] ?? 'https';
    $host = ($b['host'] ?? '') . (isset($b['port']) ? ':' . $b['port'] : '');
    if (substr($rel, 0, 2) === '//') { return $scheme . ':' . $rel; }
    if ($rel !== '' && $rel[0] === '/') { return $scheme . '://' . $host . $rel; }
    $path = $b['path'] ?? '/';
    $full = substr($path, 0, strrpos($path, '/') + 1) . $rel;
    $q = '';
    if (($pos = strpos($full, '?')) !== false) { $q = substr($full, $pos); $full = substr($full, 0, $pos); }
    $parts = [];
    foreach (explode('/', $full) as $i => $seg) {
        if ($seg === '..') { if (count($parts) > 1) { array_pop($parts); } }
        elseif ($seg !== '.' || $i === 0) { $parts[] = $seg; }
    }
    return $scheme . '://' . $host . implode('/', $parts) . $q;
}
function url_is_safe(string $u): bool {
    $p = @parse_url($u);
    if (!$p || empty($p['host']) || !in_array(strtolower($p['scheme'] ?? ''), ['http', 'https'], true)) { return false; }
    if (setting('allow_private') === '1') { return true; }
    $host = strtolower($p['host']);
    if ($host === 'localhost' || substr($host, -6) === '.local') { return false; }
    if (filter_var($host, FILTER_VALIDATE_IP) && !filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) { return false; }
    return true;
}

/* ================= upstream (curl) ================= */
function curl_base(string $url, string $ref, string $uaStr, int $timeout = 12) {
    $ch = curl_init($url);
    $hdr = [];
    if ($ref !== '') {
        $hdr[] = 'Referer: ' . $ref;
        $po = parse_url($ref);
        if (!empty($po['scheme']) && !empty($po['host'])) { $hdr[] = 'Origin: ' . $po['scheme'] . '://' . $po['host']; }
    }
    curl_setopt_array($ch, [
        CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 4,
        CURLOPT_CONNECTTIMEOUT => 6, CURLOPT_TIMEOUT => $timeout,
        CURLOPT_ENCODING => '', CURLOPT_HTTPHEADER => $hdr,
        CURLOPT_USERAGENT => $uaStr !== '' ? $uaStr : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
        CURLOPT_SSL_VERIFYPEER => setting('ssl_verify') === '1',
        CURLOPT_SSL_VERIFYHOST => setting('ssl_verify') === '1' ? 2 : 0,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
    ]);
    return $ch;
}
/** Playlist fetch with short shared file cache (protects the origin from many viewers). */
function up_get(string $url, string $ref, string $uaStr, int $ttl): array {
    if (!url_is_safe($url)) { return [0, '']; }
    ensure_dirs();
    $cf = DATA . '/cache/p_' . sha1($url . '|' . $ref);
    $fresh = function () use ($cf, $ttl) { clearstatcache(true, $cf); return $ttl > 0 && is_file($cf) && (time() - filemtime($cf)) < $ttl; };
    if ($fresh()) { return [200, (string)file_get_contents($cf)]; }
    $lk = @fopen($cf . '.lock', 'c');
    if ($lk) { flock($lk, LOCK_EX); }
    if ($fresh()) { if ($lk) { flock($lk, LOCK_UN); fclose($lk); } return [200, (string)file_get_contents($cf)]; }
    $ch = curl_base($url, $ref, $uaStr, 10);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($code === 200 && is_string($body) && $body !== '' && $ttl > 0) {
        $tmp = $cf . '.' . bin2hex(random_bytes(3)) . '.tmp';
        if (@file_put_contents($tmp, $body) !== false) { @rename($tmp, $cf); }
    }
    if ($lk) { flock($lk, LOCK_UN); fclose($lk); }
    return [$code, is_string($body) ? $body : ''];
}

/* ================= playlist rewriting ================= */
function mk_url(string $abs, string $type, array $c): string {
    $p = [
        't' => $type, 'u' => $abs, 'd' => $c['del'], 's' => $c['sid'], 'i' => $c['ipp'], 'h' => $c['uah'],
        'n' => $c['native'] ? 1 : 0, 'e' => time() + ($type === 'p' ? 21600 : 150),
    ];
    if ($c['ref'] !== '') { $p['r'] = $c['ref']; }
    if ($c['ua'] !== '') { $p['a'] = $c['ua']; }
    return base_url() . '/x.php?s=' . tok_make($p);
}
function rewrite_playlist(string $body, string $base, array $c): string {
    $lines = explode("\n", str_replace("\r", '', $body));
    $out = [];
    $nextIsPl = false;
    foreach ($lines as $ln) {
        $t = trim($ln);
        if ($t === '') { $out[] = ''; continue; }
        if ($t[0] === '#') {
            if (strpos($t, '#EXT-X-STREAM-INF') === 0) { $nextIsPl = true; }
            if (strpos($t, 'URI="') !== false) {
                $isPl = strpos($t, '#EXT-X-MEDIA') === 0 || strpos($t, '#EXT-X-I-FRAME-STREAM-INF') === 0;
                $isKey = strpos($t, '#EXT-X-KEY') === 0 || strpos($t, '#EXT-X-SESSION-KEY') === 0;
                $type = $isPl ? 'p' : ($isKey ? 'k' : 'f');
                $t = preg_replace_callback('/URI="([^"]*)"/', function ($m) use ($base, $c, $type) {
                    if ($m[1] === '' || preg_match('#^(data|skd):#i', $m[1])) { return $m[0]; }
                    return 'URI="' . mk_url(resolve_url($base, $m[1]), $type, $c) . '"';
                }, $t);
            }
            $out[] = $t;
            continue;
        }
        $isPl = $nextIsPl || preg_match('/\.m3u8?(\?|$)/i', $t);
        $nextIsPl = false;
        $out[] = mk_url(resolve_url($base, $t), $isPl ? 'p' : 'f', $c);
    }
    return implode("\n", $out) . "\n";
}
function is_master(string $body): bool { return strpos($body, '#EXT-X-STREAM-INF') !== false; }

/* ================= segment / key proxy ================= */
function ctype_for(string $url): string {
    $path = strtolower((string)parse_url($url, PHP_URL_PATH));
    if (preg_match('/\.(ts|tsv)$/', $path)) { return 'video/mp2t'; }
    if (preg_match('/\.(m4s|mp4|m4v|cmfv)$/', $path)) { return 'video/mp4'; }
    if (preg_match('/\.(aac|m4a|cmfa)$/', $path)) { return 'audio/aac'; }
    return 'application/octet-stream';
}
function dl_to_file(string $url, array $p, string $tmp): bool {
    $fh = @fopen($tmp, 'wb');
    if (!$fh) { return false; }
    $ch = curl_base($url, (string)($p['r'] ?? ''), (string)($p['a'] ?? ''), 20);
    curl_setopt($ch, CURLOPT_FILE, $fh);
    curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    fclose($fh);
    return $code === 200 && filesize($tmp) > 0;
}
function proxy_out(array $p, bool $cache): void {
    $url = (string)$p['u'];
    if (!url_is_safe($url)) { http_response_code(400); exit; }
    @set_time_limit(0);
    ensure_dirs();
    $range = (string)($_SERVER['HTTP_RANGE'] ?? '');
    if ($cache && $range === '' && setting('seg_cache') === '1') {
        $cf = DATA . '/cache/s_' . sha1($url);
        $fresh = function () use ($cf) { clearstatcache(true, $cf); return is_file($cf) && (time() - filemtime($cf)) < 60; };
        if (!$fresh()) {
            $lk = fopen($cf . '.lock', 'c');
            flock($lk, LOCK_EX);
            if (!$fresh()) {
                $tmp = $cf . '.' . bin2hex(random_bytes(3)) . '.tmp';
                if (dl_to_file($url, $p, $tmp)) { rename($tmp, $cf); }
                else { @unlink($tmp); flock($lk, LOCK_UN); fclose($lk); http_response_code(502); exit; }
            }
            flock($lk, LOCK_UN);
            fclose($lk);
        }
        while (ob_get_level() > 0) { @ob_end_clean(); }
        header('Content-Type: ' . ctype_for($url));
        header('Content-Length: ' . filesize($cf));
        header('Cache-Control: private, max-age=30');
        readfile($cf);
        exit;
    }
    // direct streaming (also used for Range requests)
    $ch = curl_base($url, (string)($p['r'] ?? ''), (string)($p['a'] ?? ''), 60);
    if ($range !== '') { curl_setopt($ch, CURLOPT_RANGE, preg_replace('/^bytes=/', '', $range)); }
    $status = 200; $hdrs = []; $sent = false;
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $line) use (&$status, &$hdrs) {
        if (stripos($line, 'HTTP/') === 0) { $status = (int)substr($line, 9, 3); $hdrs = []; }
        elseif (strpos($line, ':') !== false) { [$k, $v] = explode(':', $line, 2); $hdrs[strtolower(trim($k))] = trim($v); }
        return strlen($line);
    });
    curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($ch, $data) use (&$sent, &$status, &$hdrs, $url) {
        if (!$sent) {
            $sent = true;
            while (ob_get_level() > 0) { @ob_end_clean(); }
            http_response_code($status >= 200 && $status < 300 ? $status : 502);
            header('Content-Type: ' . ($hdrs['content-type'] ?? ctype_for($url)));
            foreach (['content-range', 'content-length'] as $k) { if (isset($hdrs[$k])) { header($k . ': ' . $hdrs[$k]); } }
            header('Accept-Ranges: bytes');
            header('Cache-Control: no-store');
        }
        echo $data;
        flush();
        return strlen($data);
    });
    curl_exec($ch);
    curl_close($ch);
    if (!$sent) { http_response_code(502); }
    exit;
}

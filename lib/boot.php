<?php
/**
 * Secure Player - core bootstrap (PHP 7.4+)
 * DB (SQLite), settings, tokens (AES-256-GCM), bans, logging.
 */
if (defined('SP_BOOT')) { return; }
define('SP_BOOT', 1);
define('ROOT', dirname(__DIR__));
define('DATA', ROOT . '/data');
define('SP_VERSION', '1.0.0');
@ini_set('display_errors', '0');
error_reporting(E_ALL);

/* ---------- small helpers ---------- */
function h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function b64u(string $s): string { return rtrim(strtr(base64_encode($s), '+/', '-_'), '='); }
function b64u_d(string $s) { return base64_decode(strtr($s, '-_', '+/'), true); }
function is_https(): bool {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
        || (strpos($_SERVER['HTTP_CF_VISITOR'] ?? '', 'https') !== false);
}
function base_url(): string {
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $dir = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
    if (substr($dir, -6) === '/admin') { $dir = substr($dir, 0, -6); }
    return (is_https() ? 'https' : 'http') . '://' . $host . $dir;
}
function ua(): string { return substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 200); }

function ensure_dirs(): void {
    foreach ([DATA, DATA . '/cache', DATA . '/sess'] as $d) {
        if (!is_dir($d)) { @mkdir($d, 0750, true); }
    }
    $ht = DATA . '/.htaccess';
    if (!is_file($ht)) {
        @file_put_contents($ht, "Require all denied\n<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n");
    }
}

/* ---------- secret key ---------- */
function secret(): string {
    static $k = null;
    if ($k !== null) { return $k; }
    ensure_dirs();
    $f = DATA . '/secret.key';
    if (!is_file($f)) {
        file_put_contents($f, bin2hex(random_bytes(32)));
        @chmod($f, 0600);
    }
    return $k = trim((string)file_get_contents($f));
}
function aes_key(): string { static $k = null; return $k ?? ($k = hash('sha256', secret() . 'aes', true)); }
function hmac_short(string $s): string { return substr(hash_hmac('sha256', $s, secret()), 0, 16); }

/* ---------- database ---------- */
function db(): PDO {
    static $pdo = null;
    if ($pdo) { return $pdo; }
    ensure_dirs();
    $pdo = new PDO('sqlite:' . DATA . '/player.sqlite', null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA busy_timeout=4000');
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA synchronous=NORMAL');
    migrate($pdo);
    return $pdo;
}
function migrate(PDO $p): void {
    $v = (int)$p->query('PRAGMA user_version')->fetchColumn();
    if ($v >= 1) { return; }
    $p->exec("
    CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS matches (
        id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT UNIQUE NOT NULL, title TEXT NOT NULL,
        poster TEXT DEFAULT '', start_at INTEGER DEFAULT 0, status TEXT DEFAULT 'live',
        mode TEXT DEFAULT 'protected', domains TEXT DEFAULT '', created INTEGER);
    CREATE TABLE IF NOT EXISTS streams (
        id INTEGER PRIMARY KEY AUTOINCREMENT, match_id INTEGER NOT NULL, name TEXT, url TEXT NOT NULL,
        ref TEXT DEFAULT '', ua TEXT DEFAULT '', delivery TEXT DEFAULT 'proxy', sort INTEGER DEFAULT 0, active INTEGER DEFAULT 1);
    CREATE INDEX IF NOT EXISTS ix_streams_match ON streams(match_id);
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY, match_id INTEGER, ip TEXT, ipp TEXT, uah TEXT, created INTEGER, last_seen INTEGER,
        hits INTEGER DEFAULT 0, decoys INTEGER DEFAULT 0, revoked INTEGER DEFAULT 0, chal TEXT,
        tk TEXT, tk_prev TEXT DEFAULT '', tk_ts INTEGER DEFAULT 0, ref_host TEXT DEFAULT '', ua TEXT DEFAULT '', ads INTEGER DEFAULT 0);
    CREATE INDEX IF NOT EXISTS ix_sess_seen ON sessions(last_seen);
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, type TEXT, ip TEXT, ua TEXT, match_id INTEGER, detail TEXT);
    CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts);
    CREATE INDEX IF NOT EXISTS ix_ev_ip ON events(ip, ts);
    CREATE TABLE IF NOT EXISTS bans (ip TEXT PRIMARY KEY, until INTEGER, reason TEXT);
    CREATE TABLE IF NOT EXISTS adclicks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, match_id INTEGER, sid TEXT, kind TEXT);
    CREATE INDEX IF NOT EXISTS ix_ad_ts ON adclicks(ts);
    PRAGMA user_version = 1;");
}

/* ---------- settings ---------- */
function setting_defaults(): array {
    return [
        'site_name' => 'البث المباشر', 'logo_url' => '', 'accent' => '#e11d48',
        'allowed_domains' => '', 'allow_no_referer' => '0', 'trust_cf' => '0', 'bind_ip' => '1',
        'devtools_guard' => '1', 'ssl_verify' => '1', 'allow_private' => '0', 'pl_cache' => '2', 'seg_cache' => '1',
        'ban_threshold' => '6', 'ban_minutes' => '120',
        'ad_head' => '', 'ad_body' => '', 'ad_links' => '', 'ad_every' => '1', 'ad_cooldown' => '60', 'ad_max' => '5',
        'msg_blocked' => 'تم إيقاف المشغل لأسباب أمنية. أغلق أدوات المطوّر ثم أعد تحميل الصفحة.',
        'admin_hash' => '',
    ];
}
function settings_all(): array {
    static $cache = null;
    if ($cache !== null) { return $cache; }
    $cache = setting_defaults();
    try {
        foreach (db()->query('SELECT k, v FROM settings') as $r) { $cache[$r['k']] = $r['v']; }
    } catch (Throwable $e) {}
    return $cache;
}
function setting(string $k, string $def = ''): string {
    $a = settings_all();
    return isset($a[$k]) ? (string)$a[$k] : $def;
}
function set_setting(string $k, string $v): void {
    db()->prepare('INSERT INTO settings(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v')->execute([$k, $v]);
}

/* ---------- client identity ---------- */
function client_ip(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (setting('trust_cf') === '1' && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) { $ip = $_SERVER['HTTP_CF_CONNECTING_IP']; }
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}
function ip_prefix(string $ip): string {
    if (strpos($ip, ':') !== false) { $b = @inet_pton($ip); return $b === false ? $ip : bin2hex(substr($b, 0, 6)); }
    return implode('.', array_slice(explode('.', $ip), 0, 3));
}
function ua_hash(): string { return hmac_short(ua()); }

/* ---------- domains ---------- */
function parse_domains(string $csv): array {
    $out = [];
    foreach (preg_split('/[\s,]+/', strtolower($csv)) as $d) {
        $d = preg_replace('#^https?://#', '', trim($d));
        $d = preg_replace('#[/:].*$#', '', $d);
        $d = preg_replace('/^\*?\./', '', $d);
        if ($d !== '') { $out[$d] = 1; }
    }
    return array_keys($out);
}
function host_allowed(string $host, array $list): bool {
    $host = strtolower($host);
    foreach ($list as $d) {
        if ($host === $d || (strlen($host) > strlen($d) && substr($host, -strlen($d) - 1) === '.' . $d)) { return true; }
    }
    return false;
}

/* ---------- tokens (stateless, AES-256-GCM) ---------- */
function tok_make(array $p): string {
    $iv = random_bytes(12); $tag = '';
    $ct = openssl_encrypt(json_encode($p, JSON_UNESCAPED_SLASHES), 'aes-256-gcm', aes_key(), OPENSSL_RAW_DATA, $iv, $tag, '', 12);
    return b64u($iv . $tag . $ct);
}
function tok_open(string $t): ?array {
    $raw = b64u_d($t);
    if ($raw === false || strlen($raw) < 26) { return null; }
    $j = @openssl_decrypt(substr($raw, 24), 'aes-256-gcm', aes_key(), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 12));
    if ($j === false) { return null; }
    $p = json_decode($j, true);
    if (!is_array($p) || (int)($p['e'] ?? 0) < time()) { return null; }
    return $p;
}

/* ---------- proof-of-JS (FNV-1a 32) ---------- */
function fnv(string $s): string {
    $h = 0x811c9dc5;
    for ($i = 0, $n = strlen($s); $i < $n; $i++) { $h ^= ord($s[$i]); $h = ($h * 0x01000193) & 0xFFFFFFFF; }
    return dechex($h);
}

/* ---------- logging / bans ---------- */
function log_event(string $type, string $detail = '', $matchId = null): void {
    try {
        $ip = client_ip();
        db()->prepare('INSERT INTO events(ts, type, ip, ua, match_id, detail) VALUES(?,?,?,?,?,?)')
            ->execute([time(), $type, $ip, substr(ua(), 0, 180), $matchId, substr($detail, 0, 250)]);
        if (in_array($type, ['decoy', 'tamper', 'replay', 'badbind'], true)) { strike($ip); }
    } catch (Throwable $e) {}
}
function strike(string $ip): void {
    $th = (int)setting('ban_threshold');
    if ($th <= 0) { return; }
    $st = db()->prepare("SELECT COUNT(*) FROM events WHERE ip = ? AND ts > ? AND type IN ('decoy','tamper','replay','badbind')");
    $st->execute([$ip, time() - 600]);
    if ((int)$st->fetchColumn() >= $th) {
        db()->prepare('INSERT OR REPLACE INTO bans(ip, until, reason) VALUES(?,?,?)')
            ->execute([$ip, time() + max(1, (int)setting('ban_minutes')) * 60, 'auto']);
    }
}
function is_banned(string $ip): bool {
    try {
        $st = db()->prepare('SELECT until FROM bans WHERE ip = ?');
        $st->execute([$ip]);
        $u = $st->fetchColumn();
        return $u !== false && (int)$u > time();
    } catch (Throwable $e) { return false; }
}

/* ---------- sessions ---------- */
function sess_get(string $sid): ?array {
    if (!preg_match('/^[a-f0-9]{24}$/', $sid)) { return null; }
    $st = db()->prepare('SELECT * FROM sessions WHERE id = ?');
    $st->execute([$sid]);
    $r = $st->fetch();
    return $r ?: null;
}

function maintenance(): void {
    if (mt_rand(1, 100) !== 1) { return; }
    try {
        $p = db();
        $p->prepare('DELETE FROM sessions WHERE last_seen < ?')->execute([time() - 86400]);
        $p->prepare('DELETE FROM events WHERE ts < ?')->execute([time() - 86400 * 30]);
        $p->prepare('DELETE FROM bans WHERE until < ?')->execute([time()]);
        $p->prepare('DELETE FROM adclicks WHERE ts < ?')->execute([time() - 86400 * 60]);
        $dir = DATA . '/cache';
        foreach ((array)@scandir($dir) as $f) {
            if ($f[0] === '.') { continue; }
            if (@filemtime("$dir/$f") < time() - 180) { @unlink("$dir/$f"); }
        }
    } catch (Throwable $e) {}
}

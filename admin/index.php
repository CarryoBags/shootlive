<?php
require dirname(__DIR__) . '/lib/boot.php';

ensure_dirs();
session_save_path(DATA . '/sess');
session_name('spadm');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => is_https(), 'httponly' => true, 'samesite' => 'Lax']);
session_start();
header('X-Frame-Options: DENY');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');

function csrf(): string { return $_SESSION['csrf'] ?? ($_SESSION['csrf'] = bin2hex(random_bytes(16))); }
function csrf_check(): void { if (!hash_equals(csrf(), (string)($_POST['_t'] ?? ''))) { http_response_code(400); exit('طلب غير صالح (CSRF)'); } }
function flash(string $m, string $t = 'ok'): void { $_SESSION['flash'] = [$m, $t]; }
function go(string $to): void { header('Location: ' . $to); exit; }
function field(string $k, string $d = ''): string { return trim((string)($_POST[$k] ?? $d)); }
function fmt_ts($t): string { return $t ? date('Y-m-d H:i', (int)$t) . ' UTC' : '—'; }
function embed_url(string $slug): string { return base_url() . '/embed.php?m=' . rawurlencode($slug); }
function iframe_code(string $slug): string {
    return '<iframe src="' . embed_url($slug) . '" width="100%" height="100%" frameborder="0" scrolling="no" '
        . 'allow="autoplay; fullscreen; picture-in-picture; encrypted-media" allowfullscreen referrerpolicy="origin"></iframe>';
}
function download_hls(): string {
    $dest = ROOT . '/assets/hls.min.js';
    foreach (['https://cdn.jsdelivr.net/npm/hls.js@1/dist/hls.min.js', 'https://unpkg.com/hls.js@1/dist/hls.min.js', 'https://cdnjs.cloudflare.com/ajax/libs/hls.js/1.5.20/hls.min.js'] as $u) {
        $ch = curl_init($u);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_TIMEOUT => 40, CURLOPT_ENCODING => '']);
        $b = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if ($code === 200 && is_string($b) && strlen($b) > 100000 && strpos($b, 'Hls') !== false) {
            file_put_contents($dest, $b);
            return $u;
        }
    }
    return '';
}

/* ================= auth ================= */
$ip = client_ip();
$hash = setting('admin_hash');
$authed = !empty($_SESSION['sp_admin']);

function layout(string $title, string $body, bool $nav = true): void {
    $p = $_GET['p'] ?? 'dash';
    $items = ['dash' => 'لوحة المعلومات', 'matches' => 'المباريات', 'ads' => 'الإعلانات', 'sec' => 'الأمان والإعدادات', 'logs' => 'السجلات والحظر', 'acct' => 'الحساب'];
    echo '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<meta name="robots" content="noindex,nofollow"><title>' . h($title) . ' - لوحة التحكم</title><link rel="stylesheet" href="admin.css?v=' . SP_VERSION . '"></head><body>';
    if ($nav) {
        echo '<aside><div class="brand">▶ المشغل المحمي</div><nav>';
        foreach ($items as $k => $l) { echo '<a href="?p=' . $k . '"' . (($p === $k || ($k === 'matches' && $p === 'edit')) ? ' class="on"' : '') . '>' . $l . '</a>'; }
        echo '<form method="post" action="?p=logout"><input type="hidden" name="_t" value="' . csrf() . '"><button class="lnk">تسجيل الخروج</button></form></nav></aside>';
    }
    echo '<main' . ($nav ? '' : ' class="solo"') . '>';
    if (!empty($_SESSION['flash'])) { [$m, $t] = $_SESSION['flash']; unset($_SESSION['flash']); echo '<div class="flash ' . h($t) . '">' . h($m) . '</div>'; }
    echo $body . '</main></body></html>';
}

if ($hash === '') { // first-run setup
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        csrf_check();
        $pw = (string)($_POST['pw'] ?? '');
        if (strlen($pw) < 8) { flash('كلمة المرور لازم تكون 8 أحرف على الأقل.', 'err'); }
        else { set_setting('admin_hash', password_hash($pw, PASSWORD_DEFAULT)); session_regenerate_id(true); $_SESSION['sp_admin'] = 1; go('?p=dash'); }
    }
    ob_start(); ?>
    <div class="card narrow"><h1>إعداد أول مرة</h1><p class="mut">اختر كلمة مرور قوية للوحة التحكم.</p>
    <form method="post"><input type="hidden" name="_t" value="<?= csrf() ?>">
    <label>كلمة المرور (8 أحرف أو أكثر)<input type="password" name="pw" required minlength="8" autofocus></label>
    <button class="btn">حفظ والدخول</button></form></div>
    <?php layout('إعداد', ob_get_clean(), false); exit;
}

if (!$authed) {
    if (($_GET['p'] ?? '') === 'logout') { go('?p=dash'); }
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        csrf_check();
        $st = db()->prepare("SELECT COUNT(*) FROM events WHERE ip = ? AND type = 'login_fail' AND ts > ?");
        $st->execute([$ip, time() - 600]);
        if ((int)$st->fetchColumn() >= 8) { flash('محاولات كثيرة. انتظر 10 دقائق.', 'err'); }
        elseif (password_verify((string)($_POST['pw'] ?? ''), $hash)) { session_regenerate_id(true); $_SESSION['sp_admin'] = 1; go('?p=dash'); }
        else { log_event('login_fail', ''); flash('كلمة المرور غير صحيحة.', 'err'); }
    }
    ob_start(); ?>
    <div class="card narrow"><h1>تسجيل الدخول</h1>
    <form method="post"><input type="hidden" name="_t" value="<?= csrf() ?>">
    <label>كلمة المرور<input type="password" name="pw" required autofocus></label>
    <button class="btn">دخول</button></form></div>
    <?php layout('دخول', ob_get_clean(), false); exit;
}

/* ================= actions (POST) ================= */
$p = (string)($_GET['p'] ?? 'dash');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $db = db();
    if ($p === 'logout') { $_SESSION = []; session_destroy(); go('?p=dash'); }

    if ($p === 'edit') {
        $id = (int)($_POST['id'] ?? 0);
        if (isset($_POST['delete']) && $id) {
            $db->prepare('DELETE FROM streams WHERE match_id = ?')->execute([$id]);
            $db->prepare('DELETE FROM sessions WHERE match_id = ?')->execute([$id]);
            $db->prepare('DELETE FROM matches WHERE id = ?')->execute([$id]);
            flash('تم حذف المباراة.'); go('?p=matches');
        }
        $title = field('title');
        $slug = preg_replace('/[^a-zA-Z0-9_-]/', '', field('slug'));
        if ($slug === '') { $slug = substr(bin2hex(random_bytes(4)), 0, 8); }
        $status = in_array(field('status'), ['live', 'upcoming', 'ended', 'hidden'], true) ? field('status') : 'live';
        $mode = field('mode') === 'open' ? 'open' : 'protected';
        $start = (int)field('start_ts');
        if ($title === '') { flash('اكتب عنوان المباراة.', 'err'); go('?p=edit' . ($id ? '&id=' . $id : '')); }
        $dup = $db->prepare('SELECT id FROM matches WHERE slug = ? AND id != ?');
        $dup->execute([$slug, $id]);
        if ($dup->fetch()) { flash('الرابط المختصر مستخدم لمباراة أخرى.', 'err'); go('?p=edit' . ($id ? '&id=' . $id : '')); }
        $vals = [$slug, $title, field('poster'), $start, $status, $mode, field('domains')];
        if ($id) {
            $db->prepare('UPDATE matches SET slug=?, title=?, poster=?, start_at=?, status=?, mode=?, domains=? WHERE id=?')->execute(array_merge($vals, [$id]));
        } else {
            $db->prepare('INSERT INTO matches(slug, title, poster, start_at, status, mode, domains, created) VALUES(?,?,?,?,?,?,?,?)')->execute(array_merge($vals, [time()]));
            $id = (int)$db->lastInsertId();
        }
        $db->prepare('DELETE FROM streams WHERE match_id = ?')->execute([$id]);
        $ins = $db->prepare('INSERT INTO streams(match_id, name, url, ref, ua, delivery, sort, active) VALUES(?,?,?,?,?,?,?,?)');
        $bad = 0;
        foreach ((array)($_POST['su'] ?? []) as $i => $u) {
            $u = trim((string)$u);
            if ($u === '') { continue; }
            if (!preg_match('#^https?://#i', $u)) { $bad++; continue; }
            $ins->execute([$id, trim((string)($_POST['sn'][$i] ?? '')), $u, trim((string)($_POST['sr'][$i] ?? '')), trim((string)($_POST['sa'][$i] ?? '')),
                (($_POST['sd'][$i] ?? 'proxy') === 'redirect') ? 'redirect' : 'proxy', (int)$i, empty($_POST['sx'][$i]) ? 1 : 0]);
        }
        flash($bad ? "تم الحفظ، لكن تم تجاهل $bad رابط غير صالح (لازم يبدأ بـ http/https)." : 'تم الحفظ.', $bad ? 'err' : 'ok');
        go('?p=edit&id=' . $id);
    }

    if ($p === 'ads') {
        foreach (['ad_head', 'ad_body', 'ad_links'] as $k) { set_setting($k, (string)($_POST[$k] ?? '')); }
        set_setting('ad_every', (string)max(1, (int)field('ad_every', '1')));
        set_setting('ad_cooldown', (string)max(0, (int)field('ad_cooldown', '60')));
        set_setting('ad_max', (string)max(0, (int)field('ad_max', '5')));
        flash('تم حفظ إعدادات الإعلانات.'); go('?p=ads');
    }

    if ($p === 'sec') {
        if (isset($_POST['dl_hls'])) {
            $r = download_hls();
            flash($r !== '' ? 'تم تنزيل hls.js محلياً.' : 'تعذّر التنزيل من السيرفر. نزّل hls.min.js يدوياً وضعه في مجلد assets.', $r !== '' ? 'ok' : 'err');
            go('?p=sec');
        }
        foreach (['allowed_domains', 'site_name', 'logo_url', 'msg_blocked'] as $k) { set_setting($k, field($k)); }
        set_setting('accent', preg_match('/^#[0-9a-fA-F]{6}$/', field('accent')) ? field('accent') : '#e11d48');
        foreach (['allow_no_referer', 'trust_cf', 'bind_ip', 'devtools_guard', 'ssl_verify', 'seg_cache', 'allow_private'] as $k) { set_setting($k, isset($_POST[$k]) ? '1' : '0'); }
        set_setting('pl_cache', (string)min(10, max(0, (int)field('pl_cache', '2'))));
        set_setting('ban_threshold', (string)max(0, (int)field('ban_threshold', '6')));
        set_setting('ban_minutes', (string)max(1, (int)field('ban_minutes', '120')));
        flash('تم حفظ الإعدادات.'); go('?p=sec');
    }

    if ($p === 'logs') {
        if (isset($_POST['unban'])) { $db->prepare('DELETE FROM bans WHERE ip = ?')->execute([field('unban')]); flash('تم فك الحظر.'); }
        if (isset($_POST['ban']) && filter_var(field('ban'), FILTER_VALIDATE_IP)) {
            $db->prepare('INSERT OR REPLACE INTO bans(ip, until, reason) VALUES(?,?,?)')->execute([field('ban'), time() + 86400 * 30, 'manual']);
            flash('تم الحظر 30 يوماً.');
        }
        if (isset($_POST['clear'])) { $db->exec('DELETE FROM events'); flash('تم مسح السجلات.'); }
        go('?p=logs');
    }

    if ($p === 'acct') {
        if (!password_verify((string)($_POST['old'] ?? ''), $hash)) { flash('كلمة المرور الحالية غير صحيحة.', 'err'); }
        elseif (strlen((string)($_POST['new'] ?? '')) < 8) { flash('كلمة المرور الجديدة قصيرة (8 أحرف على الأقل).', 'err'); }
        else { set_setting('admin_hash', password_hash((string)$_POST['new'], PASSWORD_DEFAULT)); flash('تم تغيير كلمة المرور.'); }
        go('?p=acct');
    }
    go('?p=dash');
}

/* ================= pages (GET) ================= */
$db = db();
ob_start();

if ($p === 'dash') {
    $now = time();
    $q = function ($sql, $a = []) use ($db) { $s = $db->prepare($sql); $s->execute($a); return (int)$s->fetchColumn(); };
    $viewers = $q('SELECT COUNT(*) FROM sessions WHERE hits > 0 AND last_seen > ?', [$now - 90]);
    $today = $q('SELECT COUNT(*) FROM sessions WHERE created > ?', [$now - 86400]);
    $decoys = $q("SELECT COUNT(*) FROM events WHERE type = 'decoy' AND ts > ?", [$now - 86400]);
    $tamper = $q("SELECT COUNT(*) FROM events WHERE type = 'tamper' AND ts > ?", [$now - 86400]);
    $domain = $q("SELECT COUNT(*) FROM events WHERE type = 'domain' AND ts > ?", [$now - 86400]);
    $bans = $q('SELECT COUNT(*) FROM bans WHERE until > ?', [$now]);
    $ads24 = $q('SELECT COUNT(*) FROM adclicks WHERE ts > ?', [$now - 86400]);
    $hlsOk = is_file(ROOT . '/assets/hls.min.js') && filesize(ROOT . '/assets/hls.min.js') > 100000;
    $req = [
        'PHP ' . PHP_VERSION => version_compare(PHP_VERSION, '7.4.0', '>='),
        'curl' => function_exists('curl_init'),
        'OpenSSL AES-GCM' => in_array('aes-256-gcm', openssl_get_cipher_methods(), true),
        'PDO SQLite' => extension_loaded('pdo_sqlite'),
        'مجلد data قابل للكتابة' => is_writable(DATA),
        'hls.js محلي (assets/hls.min.js)' => $hlsOk,
    ];
    echo '<h1>لوحة المعلومات</h1><div class="grid">';
    foreach ([['مشاهدون الآن', $viewers, 'good'], ['جلسات آخر 24 ساعة', $today, ''], ['نقرات إعلان 24 ساعة', $ads24, 'good'], ['طُعم/محاولات مشبوهة 24 ساعة', $decoys, $decoys ? 'warn' : ''],
        ['رصد أدوات مطوّر 24 ساعة', $tamper, $tamper ? 'warn' : ''], ['دومين غير مصرّح 24 ساعة', $domain, ''], ['عناوين محظورة الآن', $bans, '']] as $c) {
        echo '<div class="stat ' . $c[2] . '"><b>' . number_format($c[1]) . '</b><span>' . h($c[0]) . '</span></div>';
    }
    echo '</div>';
    echo '<div class="card"><h2>المتطلبات</h2><ul class="req">';
    foreach ($req as $l => $ok) { echo '<li class="' . ($ok ? 'ok' : 'no') . '">' . ($ok ? '✔' : '✖') . ' ' . h($l) . '</li>'; }
    echo '</ul>';
    if (!$hlsOk) { echo '<p class="mut">المشغل يستخدم نسخة hls.js من CDN مؤقتاً. اضغط الزر لتنزيلها على سيرفرك (أسرع وأأمن):</p><form method="post" action="?p=sec"><input type="hidden" name="_t" value="' . csrf() . '"><button class="btn" name="dl_hls" value="1">تنزيل hls.js على السيرفر</button></form>'; }
    echo '</div>';
    $rows = $db->query('SELECT m.id, m.title, m.slug, m.status, (SELECT COUNT(*) FROM sessions s WHERE s.match_id = m.id AND s.hits > 0 AND s.last_seen > ' . ($now - 90) . ') AS v FROM matches m ORDER BY v DESC, m.id DESC LIMIT 8')->fetchAll();
    echo '<div class="card"><h2>المباريات</h2><table><tr><th>المباراة</th><th>الحالة</th><th>مشاهدون الآن</th></tr>';
    foreach ($rows as $r) { echo '<tr><td><a href="?p=edit&id=' . $r['id'] . '">' . h($r['title']) . '</a></td><td>' . h($r['status']) . '</td><td>' . (int)$r['v'] . '</td></tr>'; }
    if (!$rows) { echo '<tr><td colspan="3" class="mut">لا توجد مباريات بعد. <a href="?p=edit">أضف أول مباراة</a></td></tr>'; }
    echo '</table></div>';
    $ev = $db->query('SELECT * FROM events ORDER BY id DESC LIMIT 12')->fetchAll();
    echo '<div class="card"><h2>آخر الأحداث</h2>' . events_table($ev) . '</div>';
}

elseif ($p === 'matches') {
    $now = time();
    $rows = $db->query('SELECT m.*, (SELECT COUNT(*) FROM streams s WHERE s.match_id = m.id) AS sc,
        (SELECT COUNT(*) FROM sessions s WHERE s.match_id = m.id AND s.hits > 0 AND s.last_seen > ' . ($now - 90) . ') AS v FROM matches m ORDER BY m.id DESC')->fetchAll();
    echo '<div class="bar"><h1>المباريات</h1><a class="btn" href="?p=edit">+ مباراة جديدة</a></div><div class="card"><table><tr><th>العنوان</th><th>الحالة</th><th>الحماية</th><th>سيرفرات</th><th>مشاهدون</th><th></th></tr>';
    $sl = ['live' => 'مباشر', 'upcoming' => 'قادمة', 'ended' => 'انتهت', 'hidden' => 'مخفية'];
    foreach ($rows as $r) {
        echo '<tr><td><b>' . h($r['title']) . '</b><br><small class="mut">' . h($r['slug']) . '</small></td><td><span class="badge ' . h($r['status']) . '">' . $sl[$r['status']] . '</span></td><td>'
            . ($r['mode'] === 'protected' ? '🔒 محمي' : '🌐 iframe عادي') . '</td><td>' . (int)$r['sc'] . '</td><td>' . (int)$r['v'] . '</td>'
            . '<td class="act"><a class="btn sm" href="?p=edit&id=' . $r['id'] . '">تعديل / كود التضمين</a> <a class="btn sm ghost" target="_blank" href="' . h(embed_url($r['slug'])) . '">معاينة</a></td></tr>';
    }
    if (!$rows) { echo '<tr><td colspan="6" class="mut">لا توجد مباريات.</td></tr>'; }
    echo '</table></div>';
}

elseif ($p === 'edit') {
    $id = (int)($_GET['id'] ?? 0);
    $m = ['id' => 0, 'slug' => '', 'title' => '', 'poster' => '', 'start_at' => 0, 'status' => 'live', 'mode' => 'protected', 'domains' => ''];
    $streams = [];
    if ($id) {
        $s = $db->prepare('SELECT * FROM matches WHERE id = ?'); $s->execute([$id]);
        $m = $s->fetch() ?: $m;
        $s = $db->prepare('SELECT * FROM streams WHERE match_id = ? ORDER BY sort, id'); $s->execute([$id]);
        $streams = $s->fetchAll();
    }
    if (!$streams) { $streams[] = ['name' => 'السيرفر 1', 'url' => '', 'ref' => '', 'ua' => '', 'delivery' => 'proxy', 'active' => 1]; }
    ?>
    <div class="bar"><h1><?= $id ? 'تعديل المباراة' : 'مباراة جديدة' ?></h1><a class="btn ghost" href="?p=matches">رجوع</a></div>
    <form method="post" class="card" id="mf"><input type="hidden" name="_t" value="<?= csrf() ?>"><input type="hidden" name="id" value="<?= (int)$m['id'] ?>">
    <div class="cols">
      <label>عنوان المباراة<input name="title" required value="<?= h($m['title']) ?>" placeholder="الأهلي × الزمالك"></label>
      <label>الرابط المختصر (slug)<input name="slug" value="<?= h($m['slug']) ?>" placeholder="ahly-zamalek" dir="ltr"></label>
      <label>صورة الغلاف (رابط)<input name="poster" value="<?= h($m['poster']) ?>" dir="ltr" placeholder="https://..."></label>
      <label>موعد البداية (للعدّاد التنازلي)<input type="datetime-local" id="st" dir="ltr"><input type="hidden" name="start_ts" id="stts" value="<?= (int)$m['start_at'] ?>"></label>
      <label>الحالة<select name="status"><?php foreach (['live' => 'مباشر', 'upcoming' => 'قادمة (عدّاد تنازلي)', 'ended' => 'انتهت', 'hidden' => 'مخفية'] as $k => $l) { echo '<option value="' . $k . '"' . ($m['status'] === $k ? ' selected' : '') . '>' . $l . '</option>'; } ?></select></label>
      <label>نوع التضمين<select name="mode"><option value="protected"<?= $m['mode'] === 'protected' ? ' selected' : '' ?>>🔒 محمي (قفل دومين + حارس أدوات المطوّر + توكنات)</option><option value="open"<?= $m['mode'] === 'open' ? ' selected' : '' ?>>🌐 iframe عادي (يعمل على أي موقع)</option></select></label>
    </div>
    <label>دومينات مسموحة لهذه المباراة فقط (اختياري، تتجاوز الإعداد العام — دومين في كل سطر)<textarea name="domains" rows="2" dir="ltr" placeholder="example.com"><?= h($m['domains']) ?></textarea></label>
    <h2>سيرفرات البث (روابط m3u8)</h2>
    <p class="mut">الرابط الحقيقي يبقى على السيرفر فقط ولا يظهر للمشاهد أبداً. «تمرير عبر السيرفر» أحمى لكنه يستهلك باندويث استضافتك؛ «تحويل مباشر» يوفّر الباندويث لكن رابط أجزاء الفيديو (ليس الـ m3u8) يظهر لمن يفحص الشبكة.</p>
    <div id="sl"><?php foreach ($streams as $i => $s): ?>
      <div class="srow">
        <input name="sn[]" value="<?= h($s['name']) ?>" placeholder="اسم السيرفر">
        <input name="su[]" value="<?= h($s['url']) ?>" placeholder="https://.../playlist.m3u8" dir="ltr" class="wide">
        <input name="sr[]" value="<?= h($s['ref']) ?>" placeholder="Referer (اختياري)" dir="ltr">
        <input name="sa[]" value="<?= h($s['ua']) ?>" placeholder="User-Agent (اختياري)" dir="ltr">
        <select name="sd[]"><option value="proxy"<?= $s['delivery'] === 'proxy' ? ' selected' : '' ?>>تمرير عبر السيرفر</option><option value="redirect"<?= $s['delivery'] === 'redirect' ? ' selected' : '' ?>>تحويل مباشر</option></select>
        <label class="chk"><input type="checkbox" name="sx[<?= $i ?>]" value="1"<?= empty($s['active']) ? ' checked' : '' ?>> إيقاف</label>
        <button type="button" class="btn sm ghost rm">حذف</button>
      </div><?php endforeach; ?></div>
    <p><button type="button" class="btn ghost" id="add">+ إضافة سيرفر</button></p>
    <div class="bar"><button class="btn">حفظ</button><?php if ($id): ?><button class="btn danger" name="delete" value="1" onclick="return confirm('حذف المباراة نهائياً؟')">حذف المباراة</button><?php endif; ?></div>
    </form>
    <?php if ($id): ?>
    <div class="card"><h2>أكواد التضمين</h2>
      <p class="mut">انسخ الكود وضعه في موقعك. <b>لا تضف خاصية sandbox</b> على الـ iframe لأنها تمنع نوافذ الإعلانات (pop-under).</p>
      <label><?= $m['mode'] === 'protected' ? '🔒 تضمين محمي (يعمل فقط على الدومينات المسموحة)' : '🌐 تضمين عادي' ?><textarea readonly rows="3" dir="ltr" onclick="this.select()"><?= h(iframe_code($m['slug'])) ?></textarea></label>
      <label>الرابط المباشر للمعاينة<input readonly dir="ltr" value="<?= h(embed_url($m['slug'])) ?>" onclick="this.select()"></label>
      <p class="mut">لتبديل النوع (محمي / عادي) غيّر «نوع التضمين» أعلاه واحفظ — نفس الرابط يعمل بالنوع الجديد.</p>
    </div>
    <?php endif; ?>
    <script>
    (function(){
      var st=document.getElementById('st'), ts=document.getElementById('stts'), v=parseInt(ts.value,10);
      function pad(n){return n<10?'0'+n:n}
      if(v){var d=new Date(v*1000);st.value=d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'T'+pad(d.getHours())+':'+pad(d.getMinutes());}
      st.onchange=function(){ts.value=st.value?Math.floor(new Date(st.value).getTime()/1000):0;};
      var sl=document.getElementById('sl');
      function renum(){[].forEach.call(sl.querySelectorAll('.srow'),function(r,i){r.querySelector('input[type=checkbox]').name='sx['+i+']';});}
      document.getElementById('add').onclick=function(){var r=sl.querySelector('.srow').cloneNode(true);[].forEach.call(r.querySelectorAll('input[type=text],input:not([type])'),function(i){i.value='';});r.querySelector('input[type=checkbox]').checked=false;sl.appendChild(r);renum();};
      sl.addEventListener('click',function(e){if(e.target.classList.contains('rm')){var rows=sl.querySelectorAll('.srow');if(rows.length>1){e.target.closest('.srow').remove();renum();}}});
    })();
    </script>
    <?php
}

elseif ($p === 'ads') { ?>
    <h1>الإعدادات الإعلانية</h1>
    <form method="post" class="card"><input type="hidden" name="_t" value="<?= csrf() ?>">
      <p class="mut">أكواد شبكات الإعلانات (Adsterra / PropellerAds / غيرها) تعمل <b>داخل صفحة المشغل نفسها</b>، فكل ضغطة مشاهد على المشغل تُحسب لدى الشبكة. المشغل لا يمنع النوافذ المنبثقة ولا يوقف انتشار النقرات (propagation).</p>
      <label>كود يوضع في &lt;head&gt; (سكربتات الشبكة العامة)<textarea name="ad_head" rows="4" dir="ltr"><?= h(setting('ad_head')) ?></textarea></label>
      <label>كود يوضع نهاية الصفحة (سكربت Pop-under / Social bar / Native)<textarea name="ad_body" rows="5" dir="ltr" placeholder="&lt;script src=&quot;//...&quot;&gt;&lt;/script&gt;"><?= h(setting('ad_body')) ?></textarea></label>
      <label>روابط إعلانية مباشرة (Direct Link / Smartlink) — رابط في كل سطر، تُفتح بالتناوب عند نقر المشاهد<textarea name="ad_links" rows="3" dir="ltr"><?= h(setting('ad_links')) ?></textarea></label>
      <div class="cols">
        <label>افتح الإعلان كل كم ضغطة<input type="number" min="1" name="ad_every" value="<?= h(setting('ad_every')) ?>"></label>
        <label>الحد الأدنى بين إعلانين (ثانية)<input type="number" min="0" name="ad_cooldown" value="<?= h(setting('ad_cooldown')) ?>"></label>
        <label>الحد الأقصى لكل مشاهد في الجلسة (0 = بلا حد)<input type="number" min="0" name="ad_max" value="<?= h(setting('ad_max')) ?>"></label>
      </div>
      <button class="btn">حفظ</button>
    </form>
    <?php
    $s = $db->query('SELECT m.title, COUNT(a.id) c FROM adclicks a LEFT JOIN matches m ON m.id = a.match_id WHERE a.ts > ' . (time() - 86400) . ' GROUP BY a.match_id ORDER BY c DESC LIMIT 10')->fetchAll();
    echo '<div class="card"><h2>الروابط المباشرة المفتوحة (آخر 24 ساعة)</h2><table><tr><th>المباراة</th><th>العدد</th></tr>';
    foreach ($s as $r) { echo '<tr><td>' . h($r['title'] ?? '—') . '</td><td>' . (int)$r['c'] . '</td></tr>'; }
    if (!$s) { echo '<tr><td colspan="2" class="mut">لا بيانات بعد.</td></tr>'; }
    echo '</table><p class="mut">هذه الأرقام تخص الروابط التي يفتحها المشغل بنفسه. إحصاءات سكربتات الشبكة تظهر في لوحة الشبكة الإعلانية.</p></div>';
}

elseif ($p === 'sec') { ?>
    <h1>الأمان والإعدادات</h1>
    <form method="post" class="card"><input type="hidden" name="_t" value="<?= csrf() ?>">
      <h2>قفل الدومينات</h2>
      <label>الدومينات المسموح لها بتضمين المشغل (للمباريات «المحمية») — دومين في كل سطر<textarea name="allowed_domains" rows="3" dir="ltr" placeholder="mysite.com"><?= h(setting('allowed_domains')) ?></textarea></label>
      <p class="mut">يتم الفرض بثلاث طبقات: رأس Referer، وCSP frame-ancestors من المتصفح نفسه، وفحص داخل الصفحة. اتركه فارغاً لعدم تقييد الدومينات (غير مستحسن).</p>
      <label class="chk"><input type="checkbox" name="allow_no_referer" value="1" <?= setting('allow_no_referer') === '1' ? 'checked' : '' ?>> السماح بالطلبات بدون Referer (قد يلزم لبعض متصفحات التطبيقات، يقلل الحماية)</label>
      <h2>الحماية</h2>
      <label class="chk"><input type="checkbox" name="devtools_guard" value="1" <?= setting('devtools_guard') === '1' ? 'checked' : '' ?>> حارس أدوات المطوّر (debugger + كشف الـ console) في المباريات المحمية</label>
      <label class="chk"><input type="checkbox" name="bind_ip" value="1" <?= setting('bind_ip') === '1' ? 'checked' : '' ?>> ربط الجلسة بالشبكة (IP prefix) — يمنع مشاركة الروابط، لكن قد يقطع مشاهداً تتغير شبكته أثناء المشاهدة</label>
      <label class="chk"><input type="checkbox" name="trust_cf" value="1" <?= setting('trust_cf') === '1' ? 'checked' : '' ?>> الموقع خلف Cloudflare (اقرأ IP الحقيقي من CF-Connecting-IP)</label>
      <div class="cols">
        <label>حظر تلقائي بعد كم محاولة مشبوهة خلال 10 دقائق (0 = إيقاف)<input type="number" min="0" name="ban_threshold" value="<?= h(setting('ban_threshold')) ?>"></label>
        <label>مدة الحظر (دقيقة)<input type="number" min="1" name="ban_minutes" value="<?= h(setting('ban_minutes')) ?>"></label>
        <label>رسالة الإيقاف الأمني<input name="msg_blocked" value="<?= h(setting('msg_blocked')) ?>"></label>
      </div>
      <h2>الأداء</h2>
      <div class="cols">
        <label>مدة كاش قائمة التشغيل بالثواني (تقلل الضغط على مصدر البث)<input type="number" min="0" max="10" name="pl_cache" value="<?= h(setting('pl_cache')) ?>"></label>
      </div>
      <label class="chk"><input type="checkbox" name="seg_cache" value="1" <?= setting('seg_cache') === '1' ? 'checked' : '' ?>> كاش أجزاء الفيديو على القرص لدقيقة (يطلب المصدر مرة واحدة مهما بلغ عدد المشاهدين)</label>
      <label class="chk"><input type="checkbox" name="ssl_verify" value="1" <?= setting('ssl_verify') === '1' ? 'checked' : '' ?>> التحقق من شهادة SSL لمصدر البث (أوقفه فقط لو المصدر شهادته مكسورة)</label>
      <label class="chk"><input type="checkbox" name="allow_private" value="1" <?= setting('allow_private') === '1' ? 'checked' : '' ?>> السماح بمصدر بث على localhost أو شبكة داخلية (فعّله فقط لو سيرفر البث على نفس الجهاز/الشبكة)</label>
      <h2>شكل المشغل</h2>
      <div class="cols">
        <label>اسم الموقع<input name="site_name" value="<?= h(setting('site_name')) ?>"></label>
        <label>لون التمييز<input type="color" name="accent" value="<?= h(setting('accent')) ?>"></label>
        <label>شعار فوق الفيديو (رابط صورة PNG شفافة)<input name="logo_url" dir="ltr" value="<?= h(setting('logo_url')) ?>"></label>
      </div>
      <button class="btn">حفظ</button>
    </form>
    <?php $hlsOk = is_file(ROOT . '/assets/hls.min.js') && filesize(ROOT . '/assets/hls.min.js') > 100000; ?>
    <form method="post" class="card"><input type="hidden" name="_t" value="<?= csrf() ?>"><h2>مكوّن hls.js</h2>
      <p class="mut"><?= $hlsOk ? '✔ مثبّت محلياً على السيرفر (' . round(filesize(ROOT . '/assets/hls.min.js') / 1024) . ' KB).' : '✖ غير مثبّت — المشغل يحمّله من CDN حالياً.' ?></p>
      <button class="btn ghost" name="dl_hls" value="1"><?= $hlsOk ? 'تحديث' : 'تنزيل' ?> hls.js على السيرفر</button></form>
    <?php
}

elseif ($p === 'logs') {
    $type = (string)($_GET['t'] ?? '');
    $ev = $type !== '' ? $db->prepare('SELECT * FROM events WHERE type = ? ORDER BY id DESC LIMIT 200') : $db->prepare('SELECT * FROM events ORDER BY id DESC LIMIT 200');
    $type !== '' ? $ev->execute([$type]) : $ev->execute();
    $bans = $db->query('SELECT * FROM bans WHERE until > ' . time() . ' ORDER BY until DESC')->fetchAll();
    echo '<h1>السجلات والحظر</h1><div class="card"><h2>العناوين المحظورة</h2><table><tr><th>IP</th><th>حتى</th><th>السبب</th><th></th></tr>';
    foreach ($bans as $b) { echo '<tr><td dir="ltr">' . h($b['ip']) . '</td><td>' . fmt_ts($b['until']) . '</td><td>' . h($b['reason']) . '</td><td><form method="post" action="?p=logs"><input type="hidden" name="_t" value="' . csrf() . '"><button class="btn sm" name="unban" value="' . h($b['ip']) . '">فك الحظر</button></form></td></tr>'; }
    if (!$bans) { echo '<tr><td colspan="4" class="mut">لا يوجد.</td></tr>'; }
    echo '</table><form method="post" action="?p=logs" class="inline"><input type="hidden" name="_t" value="' . csrf() . '"><input name="ban" placeholder="حظر IP يدوياً" dir="ltr"><button class="btn sm">حظر 30 يوماً</button></form></div>';
    echo '<div class="card"><div class="bar"><h2>الأحداث</h2><div>';
    foreach (['' => 'الكل', 'decoy' => 'طُعم', 'tamper' => 'أدوات مطوّر', 'replay' => 'تكرار توكن', 'badbind' => 'تغيّر شبكة', 'domain' => 'دومين', 'upstream' => 'مصدر البث', 'login_fail' => 'دخول فاشل'] as $k => $l) { echo '<a class="btn sm ghost" href="?p=logs&t=' . $k . '">' . $l . '</a> '; }
    echo '</div></div>' . events_table($ev->fetchAll());
    echo '<form method="post" action="?p=logs"><input type="hidden" name="_t" value="' . csrf() . '"><button class="btn sm danger" name="clear" value="1" onclick="return confirm(\'مسح كل السجلات؟\')">مسح السجلات</button></form></div>';
}

elseif ($p === 'acct') { ?>
    <h1>الحساب</h1>
    <form method="post" class="card narrow"><input type="hidden" name="_t" value="<?= csrf() ?>">
      <label>كلمة المرور الحالية<input type="password" name="old" required></label>
      <label>كلمة المرور الجديدة<input type="password" name="new" required minlength="8"></label>
      <button class="btn">تغيير</button></form>
    <?php
}
else { go('?p=dash'); }

function events_table(array $ev): string {
    $o = '<table><tr><th>الوقت</th><th>النوع</th><th>IP</th><th>التفاصيل</th><th>المتصفح</th></tr>';
    foreach ($ev as $e) {
        $o .= '<tr><td>' . fmt_ts($e['ts']) . '</td><td><span class="badge t-' . h($e['type']) . '">' . h($e['type']) . '</span></td><td dir="ltr">' . h($e['ip'])
            . ' <form method="post" action="?p=logs" class="inl"><input type="hidden" name="_t" value="' . csrf() . '"><button class="lnk" name="ban" value="' . h($e['ip']) . '" title="حظر">⛔</button></form></td><td>'
            . h($e['detail']) . '</td><td class="ua" dir="ltr">' . h(substr((string)($e['ua'] ?? ''), 0, 60)) . '</td></tr>';
    }
    if (!$ev) { $o .= '<tr><td colspan="5" class="mut">لا توجد أحداث.</td></tr>'; }
    return $o . '</table>';
}

$titles = ['dash' => 'لوحة المعلومات', 'matches' => 'المباريات', 'edit' => 'مباراة', 'ads' => 'الإعلانات', 'sec' => 'الأمان', 'logs' => 'السجلات', 'acct' => 'الحساب'];
layout($titles[$p] ?? 'لوحة التحكم', ob_get_clean());

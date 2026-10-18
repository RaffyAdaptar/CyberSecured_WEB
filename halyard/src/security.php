<?php
declare(strict_types=1);

function is_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') {
        return true;
    }
    if (config('trust_proxy') === true
        && strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https') {
        return true;
    }
    return false;
}

/** Send hardening headers on every response. */
function send_security_headers(): void
{
    header_remove('X-Powered-By');
    header('Content-Type: text/html; charset=utf-8');

    // No inline scripts or styles are used anywhere, so the policy can be strict.
    // Google Fonts is the only third party, and only for CSS and font files.
    header("Content-Security-Policy: "
        . "default-src 'none'; "
        . "script-src 'self'; "
        . "style-src 'self' https://fonts.googleapis.com; "
        . "font-src https://fonts.gstatic.com; "
        . "img-src 'self' data:; "
        . "form-action 'self'; "
        . "base-uri 'none'; "
        . "frame-ancestors 'none'");

    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    // "same-origin" sends no referrer to other sites, but still lets browsers send a real
    // Origin header on our own form posts. ("no-referrer" makes Chrome send "Origin: null",
    // which the CSRF origin check would correctly reject.)
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    // Account pages must never be stored by browsers or shared caches.
    header('Cache-Control: no-store, max-age=0');
    header('Pragma: no-cache');

    if (is_https()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

/** Start the session with hardened cookie settings and enforce timeouts. */
function start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $secure = is_https();

    ini_set('session.use_strict_mode', '1');   // reject session IDs the server did not create
    ini_set('session.use_only_cookies', '1');  // never accept IDs from the URL
    ini_set('session.use_trans_sid', '0');

    // The __Host- prefix pins the cookie to this exact host over HTTPS.
    session_name($secure ? '__Host-halyard_sid' : 'halyard_sid');
    session_set_cookie_params([
        'lifetime' => 0,          // session cookie, gone when the browser closes
        'path'     => '/',
        'secure'   => $secure,
        'httponly' => true,       // JavaScript cannot read it
        'samesite' => 'Lax',
    ]);

    session_start();

    if (isset($_SESSION['uid'])) {
        $now      = time();
        $idle     = (int)config('session.idle_timeout');
        $absolute = (int)config('session.absolute_timeout');

        $expired = ($now - (int)($_SESSION['last_seen'] ?? 0)) > $idle
                || ($now - (int)($_SESSION['started'] ?? 0)) > $absolute;

        if ($expired) {
            destroy_session();
            session_start(); // fresh, anonymous session
            return;
        }

        $_SESSION['last_seen'] = $now;

        // Rotate the session ID every 15 minutes while signed in.
        if ($now - (int)($_SESSION['rotated'] ?? 0) > 900) {
            session_regenerate_id(true);
            $_SESSION['rotated'] = $now;
        }
    }
}

function destroy_session(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires'  => time() - 42000,
            'path'     => $p['path'],
            'domain'   => $p['domain'],
            'secure'   => $p['secure'],
            'httponly' => $p['httponly'],
            'samesite' => $p['samesite'] ?: 'Lax',
        ]);
    }
    session_destroy();
}

/** Mark the session as signed in. Regenerates the ID to prevent session fixation. */
function sign_in_session(int $userId): void
{
    session_regenerate_id(true);
    $now = time();
    $_SESSION['uid']       = $userId;
    $_SESSION['started']   = $now;
    $_SESSION['last_seen'] = $now;
    $_SESSION['rotated']   = $now;
    $_SESSION['csrf']      = bin2hex(random_bytes(32)); // new token for the new session
}

function current_user_id(): ?int
{
    return isset($_SESSION['uid']) ? (int)$_SESSION['uid'] : null;
}

/* ---------------------------------------------------------------- CSRF -- */

function csrf_token(): string
{
    if (empty($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf" value="' . e(csrf_token()) . '">';
}

/** True when a POST carries the session's CSRF token and comes from this site. */
function csrf_valid(): bool
{
    $sent = $_POST['csrf'] ?? null;
    if (!is_string($sent) || $sent === '') {
        return false;
    }
    return hash_equals(csrf_token(), $sent) && origin_ok();
}

/** If the browser sent an Origin header, it must match our own host. */
function origin_ok(): bool
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
    if ($origin === null || $origin === '') {
        return true; // older browsers and some privacy tools omit it; the token still protects us
    }
    $parts = parse_url((string)$origin);
    if ($parts === false || empty($parts['host'])) {
        return false; // e.g. "null" origins
    }
    $host = strtolower($parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : ''));
    return hash_equals(strtolower((string)($_SERVER['HTTP_HOST'] ?? '')), $host);
}

/** Only allow the HTTP methods these pages actually handle. */
function require_method(array $allowed): void
{
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($method, $allowed, true)) {
        http_response_code(405);
        header('Allow: ' . implode(', ', $allowed));
        exit('Method not allowed.');
    }
}

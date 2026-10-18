<?php
declare(strict_types=1);

/** Read a config value with dot notation, e.g. config('db.dsn'). */
function config(string $path, mixed $default = null): mixed
{
    static $cfg = null;
    if ($cfg === null) {
        $cfg = require APP_ROOT . '/src/config.php';
    }
    $node = $cfg;
    foreach (explode('.', $path) as $segment) {
        if (!is_array($node) || !array_key_exists($segment, $node)) {
            return $default;
        }
        $node = $node[$segment];
    }
    return $node;
}

/** Escape a value for safe output inside HTML (text and attributes). */
function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Redirect to a fixed, app-internal path. Never pass user input here. */
function redirect(string $path): never
{
    header('Location: ' . $path, true, 303);
    exit;
}

/**
 * Read a POST field as a string. Returns null when the field is missing, is not a
 * plain string (e.g. `field[]=x`), is not valid UTF-8, contains a NUL byte, or is
 * longer than $maxBytes.
 */
function post_string(string $key, int $maxBytes): ?string
{
    $value = $_POST[$key] ?? null;
    if (!is_string($value)) {
        return null;
    }
    if (strlen($value) > $maxBytes || str_contains($value, "\0") || !mb_check_encoding($value, 'UTF-8')) {
        return null;
    }
    return $value;
}

/** Client IP address. Only trusts proxy headers when config('trust_proxy') is true. */
function client_ip(): string
{
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');

    if (config('trust_proxy') === true && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        // The right-most entry is the one appended by our own proxy.
        $parts = array_map('trim', explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR']));
        $ip = (string)end($parts);
    }

    return filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : '0.0.0.0';
}

/** Format a UTC database timestamp for display. */
function format_time(?string $utc): string
{
    if ($utc === null || $utc === '') {
        return 'Not yet';
    }
    try {
        $dt = new DateTimeImmutable($utc, new DateTimeZone('UTC'));
    } catch (Exception) {
        return 'Unknown';
    }
    return $dt->format('j M Y, H:i') . ' UTC';
}

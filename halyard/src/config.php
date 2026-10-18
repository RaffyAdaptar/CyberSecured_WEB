<?php
declare(strict_types=1);

/*
 * Halyard configuration.
 *
 * Secrets never belong in this file. Either set environment variables, or copy
 * config.local.sample.php to config.local.php (git-ignored) and put your values there.
 */

$config = [
    // Never enable debug on a public server: it prints error details to visitors.
    'debug' => filter_var(getenv('HALYARD_DEBUG') ?: '0', FILTER_VALIDATE_BOOLEAN),

    // Set to true ONLY if the app sits behind a reverse proxy you control
    // that sets X-Forwarded-Proto / X-Forwarded-For.
    'trust_proxy' => false,

    'db' => [
        'dsn' => getenv('HALYARD_DB_DSN') ?: sprintf(
            'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
            getenv('HALYARD_DB_HOST') ?: '127.0.0.1',
            getenv('HALYARD_DB_PORT') ?: '3306',
            getenv('HALYARD_DB_NAME') ?: 'halyard'
        ),
        'user' => getenv('HALYARD_DB_USER') ?: 'halyard_app',
        'pass' => getenv('HALYARD_DB_PASS') ?: '',
    ],

    'session' => [
        'idle_timeout'     => 1800,   // seconds without activity before sign-out
        'absolute_timeout' => 28800,  // seconds since sign-in before sign-out, no matter what
    ],

    'throttle' => [
        'login_window'             => 900,  // seconds
        'login_max_per_account_ip' => 5,    // failed attempts per (account, IP) in the window
        'login_max_per_ip'         => 20,   // failed attempts per IP in the window
        'register_window'          => 3600,
        'register_max_per_ip'      => 20,   // sign-up attempts per IP in the window (shared Wi-Fi friendly)
    ],
];

$local = __DIR__ . '/config.local.php';
if (is_file($local)) {
    $config = array_replace_recursive($config, require $local);
}

return $config;

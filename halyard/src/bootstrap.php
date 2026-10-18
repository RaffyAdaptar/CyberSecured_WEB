<?php
declare(strict_types=1);

define('APP_ROOT', dirname(__DIR__));

require __DIR__ . '/helpers.php';
require __DIR__ . '/db.php';
require __DIR__ . '/security.php';
require __DIR__ . '/auth.php';
require __DIR__ . '/view.php';

error_reporting(E_ALL);
ini_set('display_errors', config('debug') ? '1' : '0'); // never show PHP errors to visitors
ini_set('log_errors', '1');

// Anything uncaught (for example, the database being down) gets a plain message.
// Details go to the server log only, so table names, paths and passwords never leak.
set_exception_handler(static function (Throwable $e): void {
    error_log('[halyard] ' . get_class($e) . ': ' . $e->getMessage()
        . ' in ' . $e->getFile() . ':' . $e->getLine());
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
    }
    echo config('debug') ? (string)$e : 'Something went wrong on our side. Try again in a moment.';
});

send_security_headers();
start_session();

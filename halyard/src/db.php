<?php
declare(strict_types=1);

/**
 * Shared PDO connection.
 *
 * Every query in this app uses prepared statements with bound parameters and
 * native (server-side) preparation, so user input is never interpreted as SQL.
 */
function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dsn = (string)config('db.dsn');

    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,   // real prepared statements
        PDO::ATTR_STRINGIFY_FETCHES  => false,
    ];

    // Defense in depth: refuse stacked queries ("...; DROP TABLE users").
    if (str_starts_with($dsn, 'mysql:') && defined('PDO::MYSQL_ATTR_MULTI_STATEMENTS')) {
        $options[PDO::MYSQL_ATTR_MULTI_STATEMENTS] = false;
    }

    $pdo = new PDO($dsn, (string)config('db.user'), (string)config('db.pass'), $options);
    return $pdo;
}

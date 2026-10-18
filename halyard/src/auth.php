<?php
declare(strict_types=1);

/* ------------------------------------------------------------ Passwords -- */

/** Argon2id when this PHP build has it, otherwise bcrypt. Both are slow by design. */
function password_algo(): array
{
    if (defined('PASSWORD_ARGON2ID')) {
        return [PASSWORD_ARGON2ID, ['memory_cost' => 19456, 'time_cost' => 2, 'threads' => 1]];
    }
    return [PASSWORD_BCRYPT, ['cost' => 12]];
}

function hash_password(string $password): string
{
    [$algo, $options] = password_algo();
    return password_hash($password, $algo, $options);
}

const COMMON_PASSWORDS = [
    'password', 'password1', 'password12', 'password123', 'password1234', '1234567890', '12345678910',
    'qwertyuiop', 'qwerty123456', 'qwertyuiop123', '1q2w3e4r5t', 'iloveyou123', 'letmein1234',
    'admin12345', 'welcome1234', 'abc1234567', 'abcdefghij', '0123456789', '1111111111', '0000000000',
    'passw0rd123', 'changeme123', 'monkey12345', 'dragon12345', 'football123', 'baseball123',
];

/* ----------------------------------------------------------- Validation -- */

/**
 * Validate sign-up input. Returns [errors keyed by field, cleaned values].
 * The same rules run in JavaScript for convenience, but only these ones are trusted.
 */
function validate_registration(?string $username, ?string $email, ?string $password, ?string $confirm): array
{
    $errors = [];
    $username = trim($username ?? '');
    $email    = mb_strtolower(trim($email ?? ''), 'UTF-8');
    $password = $password ?? '';
    $confirm  = $confirm ?? '';

    // D modifier: "$" must match the very end, not just before a trailing newline.
    if (!preg_match('/^[A-Za-z0-9_]{3,24}$/D', $username)) {
        $errors['username'] = 'Use 3 to 24 letters, numbers or underscores.';
    }

    if (strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        $errors['email'] = 'Enter a valid email address.';
    }

    $length = mb_strlen($password, 'UTF-8');
    if ($length < 10) {
        $errors['password'] = 'Use at least 10 characters.';
    } elseif ($length > 128) {
        $errors['password'] = 'Use 128 characters or fewer.';
    } elseif (in_array(mb_strtolower($password, 'UTF-8'), COMMON_PASSWORDS, true)
        || mb_strtolower($password, 'UTF-8') === mb_strtolower($username, 'UTF-8')
        || mb_strtolower($password, 'UTF-8') === $email) {
        $errors['password'] = 'That password is too easy to guess. Try a few unrelated words.';
    }

    if (!isset($errors['password']) && !hash_equals($password, $confirm)) {
        $errors['confirm'] = 'Passwords don’t match.';
    }

    return [$errors, ['username' => $username, 'email' => $email, 'password' => $password]];
}

/* ------------------------------------------------------------- Accounts -- */

/** Insert a user. Returns the new id, or null if the username or email is already taken. */
function create_user(PDO $pdo, string $username, string $email, string $password): ?int
{
    $hash = hash_password($password);

    $stmt = $pdo->prepare(
        'INSERT INTO users (username, username_key, email, password_hash, created_at, last_login_at)
         VALUES (:username, :username_key, :email, :password_hash, :created_at, :last_login_at)'
    );

    $now = gmdate('Y-m-d H:i:s'); // signing up also signs the new member in

    try {
        $stmt->execute([
            ':username'      => $username,
            ':username_key'  => strtolower($username),
            ':email'         => $email,
            ':password_hash' => $hash,
            ':created_at'    => $now,
            ':last_login_at' => $now,
        ]);
    } catch (PDOException $e) {
        // SQLSTATE 23000 = integrity constraint violation (duplicate username or email).
        // Letting the database enforce uniqueness also closes the check-then-insert race.
        if ((string)$e->getCode() === '23000') {
            return null;
        }
        throw $e;
    }

    return (int)$pdo->lastInsertId();
}

function find_user_by_id(PDO $pdo, int $id): ?array
{
    $stmt = $pdo->prepare(
        'SELECT id, username, email, created_at, last_login_at FROM users WHERE id = :id LIMIT 1'
    );
    $stmt->execute([':id' => $id]);
    $row = $stmt->fetch();
    return $row === false ? null : $row;
}

/** Look up by username or email. Usernames cannot contain "@", so the two never collide. */
function find_user_for_login(PDO $pdo, string $identifier): ?array
{
    $needle = mb_strtolower($identifier, 'UTF-8');
    // Two names for the same value: native prepared statements do not allow reusing one.
    $stmt = $pdo->prepare(
        'SELECT id, username, email, password_hash FROM users
         WHERE username_key = :as_username OR email = :as_email LIMIT 1'
    );
    $stmt->execute([':as_username' => $needle, ':as_email' => $needle]);
    $row = $stmt->fetch();
    return $row === false ? null : $row;
}

/* --------------------------------------------------------- Rate limiting -- */

function throttle_count(PDO $pdo, string $kind, string $ip, ?string $subject, int $window): int
{
    $since = time() - $window;

    if ($subject === null) {
        $stmt = $pdo->prepare(
            'SELECT COUNT(*) FROM auth_attempts WHERE kind = :kind AND ip = :ip AND attempted_at > :since'
        );
        $stmt->execute([':kind' => $kind, ':ip' => $ip, ':since' => $since]);
    } else {
        $stmt = $pdo->prepare(
            'SELECT COUNT(*) FROM auth_attempts
             WHERE kind = :kind AND ip = :ip AND subject_hash = :subject AND attempted_at > :since'
        );
        $stmt->execute([':kind' => $kind, ':ip' => $ip, ':subject' => $subject, ':since' => $since]);
    }

    return (int)$stmt->fetchColumn();
}

function throttle_record(PDO $pdo, string $kind, string $ip, string $subject): void
{
    $stmt = $pdo->prepare(
        'INSERT INTO auth_attempts (kind, ip, subject_hash, attempted_at)
         VALUES (:kind, :ip, :subject, :at)'
    );
    $stmt->execute([':kind' => $kind, ':ip' => $ip, ':subject' => $subject, ':at' => time()]);
}

function throttle_clear(PDO $pdo, string $kind, string $ip, string $subject): void
{
    $stmt = $pdo->prepare(
        'DELETE FROM auth_attempts WHERE kind = :kind AND ip = :ip AND subject_hash = :subject'
    );
    $stmt->execute([':kind' => $kind, ':ip' => $ip, ':subject' => $subject]);
}

/** Occasionally remove records older than a day so the table stays small. */
function throttle_prune(PDO $pdo): void
{
    if (random_int(1, 50) !== 1) {
        return;
    }
    $stmt = $pdo->prepare('DELETE FROM auth_attempts WHERE attempted_at < :cutoff');
    $stmt->execute([':cutoff' => time() - 86400]);
}

function login_is_locked(PDO $pdo, string $ip, string $subject): bool
{
    $window = (int)config('throttle.login_window');
    return throttle_count($pdo, 'login', $ip, $subject, $window) >= (int)config('throttle.login_max_per_account_ip')
        || throttle_count($pdo, 'login', $ip, null, $window) >= (int)config('throttle.login_max_per_ip');
}

function register_is_locked(PDO $pdo, string $ip): bool
{
    return throttle_count($pdo, 'register', $ip, null, (int)config('throttle.register_window'))
        >= (int)config('throttle.register_max_per_ip');
}

/* --------------------------------------------------------------- Sign in -- */

/**
 * Try to sign someone in. Returns ['status' => 'ok'|'invalid'|'locked', 'user_id' => ?int].
 *
 * - The same "invalid" result covers an unknown account and a wrong password.
 * - An unknown account still pays the cost of one password hash, so response
 *   time does not reveal which usernames exist.
 */
function attempt_login(PDO $pdo, string $identifier, string $password): array
{
    $ip      = client_ip();
    $subject = hash('sha256', mb_strtolower($identifier, 'UTF-8'));

    throttle_prune($pdo);

    if (login_is_locked($pdo, $ip, $subject)) {
        return ['status' => 'locked', 'user_id' => null];
    }

    $user = $identifier !== '' ? find_user_for_login($pdo, $identifier) : null;

    if ($user === null) {
        hash_password($password);               // equalize timing with the verify path
        $valid = false;
    } else {
        $valid = password_verify($password, $user['password_hash']);
    }

    if (!$valid) {
        throttle_record($pdo, 'login', $ip, $subject);
        return ['status' => 'invalid', 'user_id' => null];
    }

    throttle_clear($pdo, 'login', $ip, $subject);

    // Upgrade the stored hash if our settings have gotten stronger since it was made.
    [$algo, $options] = password_algo();
    $newHash = password_needs_rehash($user['password_hash'], $algo, $options)
        ? hash_password($password)
        : $user['password_hash'];

    $stmt = $pdo->prepare(
        'UPDATE users SET password_hash = :hash, last_login_at = :now WHERE id = :id'
    );
    $stmt->execute([':hash' => $newHash, ':now' => gmdate('Y-m-d H:i:s'), ':id' => (int)$user['id']]);

    return ['status' => 'ok', 'user_id' => (int)$user['id']];
}

/** Redirect to the sign-in page unless someone is signed in. Returns the user row. */
function require_login(PDO $pdo): array
{
    $id = current_user_id();
    $user = $id !== null ? find_user_by_id($pdo, $id) : null;

    if ($user === null) {
        if ($id !== null) {
            destroy_session(); // the account behind this session no longer exists
        }
        redirect('login.php');
    }
    return $user;
}

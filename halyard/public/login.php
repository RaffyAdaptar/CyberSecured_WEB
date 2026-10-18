<?php
declare(strict_types=1);

require __DIR__ . '/../src/bootstrap.php';

require_method(['GET', 'HEAD', 'POST']);

if (current_user_id() !== null) {
    redirect('dashboard.php');
}

$errors = [];
$identifier = '';
$notice = isset($_GET['signed_out']) ? 'You’re signed out.' : '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_valid()) {
        http_response_code(403);
        $errors['form'] = 'This page expired. Reload it and try again.';
    } else {
        $identifier = trim(post_string('identifier', 254) ?? '');
        $password   = post_string('password', 1024);

        if ($identifier === '' || $password === null || $password === '') {
            $errors['form'] = 'Enter your username or email and your password.';
        } else {
            $result = attempt_login(db(), $identifier, $password);

            if ($result['status'] === 'ok') {
                sign_in_session($result['user_id']);
                redirect('dashboard.php');
            }

            if ($result['status'] === 'locked') {
                $minutes = (int)ceil((int)config('throttle.login_window') / 60);
                http_response_code(429);
                header('Retry-After: ' . (int)config('throttle.login_window'));
                $errors['form'] = "Too many failed attempts. Wait up to {$minutes} minutes, then try again.";
            } else {
                // One message for "no such account" and "wrong password".
                $errors['form'] = 'That username or email and password don’t match.';
            }
        }
    }
}

page_start('Sign in', ['identifier', 'password']);
?>
      <h1>Sign in</h1>
      <p class="lede">Welcome back. Your logbook is where you left it.</p>

<?php if ($notice !== ''): ?>
      <p class="notice notice-info" role="status"><?= e($notice) ?></p>
<?php endif; ?>
<?php if (isset($errors['form'])): ?>
      <p class="notice" role="alert"><?= e($errors['form']) ?></p>
<?php endif; ?>

      <form method="post" action="login.php" data-auth-form novalidate>
        <?= csrf_field() ?>

        <div class="field">
          <label for="identifier">Username or email</label>
          <input id="identifier" name="identifier" type="text" value="<?= e($identifier) ?>"
                 data-rule="identifier" data-flag="identifier" maxlength="254" required
                 autocomplete="username" autocapitalize="none" spellcheck="false"
                 aria-describedby="identifier-error">
          <?php field_error($errors, 'identifier'); ?>
        </div>

        <div class="field">
          <label for="password">Password</label>
          <div class="pw">
            <input id="password" name="password" type="password"
                   data-rule="current-password" data-flag="password" maxlength="1024" required
                   autocomplete="current-password" aria-describedby="password-error">
            <button class="pw-toggle" type="button" data-toggle="password" aria-pressed="false">Show</button>
          </div>
          <?php field_error($errors, 'password'); ?>
        </div>

        <button class="btn" type="submit" data-busy="Signing in…">Sign in</button>
      </form>

      <p class="switch">New to Halyard? <a href="register.php">Create an account</a></p>
<?php page_end(); ?>

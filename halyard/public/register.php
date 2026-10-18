<?php
declare(strict_types=1);

require __DIR__ . '/../src/bootstrap.php';

require_method(['GET', 'HEAD', 'POST']);

if (current_user_id() !== null) {
    redirect('dashboard.php');
}

$errors = [];
$values = ['username' => '', 'email' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_valid()) {
        http_response_code(403);
        $errors['form'] = 'This page expired. Reload it and try again.';
    } else {
        $pdo = db();
        $ip  = client_ip();

        if (register_is_locked($pdo, $ip)) {
            $minutes = (int)ceil((int)config('throttle.register_window') / 60);
            http_response_code(429);
            header('Retry-After: ' . (int)config('throttle.register_window'));
            $errors['form'] = "Too many sign-up attempts from this connection. Wait up to {$minutes} minutes, then try again.";
        } else {
            throttle_prune($pdo);
            throttle_record($pdo, 'register', $ip, hash('sha256', 'register'));

            [$errors, $clean] = validate_registration(
                post_string('username', 64),
                post_string('email', 320),
                post_string('password', 1024),
                post_string('password_confirm', 1024)
            );
            $values['username'] = $clean['username'];
            $values['email']    = $clean['email'];

            if ($errors === []) {
                $userId = create_user($pdo, $clean['username'], $clean['email'], $clean['password']);

                if ($userId === null) {
                    $errors['form'] = 'That username or email is already registered. Sign in instead, or pick different details.';
                } else {
                    sign_in_session($userId);
                    redirect('dashboard.php');
                }
            }
        }
    }
}

page_start('Create account', ['username', 'email', 'password', 'confirm']);
?>
      <h1>Create account</h1>
      <p class="lede">Four flags to hoist, then you’re aboard.</p>

<?php if (isset($errors['form'])): ?>
      <p class="notice" role="alert"><?= e($errors['form']) ?></p>
<?php endif; ?>

      <form method="post" action="register.php" data-auth-form novalidate>
        <?= csrf_field() ?>

        <div class="field">
          <label for="username">Username</label>
          <input id="username" name="username" type="text" value="<?= e($values['username']) ?>"
                 data-rule="username" data-flag="username" maxlength="24" required
                 autocomplete="username" autocapitalize="none" spellcheck="false"
                 aria-describedby="username-hint username-error">
          <p class="hint" id="username-hint">3 to 24 letters, numbers or underscores.</p>
          <?php field_error($errors, 'username'); ?>
        </div>

        <div class="field">
          <label for="email">Email</label>
          <input id="email" name="email" type="email" value="<?= e($values['email']) ?>"
                 data-rule="email" data-flag="email" maxlength="254" required
                 autocomplete="email" autocapitalize="none" spellcheck="false"
                 aria-describedby="email-error">
          <?php field_error($errors, 'email'); ?>
        </div>

        <div class="field">
          <label for="password">Password</label>
          <div class="pw">
            <input id="password" name="password" type="password"
                   data-rule="new-password" data-flag="password" maxlength="128" required
                   autocomplete="new-password" aria-describedby="password-hint password-error">
            <button class="pw-toggle" type="button" data-toggle="password" aria-pressed="false">Show</button>
          </div>
          <p class="hint" id="password-hint">At least 10 characters. A few unrelated words make a strong passphrase.</p>
          <?php field_error($errors, 'password'); ?>
        </div>

        <div class="field">
          <label for="password_confirm">Repeat password</label>
          <div class="pw">
            <input id="password_confirm" name="password_confirm" type="password"
                   data-rule="confirm" data-flag="confirm" maxlength="128" required
                   autocomplete="new-password" aria-describedby="confirm-error">
          </div>
          <?php field_error($errors, 'confirm'); ?>
        </div>

        <button class="btn" type="submit" data-busy="Creating account…">Create account</button>
      </form>

      <p class="switch">Already aboard? <a href="login.php">Sign in</a></p>
<?php page_end(); ?>

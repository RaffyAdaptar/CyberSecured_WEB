<?php
declare(strict_types=1);

require __DIR__ . '/../src/bootstrap.php';

require_method(['GET', 'HEAD']);

$user = require_login(db());
$idleMinutes = intdiv((int)config('session.idle_timeout'), 60);

page_start('Your logbook', ['username', 'email', 'password', 'confirm'], true);
?>
      <h1>Welcome aboard, <?= e($user['username']) ?>.</h1>
      <p class="lede">You’re signed in. This session ends after <?= $idleMinutes ?> minutes of inactivity.</p>

      <dl class="facts">
        <div><dt>Username</dt><dd><?= e($user['username']) ?></dd></div>
        <div><dt>Email</dt><dd><?= e($user['email']) ?></dd></div>
        <div><dt>Member since</dt><dd><?= e(format_time($user['created_at'])) ?></dd></div>
        <div><dt>Signed in</dt><dd><?= e(format_time($user['last_login_at'])) ?></dd></div>
      </dl>

      <form method="post" action="logout.php">
        <?= csrf_field() ?>
        <button class="btn btn-secondary" type="submit">Sign out</button>
      </form>
<?php page_end(); ?>

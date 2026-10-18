<?php
declare(strict_types=1);

/**
 * The signal flags. Each one belongs to a form field and unfurls when that field is valid.
 * Artwork is plain geometry, drawn with CSS classes (inline style attributes are blocked by the CSP).
 */
function flag_catalog(): array
{
    return [
        'username'   => ['label' => 'Username',  'art' => '<rect class="f-blue" width="160" height="100"/><circle class="f-yellow" cx="80" cy="50" r="27"/>'],
        'email'      => ['label' => 'Email',     'art' => '<rect class="f-red" width="160" height="50"/><rect class="f-white" y="50" width="160" height="50"/>'],
        'password'   => ['label' => 'Password',  'art' => '<rect class="f-yellow" width="160" height="100"/><rect class="f-blue" x="62" width="36" height="100"/><rect class="f-blue" y="32" width="160" height="36"/>'],
        'confirm'    => ['label' => 'Match',     'art' => '<rect class="f-red" width="160" height="100"/><polygon class="f-yellow" points="0,0 160,0 0,100"/>'],
        'identifier' => ['label' => 'Account',   'art' => '<rect class="f-blue" width="160" height="100"/><circle class="f-yellow" cx="80" cy="50" r="27"/>'],
    ];
}

/**
 * Open the page: <head>, the flag deck on the left, and the form panel on the right.
 *
 * @param string[] $flagNames  flags to show on the halyard, keyed to data-flag on inputs
 * @param bool     $hoisted    show every flag already unfurled (used once signed in)
 */
function page_start(string $title, array $flagNames, bool $hoisted = false): void
{
    $catalog = flag_catalog();
    ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <meta name="robots" content="noindex, nofollow">
  <title><?= e($title) ?> · Halyard</title>
  <link rel="icon" href="assets/favicon.svg" type="image/svg+xml">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600..800&amp;family=Instrument+Sans:wght@400..600&amp;display=swap">
  <link rel="stylesheet" href="assets/css/app.css">
  <script src="assets/js/app.js" defer></script>
</head>
<body>
<main class="shell">
  <aside class="deck">
    <p class="wordmark">Halyard</p>
    <p class="tagline">A private logbook for crews and skippers.</p>
    <ul class="mast" aria-hidden="true">
<?php foreach ($flagNames as $name): $flag = $catalog[$name]; ?>
      <li class="flag-item<?= $hoisted ? ' is-hoisted' : '' ?>" data-flag-for="<?= e($name) ?>">
        <svg class="flag" viewBox="0 0 160 100" focusable="false">
          <?= $flag['art'] ?>
          <rect class="f-outline" x="1.5" y="1.5" width="157" height="97"/>
        </svg>
        <span class="flag-label"><?= e($flag['label']) ?></span>
      </li>
<?php endforeach; ?>
    </ul>
  </aside>
  <section class="panel">
    <div class="panel-inner">
<?php
}

function page_end(): void
{
    ?>
    </div>
  </section>
</main>
</body>
</html>
<?php
}

/** Render the inline error line for a field (hidden until there is something to say). */
function field_error(array $errors, string $name): void
{
    $message = $errors[$name] ?? '';
    echo '<p class="field-error" id="', e($name), '-error" data-error-for="', e($name), '"',
        $message === '' ? ' hidden' : '', '>', e($message), '</p>';
}

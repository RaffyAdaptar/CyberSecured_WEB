<?php
declare(strict_types=1);

require __DIR__ . '/../src/bootstrap.php';

redirect(current_user_id() !== null ? 'dashboard.php' : 'login.php');

<?php
declare(strict_types=1);

require __DIR__ . '/../src/bootstrap.php';

// POST only, with a CSRF token: a stray link or image tag on another site
// cannot sign someone out.
require_method(['POST']);

if (!csrf_valid()) {
    http_response_code(403);
    exit('This page expired. Go back, reload it and try again.');
}

destroy_session();
redirect('login.php?signed_out=1');

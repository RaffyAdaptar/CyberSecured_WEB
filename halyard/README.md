# Halyard: secure sign-up and sign-in (PHP, MySQL, HTML, CSS, JS)

A logbook app's account system. Each form field you complete unfurls a maritime signal flag on the halyard (the rope on the left); the flags are the memorable part of the design.

## Run it

1. **Create the database** (MySQL 5.7+ or MariaDB 10.3+):
   ```
   mysql -u root -p < database/schema.sql
   ```
2. **Create a limited database user.** Open `database/schema.sql`, change the password in the commented block at the bottom, uncomment it and run it. Do not run the app as `root`.
3. **Add your credentials.** Copy `src/config.local.sample.php` to `src/config.local.php` and fill in the user and password. This file is git-ignored.
4. **Start the server** from this folder:
   ```
   php -S localhost:8000 -t public
   ```
   Then open http://localhost:8000. On XAMPP or Apache, point the document root at the `public/` folder (not the project root), so `src/` is never reachable from the web.

Requires PHP 8.1 or newer with `pdo_mysql`.

## Files

| Path | Purpose |
| --- | --- |
| `public/` | The only folder the web server serves: `login.php`, `register.php`, `dashboard.php`, `logout.php`, `assets/` |
| `src/` | Application code, config and security helpers (outside the web root) |
| `database/schema.sql` | Tables and the least-privilege account |
| `tests/smoke.sh` | End-to-end security test (`bash tests/smoke.sh`, no MySQL needed) |

## What protects it

| Threat | Defense |
| --- | --- |
| SQL injection | Every query uses PDO prepared statements with bound parameters and real server-side preparation (`ATTR_EMULATE_PREPARES = false`). Stacked queries are disabled. The app's database user can only read and write the two tables it needs. |
| Stolen database | Passwords are stored as Argon2id hashes (bcrypt fallback), never in plain text. Hashes upgrade automatically when settings get stronger. |
| Cross-site request forgery | Per-session CSRF token on every POST, checked with `hash_equals`, plus an `Origin` header check. Sign out is POST-only. |
| Cross-site scripting | All output goes through `htmlspecialchars`. A strict Content Security Policy blocks inline scripts and styles, so there are none. |
| Session hijacking and fixation | `HttpOnly`, `SameSite=Lax` and (on HTTPS) `Secure` cookies with the `__Host-` prefix. Strict mode rejects session IDs the server did not issue. The ID is regenerated on sign-in and every 15 minutes. Sessions end after 30 minutes idle or 8 hours total. |
| Password guessing | Failed sign-ins are limited to 5 per account and IP, and 20 per IP, in 15 minutes. Sign-ups are limited per IP. The same error is shown for a wrong password and an unknown account, and both paths cost the same time. |
| Bad input | Strict server-side validation (the JavaScript checks are only a convenience). Array-typed, oversized, non-UTF-8 and NUL-byte inputs are rejected. |
| Clickjacking and sniffing | `frame-ancestors 'none'`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Cache-Control: no-store`, and HSTS over HTTPS. |
| Information leaks | PHP errors are logged, never shown. Uncaught problems show a plain message. |

## Before you put it on the internet

- Serve it over **HTTPS** only. Cookies and HSTS switch to their strict forms automatically.
- Keep `debug` off (it is off by default).
- If you run behind a reverse proxy you control, set `'trust_proxy' => true` in `config.local.php`, otherwise the rate limiter sees the proxy's IP for everyone.
- Sign-up tells people when a username or email is already taken. That is normal for sign-up forms, but it does reveal that an account exists. Sign-in itself never does.
- Not included: email verification, password reset and two-factor sign-in. Add them before storing anything sensitive.

## Make it yours

The name and copy live in `src/view.php`, `public/*.php` and the colors at the top of `public/assets/css/app.css`. Fonts (Bricolage Grotesque and Instrument Sans) load from Google Fonts; offline, the page falls back to system fonts.

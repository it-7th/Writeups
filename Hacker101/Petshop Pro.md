# Petshop Pro (Hacker101 CTF)

Platform: Hacker101 CTF
Difficulty: Easy
Category: Web
Flags: 3/3

## Overview

Petshop Pro is a small e-commerce-style app with a shopping cart, a checkout flow, and an admin login that unlocks an editing panel for product pages. The intended path involves three separate bugs: a business logic flaw where the cart trusts client supplied pricing data, a weak authentication setup on the admin login that leaks whether a username is valid and has no rate limiting, and a stored cross site scripting bug in the product edit form that a naive page render does not sanitize.

For this writeup, the target hostname is replaced with `TARGET` throughout, since the Hacker101 CTF spins up a fresh subdomain and fresh credentials on every instance.

## Recon

The home page shows a small catalog of products, one of them a kitten photograph priced at $8.95, with an add to cart flow and a checkout step. There is also an admin login page at `/login`, separate from the shop itself.

```
GET https://TARGET/
GET https://TARGET/login
GET https://TARGET/cart
```

Watching the checkout request in Burp shows the cart contents are carried in two places at once. The session cookie stores a `cart` key, and the checkout POST body also sends a `cart` parameter directly.

```
POST /checkout
Cookie: session=eyJjYXJ0IjpbXX0.xxxx.xxxx

cart=[]
```

Decoding the first segment of the session cookie confirms what it is holding.

```bash
echo 'eyJjYXJ0IjpbXX0' | base64 -d
```

```json
{"cart": []}
```

That structure is a strong signal this is a Flask session, which is signed but not encrypted. The more interesting detail though is that the checkout body also sends the cart as a separate, directly editable parameter.

## Flag 1: Cart price manipulation

Adding the kitten photo to the cart in the browser and capturing the checkout request in Burp showed the full shape of the cart object.

```
cart=[[1, {"name": "Kitten", "desc": "8\"x10\" color glossy photograph of a kitten.", "logo": "kitten.jpg", "price": 8.95}]]
```

The price is sitting right there in a value the client fully controls. The server is trusting whatever price comes back in this parameter rather than looking the real price up server side from the item id. Editing the price down to zero and resending the checkout request in Repeater triggered the flag directly.

```
cart=[[1, {"name": "Kitten", "desc": "8\"x10\" color glossy photograph of a kitten.", "logo": "kitten.jpg", "price": 0}]]
```

The response on checkout returned the first flag.

This is a classic business logic flaw rather than an injection or memory corruption style bug. The fix on the server side would be to never trust a price coming from the client at all, and instead always look the price up from the item id against the product database at checkout time, recalculating the total server side regardless of what the submitted cart claims.

## Flag 2: Admin login, username enumeration and weak credentials

The admin login at `/login` posts a username and password and renders an inline error on failure.

```
POST /login
username=admin&password=test

HTTP/2 200 OK
<b style="color: red">Invalid username</b>
```

The important detail is the exact wording. The page says `Invalid username`, not a generic message like `Invalid username or password`. That is a username enumeration flaw, because it means the server is telling you outright whether the account exists at all, separately from whether the password was right. A properly built login returns the identical message either way so an attacker cannot tell real accounts from fake ones.

The plan was to split the problem into two separate smaller problems instead of guessing both username and password together. First find a real username by watching for the moment the error message changes away from `Invalid username`, then once a real account is known, brute force only its password.

A first attempt using a short list of common admin style usernames came back clean with no hits, meaning none of those common names existed as real accounts.

```bash
hydra -f -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -p admin \
  TARGET \
  https-post-form "/login:username=^USER^&password=^PASS^:Invalid username" \
  -t 4
```

Before trusting that result, it is worth confirming hydra's logic actually works by testing one known bad login by hand and checking it is reported as a failure, since a bad match string makes hydra treat every attempt as a success.

```bash
hydra -l zzznouser -p zzznopass \
  TARGET \
  https-post-form "/login:username=^USER^&password=^PASS^:Invalid username" -V
```

With the oracle confirmed sound, the search moved to a much larger list of common first names, since the account on this box turned out to be a personal name rather than a generic admin style username.

```bash
hydra -f -L /usr/share/seclists/Usernames/Names/names.txt -p admin \
  TARGET \
  https-post-form "/login:username=^USER^&password=^PASS^:Invalid username" \
  -t 4
```

This returned a hit, since hydra stops as soon as one submitted username does not match the `Invalid username` failure string.

```
[443][http-post-form] host: TARGET   login: alaine   password: admin
```

The username `alaine` is real. From here the password field for that same login changes its wording once the username itself is valid, moving to `Invalid password` instead. Confirming that by hand in Burp first matters, because the match string used for the password brute force has to reflect whatever the page actually says, not an assumption.

```
POST /login
username=alaine&password=wrongguess

HTTP/2 200 OK
<b style="color: red">Invalid password</b>
```

With the username fixed and the correct failure string in hand, the next step was a password list. Rather than reaching straight for rockyou, which at this server's slow response rate would have taken days to finish, a much shorter list of common passwords was tried first.

```bash
hydra -f -l alaine -P /usr/share/seclists/Passwords/Common-Credentials/Pwdb_top-1000.txt \
  TARGET \
  https-post-form "/login:username=^USER^&password=^PASS^:Invalid password" \
  -t 4
```

That came back with no hit after running through all one thousand entries. Since the username itself turned out to be a first name pulled from a common names list, the next guess was that the password generator for this box might follow the same pattern and also be a first name. Reusing the exact same names list that found the username, but this time pointed at the password field, was the next move.

```bash
hydra -f -l alaine -P /usr/share/seclists/Usernames/Names/names.txt \
  TARGET \
  https-post-form "/login:username=^USER^&password=^PASS^:Invalid password" \
  -t 4
```

That guess paid off.

```
[443][http-post-form] host: TARGET   login: alaine   password: penelope
```

Logging in normally at `/login` with `alaine` and `penelope`, no automation involved, confirmed the credentials work and returned the second flag.

A smaller but useful technique worth noting for future logins is hydra's `-e` flag, which tests whether the password is simply the same as the username, blank, or the username reversed, all in a handful of requests before committing to a full wordlist run.

```bash
hydra -f -l alaine -p x -e snr \
  TARGET \
  https-post-form "/login:username=^USER^&password=^PASS^:Invalid password" -t 4
```

This particular box did not need it since the names list approach already worked, but it is a cheap first move worth trying on any login before reaching for rockyou.

## Flag 3: Stored XSS in the product edit form

Logging in with the recovered `alaine` and `penelope` credentials unlocks an edit option on the product listing, with a form containing a name field and a description field for each item.

Submitting a script tag as a quick test is usually the first thing to try, but many naive filters specifically strip or scrub the literal word script, so a cleaner bypass is to avoid that word entirely and use an image tag with a broken source and an inline error handler instead.

```
name: <img src=x onerror=alert(1)>
desc: <img src=x onerror=alert(1)>
```

Saving the edit and returning to the main product listing page triggered the payload immediately. Since `src=x` is not a valid image path, the browser fires the `onerror` handler the moment it tries and fails to load the broken image, running the injected JavaScript with no user interaction needed beyond simply visiting the page. The alert fired and the third flag appeared.

This is stored cross site scripting rather than reflected, which matters for how serious the finding is. The payload is saved into the product record itself, so it executes for every single visitor who loads the main page afterward, not only for someone who clicks a specially crafted link. The underlying failure is on both ends at once. Input was accepted with no server side sanitization, and output was rendered back into the page with no encoding either. The correct fix is primarily on the output side, since any field that gets written back into HTML needs to be context aware encoded at render time, turning characters like `<`, `>`, `"`, and `'` into their safe HTML entity equivalents regardless of what was allowed in on the way in. Input validation is still worth having as a second layer of defense, but relying on it alone, especially a naive keyword filter that only blocks the literal word script, is not sufficient on its own.

## Credentials and flags found

* Admin credentials: `alaine` / `penelope`
* Flag 1: Cart price manipulation, client supplied price trusted at checkout
* Flag 2: Admin login compromised through username enumeration plus a weak, wordlist findable password
* Flag 3: Stored XSS in the product name and description fields, bypassing a naive script keyword filter

## Techniques used

* Business logic flaw, client controlled pricing data trusted server side
* Username enumeration through a distinct error message
* Credential brute forcing with hydra, staged from a small common list up to a themed names list
* Stored cross site scripting, filter bypass using an event handler instead of a script tag

## Lessons learned

The single biggest time cost on this box was not technical difficulty, it was list size. Jumping straight to rockyou against a slow remote server is a serious mistake, since even a modest fourteen million line password list at under one hundred attempts per minute works out to multiple days of runtime. Starting small with a one thousand entry common password list and only stepping up in size if that misses saves an enormous amount of wasted time, and it is worth doing the arithmetic on tries per minute against list size before launching any brute force run rather than after.

Before trusting any hydra output, it is worth sending one deliberately wrong login by hand and confirming hydra correctly reports it as a failure. A wrong failure string makes hydra treat every single attempt as a valid login, which produces a wall of convincing looking but completely false positive results. This happened early in this engagement from an incorrect endpoint path, and the fix was confirming the real response text directly in Burp rather than guessing at it.

The username here turned out to be a first name rather than a generic account name like admin or root, which is why common username wordlists missed it entirely. Once that pattern was visible, reusing the exact same names wordlist for the password field, on the theory that the account generator for this box might repeat the same naming convention, turned out to be the fastest route to the final credential, faster than any generic password list.

Hydra's target field only accepts a bare hostname, with the scheme, module, and path kept as entirely separate arguments. Pasting a full URL including `https://` directly into the host position produces an immediate invalid target definition error, and this specific mistake happened more than once over the course of this engagement before it stuck.

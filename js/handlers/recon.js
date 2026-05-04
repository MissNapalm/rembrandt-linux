'use strict';

HANDLERS.push(
  // ── Network ───────────────────────────────────────────────────────────────
  {
    match: c => c === 'ip a' || c === 'ip addr' || c === 'ifconfig',
    lines: [
      { t: 'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500' },
      { t: '        inet 10.10.10.5  netmask 255.255.255.0  broadcast 10.10.10.255' },
      { t: '        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>' },
      { t: '        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)' },
      { t: '        RX packets 4821  bytes 892145 (871.2 KiB)' },
      { t: '        TX packets 3012  bytes 441092 (430.7 KiB)' },
      { t: '' },
      { t: 'lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536' },
      { t: '        inet 127.0.0.1  netmask 255.0.0.0' },
    ],
  },
  {
    match: c => /^ping(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const target = cmd.split(' ').filter(Boolean).pop();
      return { pingMode: true, target };
    }}],
  },

  // ── nmap self (localhost / 127.0.0.1 / 10.10.10.5) ───────────────────────────
  {
    id: 'nmap-self',
    match: c => /^nmap\b/.test(c) && /(localhost|127\.0\.0\.1|10\.10\.10\.5)/.test(c) && !c.includes('10.10.10.10'),
    lines: [
      { t: () => 'Starting Nmap 7.94 ( https://nmap.org ) at ' + new Date().toUTCString().slice(0,16) },
      { t: () => `Nmap scan report for rembrandt (10.10.10.5)` },
      { t: 'Host is up (0.000082s latency).' },
      { t: 'Not shown: 65533 closed tcp ports (reset)' },
      { t: 'PORT     STATE SERVICE  VERSION' },
      { t: '22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)', cls: 'g' },
      { t: '80/tcp   open  http     Apache httpd 2.4.57 ((Debian))', cls: 'g' },
      { t: '631/tcp  open  ipp      CUPS 2.4', cls: 'g' },
      { t: '' },
      { t: 'Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel' },
      { t: '' },
      { t: () => 'Nmap done: 1 IP address (1 host up) scanned in ' + (3.8 + Math.random()).toFixed(2) + ' seconds', cls: 'g' },
    ],
  },
  {
    id: 'nmap-discovery',
    loadTime: () => jitter(2600, 500),
    progressFn: (elapsed, total) => {
      const pct = Math.min(99.9, elapsed / total * 100).toFixed(2);
      const elSec = Math.floor(elapsed / 1000);
      const elM = Math.floor(elSec / 60), elS = elSec % 60;
      const remMs = Math.max(0, total - elapsed);
      const remSec = Math.floor(remMs / 1000);
      const remM = Math.floor(remSec / 60), remS2 = remSec % 60;
      const etc = new Date(Date.now() + remMs);
      const etcStr = `${String(etc.getHours()).padStart(2,'0')}:${String(etc.getMinutes()).padStart(2,'0')}`;
      return [
        { t: `Stats: 0:${String(elM).padStart(2,'0')}:${String(elS).padStart(2,'0')} elapsed; 0 hosts completed (0 up), 256 undergoing Ping Scan`, cls: 'd' },
        { t: `Ping Scan Timing: About ${pct}% done; ETC: ${etcStr} (0:${String(remM).padStart(2,'0')}:${String(remS2).padStart(2,'0')} remaining)`, cls: 'd' },
      ];
    },
    progressOnEnter: true,
    match: c => /^nmap\b/.test(c) && (c.includes('/24') || c.includes('-sn')),
    lines: [
      { t: 'Starting Nmap 7.94 ( https://nmap.org ) at ' + new Date().toUTCString().slice(0,16) },
      { t: 'Nmap scan report for 10.10.10.1', cls: 'b' },
      { t: 'Host is up (0.00080s latency).' },
      { t: '' },
      { t: 'Nmap scan report for 10.10.10.5', cls: 'b' },
      { t: 'Host is up (0.000082s latency).' },
      { t: '' },
      { t: 'Nmap scan report for LEGACY (10.10.10.50)', cls: 'b' },
      { t: 'Host is up (0.0021s latency).' },
      { t: '' },
      { t: 'Nmap scan report for DC01.CORP.LOCAL (10.10.10.10)', cls: 'b' },
      { t: 'Host is up (0.0015s latency).' },
      { t: '' },
      { t: 'Nmap done: 256 IP addresses (4 hosts up) scanned in 2.41 seconds', cls: 'g' },
    ],
  },
    // ── nmap LEGACY (10.10.10.50) ───────────────────────────────────────────────────────────────────────────
  {
    id: 'nmap-legacy',
    loadTime: () => jitter(18000, 3000),
    progressOnEnter: true,
    progressFn: (elapsed, total) => {
      const pct = Math.min(99.99, elapsed / total * 100).toFixed(2);
      const elSec = Math.floor(elapsed / 1000);
      const elM = Math.floor(elSec / 60), elS = elSec % 60;
      const remMs = Math.max(0, total - elapsed);
      const remSec = Math.floor(remMs / 1000);
      const remM = Math.floor(remSec / 60), remS2 = remSec % 60;
      const etc = new Date(Date.now() + remMs);
      const etcStr = `${String(etc.getHours()).padStart(2,'0')}:${String(etc.getMinutes()).padStart(2,'0')}`;
      return [
        { t: `Stats: 0:${String(elM).padStart(2,'0')}:${String(elS).padStart(2,'0')} elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan`, cls: 'd' },
        { t: `SYN Stealth Scan Timing: About ${pct}% done; ETC: ${etcStr} (0:${String(remM).padStart(2,'0')}:${String(remS2).padStart(2,'0')} remaining)`, cls: 'd' },
      ];
    },
    match: c => /^nmap\b/.test(c) && c.includes('10.10.10.50'),
    lines: [
      { t: () => 'Starting Nmap 7.94 ( https://nmap.org ) at ' + new Date().toUTCString().slice(0,16) },
      { t: 'Nmap scan report for LEGACY (10.10.10.50)' },
      { t: 'Host is up (0.0021s latency).' },
      { t: 'Not shown: 65532 closed tcp ports (reset)' },
      { t: 'PORT      STATE SERVICE      VERSION' },
      { t: '135/tcp   open  msrpc        Microsoft Windows RPC', cls: 'g' },
      { t: '139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn', cls: 'g' },
      { t: '445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)', cls: 'r' },
      { t: '' },
      { t: 'Host script results:' },
      { t: '|_clock-skew: mean: 1h20m00s, deviation: 2h18m34s, median: 0s' },
      { t: '| smb-os-discovery:' },
      { t: '|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)', cls: 'r' },
      { t: '|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional' },
      { t: '|   Computer name: LEGACY' },
      { t: '|   NetBIOS computer name: LEGACY\\x00' },
      { t: '|   Workgroup: WORKGROUP\\x00' },
      { t: '| smb-security-mode:' },
      { t: '|   account_used: guest' },
      { t: '|   authentication_level: user' },
      { t: '|   challenge_response: supported' },
      { t: '|_  message_signing: disabled (dangerous, but default)', cls: 'r' },
      { t: '|_smb2-time: Protocol negotiation failed (SMB2)' },
      { t: '' },
      { t: 'Service Info: Host: LEGACY; OS: Windows; CPE: cpe:/o:microsoft:windows' },
      { t: '' },
      { t: () => 'Nmap done: 1 IP address (1 host up) scanned in ' + (17.2 + Math.random()).toFixed(2) + ' seconds', cls: 'g' },
    ],
  },
  {
    id: 'nmap-full',
    loadTime: () => jitter(28000, 5000),
    progressOnEnter: true,
    progressFn: (elapsed, total) => {
      const elSec  = Math.floor(elapsed / 1000);
      const elMin  = Math.floor(elSec / 60);
      const elRemS = elSec % 60;
      const pct    = Math.min(99.99, elapsed / total * 100).toFixed(2);
      const remMs  = Math.max(0, total - elapsed);
      const remSec = Math.floor(remMs / 1000);
      const remMin = Math.floor(remSec / 60);
      const remRemS = remSec % 60;
      const etc   = new Date(Date.now() + remMs);
      const etcStr = `${String(etc.getHours()).padStart(2,'0')}:${String(etc.getMinutes()).padStart(2,'0')}`;
      return [
        { t: `Stats: 0:${String(elMin).padStart(2,'0')}:${String(elRemS).padStart(2,'0')} elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan`, cls: 'd' },
        { t: `SYN Stealth Scan Timing: About ${pct}% done; ETC: ${etcStr} (0:${String(remMin).padStart(2,'0')}:${String(remRemS).padStart(2,'0')} remaining)`, cls: 'd' },
      ];
    },
    match: c => /^nmap\b/.test(c) && c.includes('10.10.10.10'),
    lines: [
      { t: 'Starting Nmap 7.94 ( https://nmap.org ) at ' + new Date().toUTCString().slice(0,16) },
      { t: 'Nmap scan report for DC01.CORP.LOCAL (10.10.10.10)' },
      { t: 'Host is up (0.0015s latency).' },
      { t: 'Not shown: 65514 filtered tcp ports (no-response)' },
      { t: 'PORT      STATE SERVICE       VERSION' },
      { t: '53/tcp    open  domain        Simple DNS Plus', cls: 'g' },
      { t: '80/tcp    open  http          Microsoft IIS httpd 10.0', cls: 'g' },
      { t: '88/tcp    open  kerberos-sec  Microsoft Windows Kerberos', cls: 'g' },
      { t: '135/tcp   open  msrpc         Microsoft Windows RPC', cls: 'g' },
      { t: '139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn', cls: 'g' },
      { t: '389/tcp   open  ldap          Microsoft Windows Active Directory LDAP', cls: 'g' },
      { t: '445/tcp   open  microsoft-ds?', cls: 'g' },
      { t: '464/tcp   open  kpasswd5?', cls: 'g' },
      { t: '593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0', cls: 'g' },
      { t: '636/tcp   open  ldapssl?', cls: 'g' },
      { t: '3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP', cls: 'g' },
      { t: '5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)', cls: 'g' },
      { t: '' },
      { t: 'Host script results:' },
      { t: '| smb2-security-mode:' },
      { t: '|   3:1:1:' },
      { t: '|_    Message signing enabled and required' },
      { t: '| smb2-time:' },
      { t: '|   date: 2024-01-15T14:11:47' },
      { t: '' },
      { t: 'Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows' },
      { t: '' },
      { t: 'Nmap done: 1 IP address (1 host up) scanned in 28.41 seconds', cls: 'g' },
    ],
  },

  // ── enum4linux ────────────────────────────────────────────────────────────
  {
    id: 'enum4linux',
    match: c => /^enum4linux\b/.test(c) && c.includes('10.10.10.10'),
    stepLines: [
      { t: 'Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ )', cls: 'b', delay: 0 },
      { t: '', delay: 200 },
      { t: ' ========================== Target Information ==========================', delay: jitter(400, 100) },
      { t: ' Target ........... 10.10.10.10', delay: jitter(80, 20) },
      { t: ' RID Range ........ 500-550,1000-', delay: jitter(60, 15) },
      { t: ' Username ......... \'\'', delay: jitter(60, 15) },
      { t: '', delay: jitter(800, 200) },
      { t: ' ======================== Workgroup/Domain =========================', delay: jitter(600, 150) },
      { t: '[+] Got domain/workgroup name: CORP', cls: 'g', delay: jitter(900, 200) },
      { t: '', delay: jitter(700, 200) },
      { t: ' ======================== OS information =========================', delay: jitter(500, 150) },
      { t: '[+] Got OS info for 10.10.10.10 from smbclient: Domain=[CORP] OS=[Windows Server 2019 Standard 17763] Server=[Windows Server 2019 Standard 6.3]', cls: 'g', delay: jitter(1100, 300) },
      { t: '', delay: jitter(600, 150) },
      { t: ' ======================== Users =========================', delay: jitter(500, 100) },
      { t: '[+] Got userlist with 7 members', cls: 'g', delay: jitter(1200, 300) },
      { t: 'index: 0x1 RID: 0x1f4 acb: 0x00000010 Account: Administrator  Name: Administrator', cls: 'g', delay: jitter(120, 30) },
      { t: 'index: 0x2 RID: 0x1f5 acb: 0x00000215 Account: Guest          Name: Guest', cls: 'd', delay: jitter(80, 20) },
      { t: 'index: 0x3 RID: 0x1f6 acb: 0x00000011 Account: krbtgt         Name: krbtgt', cls: 'd', delay: jitter(80, 20) },
      { t: 'index: 0x4 RID: 0x44f acb: 0x00000210 Account: john.doe       Name: John Doe', cls: 'g', delay: jitter(80, 20) },
      { t: 'index: 0x5 RID: 0x450 acb: 0x00000210 Account: svc_backup     Name: Backup Service', cls: 'g', delay: jitter(80, 20) },
      { t: 'index: 0x6 RID: 0x451 acb: 0x00000210 Account: svc_sql        Name: SQL Service', cls: 'g', delay: jitter(80, 20) },
      { t: 'index: 0x7 RID: 0x452 acb: 0x00000210 Account: svc_web        Name: Web Service', cls: 'g', delay: jitter(80, 20) },
      { t: '', delay: jitter(500, 100) },
      { t: ' ======================== Share Enumeration =========================', delay: jitter(400, 100) },
      { t: '\tSharename       Type      Comment', delay: jitter(900, 200) },
      { t: '\t---------       ----      -------', delay: jitter(60, 15) },
      { t: '\tSYSVOL          Disk      Logon server share', cls: 'b', delay: jitter(200, 50) },
      { t: '\tNETLOGON        Disk      Logon server share', cls: 'b', delay: jitter(150, 40) },
      { t: '\tIPC$            IPC       Remote IPC', cls: 'd', delay: jitter(150, 40) },
      { t: '', delay: jitter(600, 150) },
      { t: ' ======================== Password Policy Information =========================', delay: jitter(500, 100) },
      { t: '[+] Minimum password length: 7', cls: 'g', delay: jitter(800, 200) },
      { t: '[+] Password history length: 24', cls: 'g', delay: jitter(100, 30) },
      { t: '[+] Maximum password age: 41 days', cls: 'g', delay: jitter(100, 30) },
      { t: '[+] Account lockout threshold: 5', cls: 'g', delay: jitter(100, 30) },
      { t: '', delay: jitter(400, 100) },
      { t: () => 'enum4linux complete on ' + new Date().toUTCString().slice(0, 16), cls: 'g', delay: jitter(300, 80) },
    ],
    lines: [],
  },

  // ── CrackMapExec — john.doe ───────────────────────────────────────────────
  {
    id: 'cme-johndoe',
    match: c => /^crackmapexec\b/.test(c) && c.includes('john.doe') && (c.includes('Password1') || c.includes("'Password1!'")),
    stepLines: [
      { t: 'SMB         10.10.10.10     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL) (signing:True) (SMBv1:False)', delay: jitter(600, 150) },
      { t: 'SMB         10.10.10.10     445    DC01             [+] CORP.LOCAL\\john.doe:Password1!', cls: 'g', delay: jitter(800, 200) },
    ],
    lines: [],
  },

  // ── CrackMapExec — svc_backup ─────────────────────────────────────────────
  {
    id: 'cme-svcbackup',
    match: c => /^crackmapexec\b/.test(c) && c.includes('svc_backup') && c.includes('Backup2023'),
    stepLines: [
      { t: 'SMB         10.10.10.10     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL) (signing:True) (SMBv1:False)', delay: jitter(600, 150) },
      { t: 'SMB         10.10.10.10     445    DC01             [+] CORP.LOCAL\\svc_backup:Backup2023! (Backup Operators)', cls: 'g', delay: jitter(800, 200) },
    ],
    lines: [],
  },

  // ── CrackMapExec — Pass-the-Hash ─────────────────────────────────────────
  {
    id: 'cme-pth',
    match: c => /^crackmapexec\b/.test(c) && c.includes('Administrator') && c.includes('-H') && c.includes('fc525c'),
    stepLines: [
      { t: 'SMB         10.10.10.10     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL) (signing:True) (SMBv1:False)', delay: jitter(600, 150) },
      { t: 'SMB         10.10.10.10     445    DC01             [+] CORP.LOCAL\\Administrator:fc525c9683e8fe067095ba2ddc971889 (Pwn3d!)', cls: 'g', delay: jitter(800, 200) },
    ],
    lines: [],
  },

  // ── CrackMapExec — bad creds ─────────────────────────────────────────────
  {
    match: c => /^crackmapexec\b/.test(c),
    lines: [
      { t: (c) => 'SMB         10.10.10.10     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL) (signing:True) (SMBv1:False)' },
      { t: (c) => 'SMB         10.10.10.10     445    DC01             [-] Authentication failed', cls: 'r' },
    ],
  },

  // ── GetUserSPNs — enumerate (no -request) ────────────────────────────────
  {
    id: 'spns-enum',
    match: c => /impacket-GetUserSPNs|GetUserSPNs/.test(c) && c.includes('10.10.10.10') && !c.includes('-request'),
    stepLines: [
      { t: 'Impacket v0.11.0 - Copyright 2023 Fortra', delay: 0 },
      { t: '', delay: jitter(800, 200) },
      { t: 'ServicePrincipalName          Name        MemberOf  PasswordLastSet              LastLogon', delay: jitter(1200, 300) },
      { t: '----------------------------  ----------  --------  ---------------------------  ---------------------------', delay: jitter(80, 20) },
      { t: 'backup/dc01.corp.local        svc_backup            2024-01-10 09:15:43.000000   2024-01-14 18:32:17.000000', cls: 'g', delay: jitter(300, 80) },
      { t: 'MSSQLSvc/dc01.corp.local:1433 svc_sql               2024-01-08 11:22:01.000000   2024-01-13 09:45:22.000000', cls: 'g', delay: jitter(200, 60) },
      { t: 'HTTP/web.corp.local           svc_web               2024-01-05 14:30:15.000000   2024-01-12 16:20:08.000000', cls: 'g', delay: jitter(200, 60) },
    ],
    lines: [],
  },

  // ── GetUserSPNs — request TGS tickets ────────────────────────────────────
  {
    id: 'spns-request',
    match: c => /impacket-GetUserSPNs|GetUserSPNs/.test(c) && c.includes('10.10.10.10') && c.includes('-request'),
    stepLines: [
      { t: 'Impacket v0.11.0 - Copyright 2023 Fortra', delay: 0 },
      { t: '', delay: jitter(800, 200) },
      { t: 'ServicePrincipalName          Name        MemberOf  PasswordLastSet              LastLogon', delay: jitter(1200, 300) },
      { t: '----------------------------  ----------  --------  ---------------------------  ---------------------------', delay: jitter(80, 20) },
      { t: 'backup/dc01.corp.local        svc_backup            2024-01-10 09:15:43.000000   2024-01-14 18:32:17.000000', cls: 'g', delay: jitter(300, 80) },
      { t: 'MSSQLSvc/dc01.corp.local:1433 svc_sql               2024-01-08 11:22:01.000000   2024-01-13 09:45:22.000000', cls: 'g', delay: jitter(200, 60) },
      { t: 'HTTP/web.corp.local           svc_web               2024-01-05 14:30:15.000000   2024-01-12 16:20:08.000000', cls: 'g', delay: jitter(200, 60) },
      { t: '', delay: jitter(600, 150) },
      { t: '$krb5tgs$23$*svc_backup$CORP.LOCAL$backup/dc01.corp.local*$8a3f2b1c...', cls: 'y', delay: jitter(500, 120) },
      { t: '$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/dc01.corp.local:1433*$9b4c3d2e...', cls: 'y', delay: jitter(400, 100) },
      { t: '$krb5tgs$23$*svc_web$CORP.LOCAL$HTTP/web.corp.local*$7c5d4e3f...', cls: 'y', delay: jitter(400, 100) },
      { t: '', delay: jitter(300, 80) },
      { t: (c) => c.includes('-outputfile') ? '[*] Saving 3 tickets to hashes.kerberoast' : '', cls: 'b', delay: jitter(200, 50) },
    ],
    lines: [],
    after: (c) => { if (c.includes('-outputfile') || c.includes('hashes.kerberoast')) SIM.hashesOnDisk = true; },
  },

  // ── john — crack ──────────────────────────────────────────────────────────
  {
    id: 'john-crack',
    loadTime: () => jitter(6500, 1500),
    match: c => /^john\b/.test(c) && c.includes('hashes') && !c.includes('--show'),
    progressFn: (elapsed, total) => {
      const pct = Math.min(99, elapsed / total * 100);
      const rate = (1200 + Math.random() * 800).toFixed(0);
      const tried = Math.floor(pct * 140000 / 100).toLocaleString();
      return [
        { t: `${(pct).toFixed(2)}g 0:00:00:${String(Math.floor(elapsed/1000)).padStart(2,'0')} ${pct < 99 ? (pct/10).toFixed(4)+'g/s' : 'DONE'} ${rate}p/s ${(parseInt(rate)*3).toLocaleString()}c/s`, cls: 'd' },
      ];
    },
    lines: [
      { t: 'Using default input encoding: UTF-8' },
      { t: 'Loaded 3 password hashes with 3 different salts (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])' },
      { t: 'Will run 4 OpenMP threads' },
      { t: "Press 'q' or Ctrl-C to abort, almost any other key for status" },
      { t: '' },
      { t: 'Backup2023!      (svc_backup)', cls: 'g' },
      { t: 'SqlServer1!      (svc_sql)', cls: 'g' },
      { t: 'Welcome123       (svc_web)', cls: 'g' },
      { t: '' },
      { t: '3g 0:00:00:23 DONE (2024-01-15 14:18) 0.1298g/s 1865p/s 5595c/s', cls: 'd' },
      { t: 'Use the "--show" option to display all of the cracked passwords reliably', cls: 'd' },
      { t: 'Session completed.', cls: 'g' },
    ],
  },

  // ── john --show ───────────────────────────────────────────────────────────
  {
    match: c => /^john\b/.test(c) && c.includes('--show'),
    loadTime: () => jitter(400, 100),
    lines: [
      { t: 'svc_backup:Backup2023!:CORP.LOCAL:backup/dc01.corp.local:$krb5tgs$23$*svc_backup$...', cls: 'g' },
      { t: 'svc_sql:SqlServer1!:CORP.LOCAL:MSSQLSvc/dc01.corp.local:1433:$krb5tgs$23$*svc_sql$...', cls: 'g' },
      { t: 'svc_web:Welcome123:CORP.LOCAL:HTTP/web.corp.local:$krb5tgs$23$*svc_web$...', cls: 'g' },
      { t: '' },
      { t: '3 password hashes cracked, 0 left' },
    ],
  },

  // ── hashcat ───────────────────────────────────────────────────────────────
  {
    id: 'hashcat',
    loadTime: () => jitter(5500, 1200),
    match: c => /^hashcat\b/.test(c) && c.includes('13100'),
    lines: [
      { t: 'hashcat (v6.2.6) starting...' },
      { t: '' },
      { t: 'OpenCL API (OpenCL 3.0 LINUX) - Platform #1 [Intel(R) Corporation]' },
      { t: '* Device #1: AMD Radeon RX 6800 XT, 16256/16368 MB (4092 MB allocatable), 36MCU' },
      { t: '' },
      { t: 'Minimum password length supported by kernel: 0', cls: 'd' },
      { t: 'Maximum password length supported by kernel: 256', cls: 'd' },
      { t: '' },
      { t: 'Hashes: 3 digests; 3 unique digests, 3 unique salts' },
      { t: 'Bitmaps: 16 bits, 65536 entries' },
      { t: 'Applicable optimizers applied:' },
      { t: '* Zero-Byte, Not-Iterated, Single-Version' },
      { t: '' },
      { t: 'ATTENTION! Pure (unoptimized) backend kernels selected.', cls: 'y' },
      { t: '' },
      { t: '$krb5tgs$23$*svc_backup$...:Backup2023!', cls: 'g' },
      { t: '$krb5tgs$23$*svc_sql$...:SqlServer1!', cls: 'g' },
      { t: '$krb5tgs$23$*svc_web$...:Welcome123', cls: 'g' },
      { t: '' },
      { t: 'Session..........: hashcat' },
      { t: 'Status...........: Cracked', cls: 'g' },
      { t: 'Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)' },
      { t: 'Time.Started.....: Mon Jan 15 14:18:04 2024 (22 secs)' },
      { t: 'Speed.#1.........:  3,482.2 kH/s (1.48ms) @ Accel:512 Loops:1 Thr:32 Vec:4' },
      { t: 'Recovered........: 3/3 (100.00%) Digests (total), 3/3 (100.00%) Digests (new)' },
      { t: 'Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)' },
      { t: '' },
      { t: 'Started: Mon Jan 15 14:18:04 2024', cls: 'd' },
      { t: 'Stopped: Mon Jan 15 14:18:26 2024', cls: 'd' },
    ],
  },

  // ── secretsdump ───────────────────────────────────────────────────────────
  {
    id: 'secretsdump',
    match: c => /impacket-secretsdump|secretsdump/.test(c) && c.includes('10.10.10.10'),
    stepLines: [
      { t: 'Impacket v0.11.0 - Copyright 2023 Fortra', delay: 0 },
      { t: '', delay: jitter(600, 150) },
      { t: '[*] Target system bootKey: 0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d', cls: 'b', delay: jitter(1200, 300) },
      { t: '[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)', cls: 'b', delay: jitter(800, 200) },
      { t: 'Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::', cls: 'g', delay: jitter(400, 100) },
      { t: 'Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::', delay: jitter(200, 50) },
      { t: '', delay: jitter(500, 120) },
      { t: '[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)', cls: 'b', delay: jitter(600, 150) },
      { t: '[*] Using the DRSUAPI method to get NTDS.DIT secrets', cls: 'b', delay: jitter(1400, 400) },
      { t: 'CORP\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::', cls: 'g', delay: jitter(300, 80) },
      { t: 'CORP\\Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::', delay: jitter(150, 40) },
      { t: 'CORP\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9f3a8b2c1d4e5f6a7b8c9d0e1f2a3b4c:::', delay: jitter(150, 40) },
      { t: 'CORP\\john.doe:1103:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::', delay: jitter(150, 40) },
      { t: 'CORP\\svc_backup:1104:aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5:::', cls: 'g', delay: jitter(150, 40) },
      { t: 'CORP\\svc_sql:1105:aad3b435b51404eeaad3b435b51404ee:f4c5e53a5e66f1c6e1c6d57f6eac2f5a:::', delay: jitter(150, 40) },
      { t: 'CORP\\svc_web:1106:aad3b435b51404eeaad3b435b51404ee:e10adc3949ba59abbe56e057f20f883e:::', delay: jitter(150, 40) },
      { t: '', delay: jitter(400, 100) },
      { t: '[*] Kerberos keys grabbed', cls: 'b', delay: jitter(700, 180) },
      { t: 'CORP\\Administrator:aes256-cts-hmac-sha1-96:3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4', delay: jitter(200, 50) },
      { t: '', delay: jitter(300, 80) },
      { t: '[*] Cleaning up...', cls: 'd', delay: jitter(500, 120) },
    ],
    lines: [],
  },

  // ── psexec ────────────────────────────────────────────────────────────────
  {
    id: 'psexec',
    match: c => /impacket-psexec|psexec\.py/.test(c) && c.includes('10.10.10.10'),
    stepLines: [
      { t: 'Impacket v0.11.0 - Copyright 2023 Fortra',                    delay: 0 },
      { t: '',                                                             delay: 300 },
      { t: '[*] Requesting shares on 10.10.10.10.....',   cls: 'b',       delay: jitter(1200, 300) },
      { t: '[*] Found writable share ADMIN$',             cls: 'g',       delay: jitter(800, 200) },
      { t: '[*] Uploading file XGaHpFZv.exe',             cls: 'b',       delay: jitter(1400, 400) },
      { t: '[*] Opening SVCManager on 10.10.10.10.....',  cls: 'b',       delay: jitter(900, 200) },
      { t: '[*] Creating service oUUL on 10.10.10.10.....',cls: 'b',      delay: jitter(600, 150) },
      { t: '[*] Starting service oUUL.....',              cls: 'b',       delay: jitter(1100, 300) },
      { t: '[!] Press help for extra shell commands',     cls: 'y',       delay: jitter(500, 100) },
      { t: 'Microsoft Windows [Version 10.0.17763.4737]', cls: 'w',      delay: jitter(700, 150) },
      { t: '(c) 2018 Microsoft Corporation. All rights reserved.', cls: 'd', delay: 100 },
      { t: '',                                                             delay: 400 },
      { t: 'C:\\Windows\\system32> whoami',               cls: 'p',       delay: jitter(600, 150) },
      { t: 'nt authority\\system',                        cls: 'g',       delay: jitter(300, 80) },
      { t: '',                                                             delay: 200 },
    ],
    lines: [],
    after: () => { SIM.windowsShell = true; SIM.winCwd = 'C:\\Windows\\system32'; },
  },

  // ── gobuster / dirb ───────────────────────────────────────────────────────
  {
    match: c => /^gobuster\b|^dirb\b|^dirsearch\b/.test(c),
    lines: [
      { t: 'Gobuster v3.6', cls: 'b' },
      { t: 'by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)', cls: 'd' },
      { t: '' },
      { t: 'Initializing scan...' },
      { t: '/index.html           (Status: 200) [Size: 1245]', cls: 'g' },
      { t: '/images               (Status: 301) [Size: 166]', cls: 'g' },
      { t: '/admin                (Status: 403) [Size: 291]', cls: 'y' },
      { t: '' },
      { t: 'Finished', cls: 'g' },
    ],
  },

  // ── rpcclient ─────────────────────────────────────────────────────────────
  {
    match: c => /^rpcclient\b/.test(c),
    lines: [
      { t: 'rpcclient $> enumdomusers', cls: 'd' },
      { t: 'user:[Administrator] rid:[0x1f4]' },
      { t: 'user:[john.doe] rid:[0x44f]' },
      { t: 'user:[svc_backup] rid:[0x450]' },
      { t: 'user:[svc_sql] rid:[0x451]' },
      { t: 'user:[svc_web] rid:[0x452]' },
      { t: 'rpcclient $> quit', cls: 'd' },
    ],
  },

  // ── smbclient ─────────────────────────────────────────────────────────────
  {
    match: c => /^smbclient\b/.test(c),
    lines: [
      { t: 'Password for [WORKGROUP\\root]:' },
      { t: '' },
      { t: '\tSharename       Type      Comment' },
      { t: '\t---------       ----      -------' },
      { t: '\tSYSVOL          Disk      Logon server share', cls: 'b' },
      { t: '\tNETLOGON        Disk      Logon server share', cls: 'b' },
      { t: '\tIPC$            IPC       Remote IPC', cls: 'd' },
      { t: 'Reconnecting with SMB1 for workgroup listing.' },
    ],
  },

  // ── kerbrute ─────────────────────────────────────────────────────────────
  {
    match: c => /^kerbrute\b/.test(c),
    lines: [
      { t: '    __             __               __', cls: 'p' },
      { t: '   / /_____  _____/ /_  _______  __/ /____', cls: 'p' },
      { t: '  / //_/ _ \\/ ___/ __ \\/ ___/ / / / __/ _ \\', cls: 'p' },
      { t: ' / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/', cls: 'p' },
      { t: '/_/|_|\\___/_/  /_.___/_/   \\__,_/\\__/\\___/', cls: 'p' },
      { t: '' },
      { t: 'Version: v1.0.3 (9dad6e1) - 01/15/24 - Ronnie Flathers @ropnop', cls: 'd' },
      { t: '' },
      { t: '2024/01/15 14:05:31 >  Using KDC(s):', cls: 'b' },
      { t: '2024/01/15 14:05:31 >  10.10.10.10:88', cls: 'b' },
      { t: '' },
      { t: '2024/01/15 14:05:32 >  [+] VALID USERNAME: Administrator@CORP.LOCAL', cls: 'g' },
      { t: '2024/01/15 14:05:32 >  [+] VALID USERNAME: john.doe@CORP.LOCAL', cls: 'g' },
      { t: '2024/01/15 14:05:32 >  [+] VALID USERNAME: svc_backup@CORP.LOCAL', cls: 'g' },
      { t: '2024/01/15 14:05:33 >  Done! Tested 100 usernames, 3 valid', cls: 'g' },
    ],
  },

  // ── pypykatz — offline LSASS minidump parser (file exists) ────────────────
  {
    id: 'pypykatz',
    loadTime: () => jitter(2400, 700),
    progressOnEnter: true,        // print first line immediately, then idle until done
    match: c => {
      const m = c.match(/^pypykatz\s+lsa\s+minidump\s+(\S+)/i);
      if (!m) return false;
      const path = m[1].replace(/^["']|["']$/g, '');
      const abs = path.startsWith('/') ? path : (SIM.cwd.replace(/\/$/, '') + '/' + path);
      return !!SIM.files[abs] || !!SIM.files[path];
    },
    lines: [
      { t: 'INFO:pypykatz:Parsing file lsass.dmp',                                cls: 'b' },
      { t: 'INFO:pypykatz:File parsed successfully',                              cls: 'g' },
      { t: '' },
      { t: 'FILE: lsass.dmp',                                                     cls: 'b' },
      { t: '== LogonSession ==',                                                  cls: 'b' },
      { t: 'authentication_id 996 (3e4)',                                         cls: 'd' },
      { t: 'session_id 0',                                                        cls: 'd' },
      { t: 'username DC01$' },
      { t: 'domainname CORP' },
      { t: 'logon_server',                                                        cls: 'd' },
      { t: 'logon_time 2024-01-15T15:14:33.234567',                               cls: 'd' },
      { t: '\t== MSV ==',                                                         cls: 'b' },
      { t: '\t\tUsername: DC01$' },
      { t: '\t\tDomain: CORP' },
      { t: '\t\tLM: NA',                                                          cls: 'd' },
      { t: '\t\tNT: 8c4d4e3a92ad1f0b4e9c8d7a6f5e4d3c',                            cls: 'g' },
      { t: '\t\tSHA1: 9f1e8d7c6b5a4e3d2c1b0a9f8e7d6c5b4a3f2e1d',                  cls: 'g' },
      { t: '' },
      { t: '== LogonSession ==',                                                  cls: 'b' },
      { t: 'authentication_id 281842 (44d32)',                                    cls: 'd' },
      { t: 'username Administrator' },
      { t: 'domainname DC01' },
      { t: '\t== MSV ==',                                                         cls: 'b' },
      { t: '\t\tUsername: Administrator' },
      { t: '\t\tDomain: DC01' },
      { t: '\t\tNT: fc525c9683e8fe067095ba2ddc971889',                            cls: 'g' },
      { t: '\t== WDIGEST [44d32]==',                                              cls: 'b' },
      { t: '\t\tusername Administrator' },
      { t: '\t\tdomainname DC01' },
      { t: '\t\tpassword SuperS3cret_Admin!2024',                                 cls: 'g' },
      { t: '\t== Kerberos ==',                                                    cls: 'b' },
      { t: '\t\tUsername: Administrator' },
      { t: '\t\tDomain: CORP.LOCAL' },
      { t: '\t\tPassword: SuperS3cret_Admin!2024',                                cls: 'g' },
      { t: '' },
      { t: '== LogonSession ==',                                                  cls: 'b' },
      { t: 'authentication_id 425918 (67ffe)',                                    cls: 'd' },
      { t: 'username svc_backup' },
      { t: 'domainname CORP' },
      { t: '\t== MSV ==',                                                         cls: 'b' },
      { t: '\t\tNT: 8c802621d2e36fc074345dded890f3e5',                            cls: 'g' },
      { t: '\t== WDIGEST [67ffe]==',                                              cls: 'b' },
      { t: '\t\tpassword Backup2024!',                                            cls: 'g' },
    ],
  },

  // ── pypykatz — file not found ─────────────────────────────────────────────
  {
    match: c => /^pypykatz\s+lsa\s+minidump\s+\S+/i.test(c),
    lines: [{ t: (cmd) => {
      const m = cmd.match(/^pypykatz\s+lsa\s+minidump\s+(\S+)/i);
      const path = m ? m[1].replace(/^["']|["']$/g, '') : '<file>';
      return `Traceback (most recent call last):\n` +
        `  File "/usr/local/bin/pypykatz", line 33, in <module>\n` +
        `    sys.exit(load_entry_point('pypykatz==0.6.10', 'console_scripts', 'pypykatz')())\n` +
        `  File "/usr/local/lib/python3.11/dist-packages/pypykatz/__main__.py", line 90, in main\n` +
        `    raise FileNotFoundError(args.minidumpfile)\n` +
        `FileNotFoundError: ${path}`;
    }, cls: 'r' }],
  },

  // ── pypykatz — usage (no args) ────────────────────────────────────────────
  {
    match: c => /^pypykatz(\s+lsa)?(\s+minidump)?\s*$/i.test(c) || c === 'pypykatz',
    lines: [
      { t: 'usage: pypykatz [-h] [-v] [--logfile LOGFILE]', cls: 'b' },
      { t: '                {lsa,registry,live,sake,kerberos,...} ...' },
      { t: '' },
      { t: 'pypykatz: error: the following arguments are required: command', cls: 'r' },
    ],
  },

  // ── hydra ─────────────────────────────────────────────────────────────────
  {
    match: c => /^hydra\b/.test(c),
    lines: [
      { t: 'Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak' },
      { t: '' },
      { t: 'Hydra (https://github.com/vanhauser-thc/thc-hydra) starting...', cls: 'b' },
      { t: '[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries' },
      { t: '[DATA] attacking smb://10.10.10.10:445/' },
      { t: '[445][smb] host: 10.10.10.10   login: john.doe   password: Password1!', cls: 'g' },
      { t: '1 of 1 target successfully completed, 1 valid password found', cls: 'g' },
    ],
  },

);

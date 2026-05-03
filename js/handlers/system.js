'use strict';

HANDLERS.push(
  // ── ps ────────────────────────────────────────────────────────────────────
  {
    match: c => /^ps(\s|$)/.test(c),
    lines: [{ t: c => {
      const isAux = c.includes('aux') || c.includes('-aux') || c.includes('a');
      if (isAux) return [
        'USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND',
        'root           1  0.0  0.2 168796 13132 ?        Ss   12:09   0:02 /sbin/init',
        'root           2  0.0  0.0      0     0 ?        S    12:09   0:00 [kthreadd]',
        'root         432  0.7  0.3 545928 24568 ?        Ssl  12:09   0:03 /usr/sbin/NetworkManager --no-daemon',
        'root         591  0.0  0.1  12312  7712 ?        Ss   12:09   0:00 sshd: /usr/sbin/sshd -D',
        'root         623  0.0  0.0  11688  3560 ?        Ss   12:09   0:00 /usr/sbin/cron -f',
        'rembrandt         891  0.0  0.6 231420 52400 tty7     Ss+  12:10   0:01 /usr/bin/Xorg :0 -seat seat0',
        'rembrandt        1189  0.0  0.9 456748 78432 ?        Ss   12:10   0:02 xfce4-session',
        `${SIM.user.padEnd(12)} 1234  0.0  0.1  11936  5192 pts/0    Ss   12:10   0:00 bash`,
        `${SIM.user.padEnd(12)} 1338  0.0  0.0  12240  3512 pts/0    R+   14:23   0:00 ps aux`,
      ].join('\n');
      return [
        '    PID TTY          TIME CMD',
        `   1234 pts/0    00:00:00 bash`,
        `   1338 pts/0    00:00:00 ps`,
      ].join('\n');
    }}],
  },

  // ── ss / netstat ─────────────────────────────────────────────────────────
  {
    match: c => /^(ss|netstat)(\s|$)/.test(c),
    lines: [
      { t: 'Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port' },
      { t: 'tcp    LISTEN  0       128     0.0.0.0:22         0.0.0.0:*', cls: 'g' },
      { t: 'tcp    LISTEN  0       128     127.0.0.1:631      0.0.0.0:*' },
      { t: 'tcp    ESTAB   0       0       10.10.10.5:51234   10.10.10.10:445', cls: 'b' },
    ],
  },

  // ── sudo -l (called by _runSudoCmd after auth) ────────────────────────────
  {
    match: c => c === '-l',
    lines: [
      { t: 'Matching Defaults entries for rembrandt on rembrandt:' },
      { t: '    env_reset, mail_badpass,' },
      { t: '    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' },
      { t: '' },
      { t: 'User rembrandt may run the following commands on rembrandt:', cls: 'g' },
      { t: '    (ALL : ALL) ALL', cls: 'g' },
    ],
  },

  // ── which ────────────────────────────────────────────────────────────────
  {
    match: c => /^which\s/.test(c),
    lines: [{ t: (c) => {
      const tool = c.replace(/^which\s+/, '').trim();
      const paths = {
        nmap: '/usr/bin/nmap', python3: '/usr/bin/python3', python: '/usr/bin/python3',
        bash: '/usr/bin/bash', sh: '/usr/bin/sh', john: '/usr/sbin/john',
        hashcat: '/usr/bin/hashcat', curl: '/usr/bin/curl', wget: '/usr/bin/wget',
        ssh: '/usr/bin/ssh', nc: '/usr/bin/nc', netcat: '/usr/bin/nc',
        'impacket-GetUserSPNs': '/usr/bin/impacket-GetUserSPNs',
        'impacket-secretsdump': '/usr/bin/impacket-secretsdump',
        'impacket-psexec': '/usr/bin/impacket-psexec',
        crackmapexec: '/usr/bin/crackmapexec', enum4linux: '/usr/bin/enum4linux',
        hydra: '/usr/bin/hydra', gobuster: '/usr/bin/gobuster',
        kerbrute: '/opt/kerbrute/kerbrute',
        top: '/usr/bin/top', htop: '/usr/bin/htop',
        df: '/usr/bin/df', free: '/usr/bin/free',
        ifconfig: '/usr/sbin/ifconfig', ip: '/usr/sbin/ip',
        ps: '/usr/bin/ps', ss: '/usr/bin/ss', arp: '/usr/sbin/arp',
      };
      return paths[tool] || `${tool} not found`;
    }, cls: (c) => {
      const tool = c.replace(/^which\s+/, '').trim();
      return ['nmap','john','hashcat','curl','wget','ssh','python3','bash','crackmapexec','enum4linux'].includes(tool) ? 'g' : 'r';
    }}],
  },

  // ── find ─────────────────────────────────────────────────────────────────
  {
    match: c => /^find\s/.test(c),
    lines: [{ t: (c) => {
      if (c.includes('.kerberoast') || c.includes('hash')) return SIM.hashesOnDisk ? '/home/' + SIM.user + '/hashes.kerberoast' : '';
      if (c.includes('wordlist') || c.includes('rockyou')) return '/usr/share/wordlists/rockyou.txt';
      if (c.includes('txt')) return '/home/' + SIM.user + '/notes.txt\n/etc/hosts\n/etc/os-release';
      return '';
    }}],
  },

  // ── grep ─────────────────────────────────────────────────────────────────
  {
    match: c => /^grep\s/.test(c),
    lines: [{ t: (c) => {
      if (c.includes('root') && c.includes('passwd')) return 'root:x:0:0:root:/root:/bin/bash';
      if (c.includes('rembrandt') && c.includes('passwd')) return '' + SIM.user + ':x:1000:1000:Rembrandt,,,:/home/' + SIM.user + ':/bin/bash';
      if (c.includes('svc') || c.includes('service')) return 'svc_backup:Backup2023!\nsvc_sql:SqlServer1!\nsvc_web:Welcome123';
      return '';
    }, cls: 'g'}],
  },

  // ── python3 ───────────────────────────────────────────────────────────────
  {
    match: c => /^python3?(\s|$)/.test(c),
    lines: [{ t: (c) => {
      if (c.includes('--version') || c.includes('-V')) return 'Python 3.11.6';
      if (c.includes('-c')) return '';
      return 'Python 3.11.6 (main, Oct 2 2023, 20:46:14) [GCC 13.2.0] on linux\nType "help", "copyright", "credits" or "license" for more information.\n>>> (simulation — interactive mode not supported)';
    }}],
  },

  // ── curl / wget ───────────────────────────────────────────────────────────
  {
    match: c => /^curl\s/.test(c),
    lines: [{ t: (c) => {
      if (c.includes('10.10.10.10') || c.includes('dc01')) return '<!DOCTYPE html>\n<html><head><title>IIS Windows Server</title></head><body><h1>IIS</h1></body></html>';
      return 'curl: (6) Could not resolve host: ' + c.split(' ').pop();
    }}],
  },
  {
    match: c => /^wget\s/.test(c),
    loadTime: () => jitter(1400, 400),
    lines: [
      { t: (c) => `--2024-01-15 14:23:01--  ${c.split(' ').pop()}` },
      { t: 'Connecting to... connected.' },
      { t: 'HTTP request sent, awaiting response... 200 OK' },
      { t: 'Length: 4096 (4.0K)' },
      { t: 'Saving to: output_file' },
      { t: '2024-01-15 14:23:02 (4.00 MB/s) — output_file saved [4096/4096]', cls: 'g' },
    ],
  },

  // ── ssh ───────────────────────────────────────────────────────────────────
  {
    match: c => /^ssh\s/.test(c),
    lines: [
      { t: (c) => {
        const host = c.split(' ').pop();
        return `ssh: connect to host ${host} port 22: Connection refused`;
      }, cls: 'r' },
    ],
  },

  // ── nc / netcat ───────────────────────────────────────────────────────────
  {
    match: c => /^(nc|netcat)\s/.test(c),
    lines: [{ t: '(simulation — nc not interactive)', cls: 'd' }],
  },

  // ── nano / vim ──────────────────────────────────────────────────────────────────────────────
  {
    match: c => /^(nano|vim?)\b/.test(c),
    lines: [{ t: (c) => {
      const arg = c.replace(/^(nano|vim?)\s*/, '').trim();
      if (!arg) return 'Usage: nano <filename>';
      const abs = arg.startsWith('/') ? arg : SIM.cwd.replace(/\/?$/, '/') + arg;
      const content = simFiles()[abs] !== undefined ? simFiles()[abs] : '';
      return { openEditor: true, filename: arg, filepath: abs, content };
    }}],
  },
  // ── other editors ───────────────────────────────────────────────────────────────────────────
  {
    match: c => /^(gedit|emacs|micro)\b/.test(c),
    lines: [{ t: (c) => `${c.split(' ')[0]}: interactive editors not supported in this simulation`, cls: 'y' }],
  },

  // ── service / systemctl ───────────────────────────────────────────────────
  {
    match: c => /^(service|systemctl)\s/.test(c),
    lines: [{ t: (c) => {
      if (c.includes('status')) return '● ssh.service - OpenBSD Secure Shell server\n   Loaded: loaded (/lib/systemd/system/ssh.service)\n   Active: active (running) since Mon 2024-01-15 12:10:03 EST; 2h 13min ago\n Main PID: 591 (sshd)\n   CGroup: /system.slice/ssh.service\n           └─591 sshd: /usr/sbin/sshd -D';
      if (c.includes('start') || c.includes('restart')) return '';
      return '';
    }}],
  },

  // ── top (animated live display) ──────────────────────────────────────────
  {
    match: c => c === 'top' || /^top\s/.test(c),
    liveDisplay: true,
    loadTime: 120000,
    refreshMs: 1000,
    displayFn: (tick) => {
      const now = new Date(Date.now() + tick * 1000);
      const hms = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`;
      const upM = String(13 + Math.floor(tick * 2 / 60)).padStart(2, '0');
      const upS = String((tick * 2) % 60).padStart(2, '0');
      const r = (v, d) => Math.max(0, v + (Math.random() * d * 2 - d));
      const us = r(8.4, 2.5).toFixed(1);
      const sy = r(3.1, 0.8).toFixed(1);
      const wa = r(0.4, 0.3).toFixed(1);
      const id = Math.max(0, 100 - parseFloat(us) - parseFloat(sy) - parseFloat(wa)).toFixed(1);
      const memFree = r(3821.5, 40).toFixed(1);
      const memUsed = r(3254.3, 30).toFixed(1);
      const la1  = r(0.72, 0.15).toFixed(2);
      const la5  = r(0.58, 0.10).toFixed(2);
      const la15 = r(0.41, 0.08).toFixed(2);
      const nmT = `0:0${3 + Math.floor(tick / 30)}.${String((21 + tick) % 100).padStart(2,'0')}`;
      const baT = `0:0${Math.floor((44 + tick * 3) / 100)}.${String((44 + tick * 3) % 100).padStart(2,'0')}`;
      const toT = `0:00.${String(tick % 100).padStart(2,'0')}`;
      // build process list with fluctuating CPU and sort by CPU each tick
      const procs = [
        { pid: 432,  user: 'root',      cpu: r(parseFloat(us)*0.6, 2.0), mem: 0.3, virt: 545928, res: 24568, time: nmT,       cmd: 'NetworkManager' },
        { pid: 1234, user: SIM.user,    cpu: r(2.1, 1.2),                mem: 0.1, virt: 11936,  res: 5192,  time: baT,       cmd: 'bash' },
        { pid: 891,  user: SIM.user,    cpu: r(1.4, 1.8),                mem: 0.6, virt: 231420, res: 52400, time: '0:01.23', cmd: 'Xorg' },
        { pid: 1189, user: SIM.user,    cpu: r(0.8, 1.0),                mem: 0.9, virt: 456748, res: 78432, time: '0:02.11', cmd: 'xfce4-session' },
        { pid: 1,    user: 'root',      cpu: r(0.1, 0.2),                mem: 0.2, virt: 168796, res: 13132, time: '0:02.14', cmd: 'systemd' },
        { pid: 2,    user: 'root',      cpu: 0.0,                        mem: 0.0, virt: 0,      res: 0,     time: '0:00.01', cmd: '[kthreadd]' },
        { pid: 3,    user: 'root',      cpu: r(0.0, 0.1),                mem: 0.0, virt: 0,      res: 0,     time: '0:00.00', cmd: '[rcu_gp]' },
        { pid: 591,  user: 'root',      cpu: r(0.0, 0.3),                mem: 0.1, virt: 12312,  res: 7712,  time: '0:00.08', cmd: 'sshd' },
        { pid: 623,  user: 'root',      cpu: r(0.0, 0.1),                mem: 0.0, virt: 11688,  res: 3560,  time: '0:00.01', cmd: 'cron' },
        { pid: 798,  user: 'root',      cpu: r(0.0, 0.2),                mem: 0.0, virt: 8192,   res: 2048,  time: '0:00.03', cmd: 'cupsd' },
        { pid: 412,  user: 'systemd-r', cpu: r(0.0, 0.1),                mem: 0.0, virt: 14532,  res: 4096,  time: '0:00.02', cmd: 'systemd-resolve' },
        { pid: 1337, user: SIM.user,    cpu: r(0.0, 0.1),                mem: 0.0, virt: 14240,  res: 3864,  time: toT,       cmd: '\x1b[1;97mtop\x1b[0m' },
      ];
      procs.sort((a, b) => b.cpu - a.cpu);
      const procRows = procs.map(p => {
        const cs = p.cpu.toFixed(1).padStart(4);
        const cc = p.cpu > 5 ? `\x1b[33m${cs}\x1b[0m` : p.cpu > 1 ? `\x1b[32m${cs}\x1b[0m` : cs;
        const row = `${String(p.pid).padStart(7)} ${p.user.slice(0,9).padEnd(9)} 20   0 ${String(p.virt).padStart(7)} ${String(p.res).padStart(6)} ${String(Math.floor(p.res*0.7)).padStart(6)} S ${cc}   ${p.mem.toFixed(1)}   ${p.time} ${p.cmd}`;
        return { t: row };
      });
      return [
        { t: `top - ${hms} up  2:${upM}:${upS},  1 user,  load average: ${la1}, ${la5}, ${la15}` },
        { t: `Tasks: \x1b[97m142\x1b[0m total,   \x1b[32m1\x1b[0m running, \x1b[0m141\x1b[0m sleeping,   0 stopped,   0 zombie` },
        { t: `%Cpu(s): \x1b[32m${String(us).padStart(4)} us\x1b[0m, \x1b[31m${String(sy).padStart(4)} sy\x1b[0m,  0.0 ni, \x1b[90m${String(id).padStart(5)} id\x1b[0m,  ${wa} wa,  0.0 hi,  0.0 si,  0.0 st` },
        { t: `\x1b[94mMiB Mem\x1b[0m :   8192.0 total,  ${String(memFree).padStart(7)} free,  \x1b[33m${String(memUsed).padStart(7)} used\x1b[0m,   ${(8192 - parseFloat(memFree) - parseFloat(memUsed)).toFixed(1)} buff/cache` },
        { t: `\x1b[94mMiB Swap\x1b[0m:   2048.0 total,   2048.0 free,      0.0 used.   ${(8192 - parseFloat(memUsed)).toFixed(1)} avail Mem` },
        { t: '' },
        { t: `\x1b[1;4m    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\x1b[0m` },
        ...procRows.map(r => ({ ...r, t: r.t.slice(0, 80) })),
        { t: '' },
        { t: `\x1b[90mq or Ctrl+C to quit\x1b[0m` },
      ];
    },
    // dead code path kept to satisfy dispatcher shape
    lines: [{ t: '' }],
  },

  // ── htop (animated, colored) ──────────────────────────────────────────────
  {
    match: c => c === 'htop' || /^htop\s/.test(c),
    liveDisplay: true,
    loadTime: 120000,
    refreshMs: 500,
    displayFn: (tick) => {
      const r  = (v, d) => Math.max(0, v + (Math.random() * d * 2 - d));
      const cpuPct  = r(11.5, 3.0);
      const memUsedM = Math.round(r(3254, 40));
      const la1  = r(0.72, 0.15).toFixed(2);
      const la5  = r(0.58, 0.10).toFixed(2);
      const la15 = r(0.41, 0.08).toFixed(2);
      const upM  = String(13 + Math.floor(tick * 2 / 60)).padStart(2,'0');
      const upS  = String((tick * 2) % 60).padStart(2,'0');
      const toT  = `0:00.${String(tick % 100).padStart(2,'0')}`;

      // CPU bar — green=user, red=sys, blank=idle
      const W = 36;
      const fill  = Math.round(cpuPct / 100 * W);
      const uFill = Math.max(1, Math.round(fill * 0.75));
      const sFill = fill - uFill;
      const cpuBar = `\x1b[32m${'|'.repeat(uFill)}\x1b[31m${'|'.repeat(sFill)}\x1b[0m${' '.repeat(W - fill)}`;

      // Memory bar — green=used, blue=buffers
      const mFill  = Math.round(memUsedM / 8192 * W);
      const mU     = Math.max(1, Math.round(mFill * 0.88));
      const mB     = mFill - mU;
      const memBar = `\x1b[32m${'|'.repeat(mU)}\x1b[34m${'|'.repeat(mB)}\x1b[0m${' '.repeat(W - mFill)}`;

      return [
        { t: `  \x1b[32mCPU\x1b[0m[${cpuBar}] ${String(cpuPct.toFixed(1)).padStart(5)}%   Tasks: \x1b[32m142\x1b[0m, 456 thr; \x1b[32m1\x1b[0m running` },
        { t: `  \x1b[32mMem\x1b[0m[${memBar}] ${memUsedM}M/8192M   Load avg: \x1b[33m${la1} ${la5} ${la15}\x1b[0m` },
        { t: `  \x1b[32mSwp\x1b[0m[${' '.repeat(W)}]    0K/2048M   Uptime: \x1b[97m02:${upM}:${upS}\x1b[0m` },
        { t: '' },
        { t: `\x1b[1;30;47m  PID USER       PRI  NI  VIRT   RES   SHR S CPU%  MEM%   TIME+   Command                              \x1b[0m` },
        { t: `  432 \x1b[32mroot\x1b[0m        20   0  533M 24568 18844 S ${String(cpuPct.toFixed(1)).padStart(5)}  0.3  0:03.21 \x1b[32mNetworkManager\x1b[0m` },
        { t: ` 1234 \x1b[32m${SIM.user.padEnd(10)}\x1b[0m 20   0 11936  5192  3824 S  ${r(2.1,0.8).toFixed(1).padStart(4)}   0.1  ${`0:0${Math.floor((44 + tick * 3)/100)}.${String((44 + tick * 3) % 100).padStart(2,'0')}`} \x1b[32mbash\x1b[0m` },
        { t: `    1 \x1b[32mroot\x1b[0m        20   0  165M 13132  8392 S  0.0   0.2  0:02.14 \x1b[90m/sbin/init\x1b[0m` },
        { t: `    2 \x1b[32mroot\x1b[0m         0 -20     0     0     0 I  0.0   0.0  0:00.01 \x1b[90m[kthreadd]\x1b[0m` },
        { t: `  591 \x1b[32mroot\x1b[0m        20   0 12312  7712  6448 S  0.0   0.1  0:00.08 \x1b[36msshd\x1b[0m` },
        { t: `  623 \x1b[32mroot\x1b[0m        20   0 11688  3560  3284 S  0.0   0.0  0:00.01 \x1b[36mcron\x1b[0m` },
        { t: `  891 \x1b[34mrembrandt\x1b[0m        20   0  226M 52400 38100 S  0.0   0.6  0:01.23 \x1b[34mXorg\x1b[0m` },
        { t: ` 1189 \x1b[34mrembrandt\x1b[0m        20   0  446M 78432 59200 S  0.0   0.9  0:02.11 \x1b[34mxfce4-session\x1b[0m` },
        { t: ` 1338 \x1b[34m${SIM.user.padEnd(10)}\x1b[0m 20   0 14240  3864  3188 R  0.0   0.0  ${toT}  \x1b[1;97mhtop\x1b[0m` },
        { t: '' },
        { t: `\x1b[30;42m F1\x1b[0mHelp \x1b[30;42m F2\x1b[0mSetup \x1b[30;42m F3\x1b[0mSearch \x1b[30;42m F4\x1b[0mFilter \x1b[30;42m F5\x1b[0mTree \x1b[30;42m F6\x1b[0mSortBy \x1b[30;42m F9\x1b[0mKill \x1b[30;42mF10\x1b[0mQuit` },
      ];
    },
    lines: [{ t: '' }],
  },

  // ── df ────────────────────────────────────────────────────────────────────
  {
    match: c => /^df(\s|$)/.test(c),
    lines: [
      { t: 'Filesystem      Size  Used Avail Use% Mounted on' },
      { t: '/dev/sda1        50G   18G   30G  38% /', cls: 'g' },
      { t: 'tmpfs           4.0G     0  4.0G   0% /dev/shm' },
      { t: 'tmpfs           1.6G  1.2M  1.6G   1% /run' },
      { t: '/dev/sda2       200G   45G  145G  24% /home', cls: 'g' },
      { t: 'tmpfs           100M   20K  100M   1% /run/user/1000' },
    ],
  },

  // ── free ─────────────────────────────────────────────────────────────────
  {
    match: c => /^free(\s|$)/.test(c),
    lines: [
      { t: '               total        used        free      shared  buff/cache   available' },
      { t: 'Mem:         8388608     2914048     4325632       13312     1148928     5178208', cls: 'b' },
      { t: 'Swap:        2097152           0     2097152', cls: 'd' },
    ],
  },

  // ── ifconfig / ip addr / ip a ─────────────────────────────────────────────
  {
    match: c => c === 'ifconfig' || c === 'ifconfig -a' || /^ip\s+(addr|a|address|link)/.test(c),
    lines: [
      { t: 'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500', cls: 'b' },
      { t: '        inet 10.10.10.5  netmask 255.255.255.0  broadcast 10.10.10.255' },
      { t: '        inet6 fe80::250:56ff:fe8d:4ab3  prefixlen 64  scopeid 0x20<link>' },
      { t: '        ether 00:50:56:8d:4a:b3  txqueuelen 1000  (Ethernet)' },
      { t: '        RX packets 84231  bytes 12445920 (11.8 MiB)' },
      { t: '        TX packets 52134  bytes 8923410 (8.5 MiB)' },
      { t: '' },
      { t: 'lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536', cls: 'b' },
      { t: '        inet 127.0.0.1  netmask 255.0.0.0' },
      { t: '        inet6 ::1  prefixlen 128  scopeid 0x10<host>' },
      { t: '        loop  txqueuelen 1000  (Local Loopback)' },
    ],
  },

  // ── ip route ─────────────────────────────────────────────────────────────
  {
    match: c => /^ip\s+r(oute)?/.test(c) || c === 'route -n' || c === 'route',
    lines: [
      { t: 'default via 10.10.10.1 dev eth0 proto dhcp metric 100', cls: 'g' },
      { t: '10.10.10.0/24 dev eth0 proto kernel scope link src 10.10.10.5 metric 100' },
      { t: '127.0.0.0/8 dev lo proto kernel scope link src 127.0.0.1' },
    ],
  },

  // ── arp ───────────────────────────────────────────────────────────────────
  {
    match: c => /^arp(\s|$)/.test(c),
    lines: [
      { t: 'Address                  HWtype  HWaddress           Flags Mask    Iface' },
      { t: '10.10.10.1               ether   00:50:56:c0:00:08   C             eth0' },
      { t: '10.10.10.10              ether   00:0c:29:3a:bc:de   C             eth0', cls: 'g' },
    ],
  },

  // ── echo ─────────────────────────────────────────────────────────────────
  {
    match: c => /^echo(\s|$)/.test(c),
    lines: [{ t: c => c.replace(/^echo\s*/, '').replace(/^(['"])(.*)\1$/, '$2') }],
  },

  // ── lsb_release ──────────────────────────────────────────────────────────
  {
    match: c => /^lsb_release/.test(c),
    lines: [
      { t: 'Distributor ID:\tRembrandt' },
      { t: 'Description:\tRembrandt GNU/Linux Rolling' },
      { t: 'Release:\t2024.2' },
      { t: 'Codename:\trembrandt-rolling' },
    ],
  },

  // ── w ─────────────────────────────────────────────────────────────────────
  {
    match: c => c === 'w' || /^w\s/.test(c),
    lines: [{ t: () => {
      const t = new Date();
      const hms = `${String(t.getHours()).padStart(2,'0')}:${String(t.getMinutes()).padStart(2,'0')}:${String(t.getSeconds()).padStart(2,'0')}`;
      return ` ${hms} up 2:13,  1 user,  load average: 0.15, 0.22, 0.18\nUSER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\n${SIM.user.padEnd(8)} pts/0    10.10.10.1       12:10    0.00s  0.08s  0.00s w`;
    }}],
  },

  // ── who ───────────────────────────────────────────────────────────────────
  {
    match: c => c === 'who' || c === 'who -a' || c === 'who -H',
    lines: [{ t: () => `${SIM.user.padEnd(8)} pts/0        ${new Date().toISOString().slice(0,16).replace('T',' ')}  (10.10.10.1)` }],
  },

  // ── last ─────────────────────────────────────────────────────────────────
  {
    match: c => /^last(\s|$)/.test(c),
    lines: [
      { t: () => `${SIM.user.padEnd(8)} pts/0        10.10.10.1       Mon Jan 15 12:10   still logged in` },
      { t: 'reboot   system boot  6.6.9-amd64      Mon Jan 15 12:09   still running' },
      { t: '' },
      { t: 'wtmp begins Mon Jan 15 12:09:02 2024', cls: 'd' },
    ],
  },

  // ── mkdir / touch / rm / cp / mv ─────────────────────────────────────────────────────────────────
  {
    match: c => /^(mkdir|touch|rm|cp|mv)(\s|$)/.test(c),
    lines: [{ t: c => {
      const op = c.split(' ')[0];
      const arg = c.replace(/^\S+\s*(-p\s+)?/, '').trim();
      if (!arg) return `${op}: missing operand`;
      const abs = arg.startsWith('/') ? arg : SIM.cwd.replace(/\/?$/, '/') + arg;
      if (op === 'mkdir') { SIM.dirs.add(abs); return ''; }
      if (op === 'touch') { if (!SIM.files[abs]) SIM.files[abs] = ''; return ''; }
      if (op === 'rm') {
        if (c.includes('-rf') && arg === '/') return "rm: it is dangerous to operate recursively on '/'";
        if (!SIM.files[abs] && !SIM.dirs.has(abs)) return `rm: cannot remove '${arg}': No such file or directory`;
        delete SIM.files[abs]; SIM.dirs.delete(abs); return '';
      }
      if (op === 'cp' || op === 'mv') {
        const parts = c.split(/\s+/).slice(1).filter(p => !p.startsWith('-'));
        if (parts.length < 2) return `${op}: missing destination`;
        const src = parts[0].startsWith('/') ? parts[0] : SIM.cwd.replace(/\/?$/, '/') + parts[0];
        const dst = parts[1].startsWith('/') ? parts[1] : SIM.cwd.replace(/\/?$/, '/') + parts[1];
        if (SIM.files[src] !== undefined) {
          SIM.files[dst] = SIM.files[src];
          if (op === 'mv') delete SIM.files[src];
        } else if (SIM.dirs.has(src)) {
          SIM.dirs.add(dst);
          if (op === 'mv') SIM.dirs.delete(src);
        } else {
          return `${op}: cannot stat '${parts[0]}': No such file or directory`;
        }
        return '';
      }
      return '';
    }}],
  },

  // ── cat /proc entries ─────────────────────────────────────────────────────
  {
    match: c => c === 'cat /proc/version',
    lines: [{ t: 'Linux version 6.6.9-amd64 (debian-kernel@lists.debian.org) (gcc-13 (Debian 13.2.0-13) 13.2.0, GNU ld (GNU Binutils for Debian) 2.41) #1 SMP PREEMPT_DYNAMIC Rembrandt 6.6.9-1rembrandt1 (2024-01-08)' }],
  },
  {
    match: c => c === 'cat /proc/cpuinfo' || c === 'cat /proc/cpuinfo | head -20',
    lines: [
      { t: 'processor\t: 0' },
      { t: 'vendor_id\t: GenuineIntel' },
      { t: 'cpu family\t: 6' },
      { t: 'model name\t: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz' },
      { t: 'cpu MHz\t\t: 3799.998' },
      { t: 'cache size\t: 16384 KB' },
      { t: 'physical id\t: 0' },
      { t: 'cpu cores\t: 4' },
      { t: 'flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc' },
    ],
  },

  // ── lscpu ────────────────────────────────────────────────────────────────
  {
    match: c => c === 'lscpu' || /^lscpu\s/.test(c),
    lines: [
      { t: 'Architecture:                    x86_64', cls: 'b' },
      { t: 'CPU op-mode(s):                  32-bit, 64-bit' },
      { t: 'Address sizes:                   45 bits physical, 48 bits virtual' },
      { t: 'Byte Order:                      Little Endian' },
      { t: 'CPU(s):                          4', cls: 'g' },
      { t: 'On-line CPU(s) list:             0-3' },
      { t: 'Vendor ID:                       GenuineIntel' },
      { t: 'BIOS Vendor ID:                  GenuineIntel' },
      { t: 'Model name:                      Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz', cls: 'g' },
      { t: 'BIOS Model name:                 Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz  CPU @ 3.8GHz' },
      { t: 'CPU family:                      6' },
      { t: 'Model:                           165' },
      { t: 'Thread(s) per core:              2' },
      { t: 'Core(s) per socket:              4' },
      { t: 'Socket(s):                       1' },
      { t: 'Stepping:                        5' },
      { t: 'CPU max MHz:                     5100.0000', cls: 'y' },
      { t: 'CPU min MHz:                     800.0000' },
      { t: 'BogoMIPS:                        7600.00' },
      { t: 'Virtualization:                  VT-x', cls: 'c' },
      { t: 'L1d cache:                       128 KiB (4 instances)' },
      { t: 'L1i cache:                       128 KiB (4 instances)' },
      { t: 'L2 cache:                        1 MiB (4 instances)' },
      { t: 'L3 cache:                        16 MiB (1 instance)', cls: 'g' },
      { t: 'NUMA node(s):                    1' },
      { t: 'NUMA node0 CPU(s):               0-3' },
      { t: 'Vulnerability Itlb multihit:     Not affected' },
      { t: 'Vulnerability L1tf:              Not affected' },
      { t: 'Vulnerability Mds:               Not affected' },
      { t: 'Vulnerability Meltdown:          Not affected' },
      { t: 'Vulnerability Mmio stale data:   Mitigation; Clear CPU buffers; SMT vulnerable', cls: 'y' },
      { t: 'Vulnerability Spec store bypass: Mitigation; Speculative Store Bypass disabled via prctl', cls: 'y' },
      { t: 'Vulnerability Spectre v1:        Mitigation; usercopy/swapgs barriers and __user pointer sanitization', cls: 'y' },
      { t: 'Vulnerability Spectre v2:        Mitigation; Enhanced / Automatic IBRS; IBPB conditional; RSB filling', cls: 'y' },
      { t: 'Flags:                           fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d arch_capabilities', cls: 'd' },
    ],
  },

  // ── lsblk ─────────────────────────────────────────────────────────────────
  {
    match: c => /^lsblk(\s|$)/.test(c),
    lines: [
      { t: 'NAME        MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS' },
      { t: 'sda           8:0    0    50G  0 disk ', cls: 'b' },
      { t: '├─sda1        8:1    0    48G  0 part /', cls: 'g' },
      { t: '└─sda2        8:2    0     2G  0 part [SWAP]', cls: 'd' },
      { t: 'sr0          11:0    1  1024M  0 rom  ', cls: 'd' },
    ],
  },

  // ── lspci ─────────────────────────────────────────────────────────────────
  {
    match: c => /^lspci(\s|$)/.test(c),
    lines: [
      { t: '00:00.0 Host bridge: Intel Corporation 440BX/ZX/DX - 82443BX/ZX/DX Host bridge (rev 01)' },
      { t: '00:01.0 PCI bridge: Intel Corporation 440BX/ZX/DX - 82443BX/ZX/DX AGP bridge (rev 01)' },
      { t: '00:07.0 ISA bridge: Intel Corporation 82371AB/EB/MB PIIX4 ISA (rev 08)' },
      { t: '00:07.1 IDE interface: Intel Corporation 82371AB/EB/MB PIIX4 IDE (rev 01)' },
      { t: '00:07.3 Bridge: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 08)' },
      { t: '00:07.7 System peripheral: VMware Virtual Machine Communication Interface (rev 10)' },
      { t: '00:0f.0 VGA compatible controller: VMware SVGA II Adapter', cls: 'g' },
      { t: '00:10.0 SCSI storage controller: Broadcom / LSI 53c1030 PCI-X Fusion-MPT Dual Ultra320 SCSI' },
      { t: '00:11.0 PCI bridge: VMware PCI bridge (rev 02)' },
      { t: '00:15.0 PCI bridge: VMware PCI Express Root Port (rev 01)' },
      { t: '02:00.0 USB controller: VMware USB2 EHCI Controller', cls: 'b' },
      { t: '02:01.0 Ethernet controller: VMware VMXNET3 Ethernet Controller (rev 01)', cls: 'g' },
      { t: '02:02.0 Multimedia audio controller: Ensoniq ES1371/ES1373 / Creative Labs CT2518 (rev 02)' },
      { t: '02:03.0 SATA controller: VMware SATA AHCI controller', cls: 'b' },
    ],
  },

  // ── lsusb ─────────────────────────────────────────────────────────────────
  {
    match: c => /^lsusb(\s|$)/.test(c),
    lines: [
      { t: 'Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub', cls: 'b' },
      { t: 'Bus 001 Device 002: ID 0e0f:0003 VMware, Inc. Virtual Mouse' },
      { t: 'Bus 001 Device 003: ID 0e0f:0002 VMware, Inc. Virtual Keyboard' },
      { t: 'Bus 002 Device 001: ID 1d6b:0001 Linux Foundation 1.1 root hub', cls: 'b' },
      { t: 'Bus 002 Device 002: ID 0e0f:0008 VMware, Inc. VMware Virtual USB Hub' },
    ],
  },

  // ── hostnamectl ───────────────────────────────────────────────────────────
  {
    match: c => /^hostnamectl(\s|$)/.test(c),
    lines: [
      { t: '   Static hostname: rembrandt', cls: 'b' },
      { t: '         Icon name: computer-vm' },
      { t: '           Chassis: vm 🖥' },
      { t: () => `        Machine ID: d4a8f2c1b3e5a7d9f1c3e5b7a9d1f3c5` },
      { t: '           Boot ID: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6' },
      { t: '    Virtualization: vmware', cls: 'y' },
      { t: '  Operating System: Rembrandt GNU/Linux Rolling', cls: 'g' },
      { t: '       OS Arch: x86-64' },
      { t: '            Kernel: Linux 6.6.9-amd64', cls: 'g' },
      { t: '      Architecture: x86-64' },
      { t: '   Hardware Vendor: VMware, Inc.' },
      { t: '    Hardware Model: VMware Virtual Platform' },
      { t: '  Firmware Version: 6.00' },
      { t: '     Firmware Date: Thu 2020-11-12' },
      { t: '      Firmware Age: 3y 2month 2d' },
    ],
  },

  // ── timedatectl ───────────────────────────────────────────────────────────
  {
    match: c => /^timedatectl(\s|$)/.test(c),
    lines: [{ t: () => {
      const now = new Date();
      const utc = now.toUTCString().replace('GMT', 'UTC');
      return [
        `               Local time: ${now.toString().replace(/ \(.+\)/,'')}`,
        `           Universal time: ${utc}`,
        `                 RTC time: ${utc}`,
        `                Time zone: America/New_York (EST, -0500)`,
        `System clock synchronized: yes`,
        `              NTP service: active`,
        `          RTC in local TZ: no`,
      ].join('\n');
    }}],
  },

  // ── dmidecode ─────────────────────────────────────────────────────────────
  {
    match: c => /^dmidecode(\s|$)/.test(c),
    requireRoot: true,
    lines: [
      { t: '# dmidecode 3.5', cls: 'd' },
      { t: 'Getting SMBIOS data from sysfs.' },
      { t: 'SMBIOS 2.7 present.' },
      { t: '' },
      { t: 'Handle 0x0001, DMI type 1, 27 bytes', cls: 'b' },
      { t: 'System Information' },
      { t: '\tManufacturer: VMware, Inc.' },
      { t: '\tProduct Name: VMware Virtual Platform' },
      { t: '\tVersion: None' },
      { t: '\tSerial Number: VMware-56 4d 2f 8a b2 c1 3d e4-89 f0 12 34 56 78 9a bc' },
      { t: '\tUUID: 564d2f8a-b2c1-3de4-89f0-123456789abc' },
      { t: '\tWake-up Type: Power Switch' },
      { t: '' },
      { t: 'Handle 0x0002, DMI type 2, 15 bytes', cls: 'b' },
      { t: 'Base Board Information' },
      { t: '\tManufacturer: Intel Corporation' },
      { t: '\tProduct Name: 440BX Desktop Reference Platform' },
      { t: '\tVersion: None' },
      { t: '' },
      { t: 'Handle 0x0004, DMI type 4, 48 bytes', cls: 'b' },
      { t: 'Processor Information' },
      { t: '\tSocket Designation: CPU socket #0' },
      { t: '\tType: Central Processor' },
      { t: '\tFamily: Xeon' },
      { t: '\tManufacturer: GenuineIntel' },
      { t: '\tID: EA 06 00 00 FF FB EB BF' },
      { t: '\tVersion: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz' },
      { t: '\tVoltage: 3.3 V' },
      { t: '\tExternal Clock: 100 MHz' },
      { t: '\tMax Speed: 3800 MHz' },
      { t: '\tCurrent Speed: 3800 MHz' },
      { t: '\tStatus: Populated, Enabled' },
      { t: '\tCore Count: 4' },
      { t: '\tThread Count: 8' },
      { t: '' },
      { t: 'Handle 0x0017, DMI type 17, 92 bytes', cls: 'b' },
      { t: 'Memory Device' },
      { t: '\tArray Handle: 0x0016' },
      { t: '\tTotal Width: 64 bits' },
      { t: '\tData Width: 64 bits' },
      { t: '\tSize: 8 GB' },
      { t: '\tForm Factor: DIMM' },
      { t: '\tLocator: DIMM 0' },
      { t: '\tType: RAM' },
      { t: '\tSpeed: 3200 MT/s' },
      { t: '\tManufacturer: Kingston' },
      { t: '\tSerial Number: 00000001' },
      { t: '\tPart Number: KHX3200C16D4/8GX' },
      { t: '\tConfigured Memory Speed: 3200 MT/s' },
    ],
  },

  // ── vmstat ────────────────────────────────────────────────────────────────
  {
    match: c => /^vmstat(\s|$)/.test(c),
    lines: [
      { t: 'procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----', cls: 'b' },
      { t: ' r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st' },
      { t: ' 1  0      0 4325632 213456  935472    0    0     1     4  167  423  2  1 97  0  0', cls: 'g' },
    ],
  },

  // ── iostat ────────────────────────────────────────────────────────────────
  {
    match: c => /^iostat(\s|$)/.test(c),
    lines: [
      { t: () => `Linux 6.6.9-amd64 (capy) \t${new Date().toLocaleDateString('en-US',{month:'2-digit',day:'2-digit',year:'numeric'})} \t_x86_64_\t(4 CPU)` },
      { t: '' },
      { t: 'avg-cpu:  %user   %nice %system %iowait  %steal   %idle', cls: 'b' },
      { t: '           2.28    0.00    0.82    0.21    0.00   96.69' },
      { t: '' },
      { t: 'Device             tps    kB_read/s    kB_wrtn/s    kB_dscd/s    kB_read    kB_wrtn    kB_dscd', cls: 'b' },
      { t: 'sda               1.23         3.21        12.45         0.00      48291     187432          0', cls: 'g' },
    ],
  },

  // ── sysctl ────────────────────────────────────────────────────────────────
  {
    match: c => /^sysctl(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      if (cmd.includes('net.ipv4.ip_forward')) return 'net.ipv4.ip_forward = 1';
      if (cmd.includes('kernel.hostname'))     return 'kernel.hostname = rembrandt';
      if (cmd.includes('-a') || cmd.includes('--all')) return [
        'abi.vsyscall32 = 1',
        'debug.exception-trace = 1',
        'fs.file-max = 9223372036854775807',
        'kernel.hostname = rembrandt',
        'kernel.osrelease = 6.6.9-amd64',
        'kernel.ostype = Linux',
        'kernel.pid_max = 4194304',
        'net.core.rmem_max = 212992',
        'net.ipv4.conf.all.forwarding = 1',
        'net.ipv4.ip_forward = 1',
        'net.ipv4.tcp_fin_timeout = 60',
        'net.ipv4.tcp_keepalive_time = 7200',
        'vm.swappiness = 60',
        'vm.dirty_ratio = 20',
      ].join('\n');
      return `sysctl: cannot stat /proc/sys/${cmd.split(' ').pop().replace(/\./g,'/')}: No such file or directory`;
    }}],
  },

  // ── lsmod ─────────────────────────────────────────────────────────────────
  {
    match: c => c === 'lsmod',
    lines: [
      { t: 'Module                  Size  Used by', cls: 'b' },
      { t: 'nf_nat                 57344  3 nft_nat,xt_nat,nf_nat_masquerade_ipv4' },
      { t: 'nf_conntrack          180224  6 nf_nat,nft_ct,xt_conntrack,nf_nat_masquerade_ipv4,nf_conntrack_netlink,xt_MASQUERADE' },
      { t: 'nft_compat             20480  34' },
      { t: 'nf_tables             299008  438 nft_compat,nft_ct,nft_nat' },
      { t: 'vmw_vsock_vmci_transport    32768  0' },
      { t: 'vmw_vmci               77824  1 vmw_vsock_vmci_transport' },
      { t: 'vmwgfx                393216  2', cls: 'b' },
      { t: 'drm_ttm_helper         16384  1 vmwgfx' },
      { t: 'ttm                    77824  2 vmwgfx,drm_ttm_helper' },
      { t: 'drm_kms_helper        221184  1 vmwgfx' },
      { t: 'e1000                 155648  0', cls: 'g' },
      { t: 'vmxnet3                73728  0', cls: 'g' },
      { t: 'ata_piix               32768  2' },
      { t: 'libata                266240  2 ata_piix,ahci' },
      { t: 'scsi_mod              266240  4 libata,sd_mod,scsi_transport_spi,mptspi' },
    ],
  },

  // ── dmesg ────────────────────────────────────────────────────────────────
  {
    match: c => /^dmesg(\s|$)/.test(c),
    lines: [
      { t: '[    0.000000] Linux version 6.6.9-amd64 (debian-kernel@lists.debian.org) (gcc-13 (Debian 13.2.0-13) 13.2.0, GNU ld (GNU Binutils for Debian) 2.41) #1 SMP PREEMPT_DYNAMIC Rembrandt 6.6.9-1rembrandt1 (2024-01-08)', cls: 'b' },
      { t: '[    0.000000] Command line: BOOT_IMAGE=/vmlinuz-6.6.9-amd64 root=/dev/sda1 ro quiet splash' },
      { t: '[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009efff] usable' },
      { t: '[    0.000000] BIOS-e820: [mem 0x000000000009f000-0x00000000000fffff] reserved' },
      { t: '[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x000000003fffffff] usable' },
      { t: '[    0.000000] NX (Execute Disable) protection: active', cls: 'g' },
      { t: '[    0.000000] SMBIOS 2.7 present.' },
      { t: '[    0.000000] DMI: VMware, Inc. VMware Virtual Platform/440BX Desktop Reference Platform, BIOS 6.00 11/12/2020' },
      { t: '[    0.000000] Hypervisor detected: VMware', cls: 'y' },
      { t: '[    0.000000] tsc: Detected 3800.000 MHz processor' },
      { t: '[    0.235718] ACPI: IRQ0 used by override.' },
      { t: '[    0.246891] PCI: Using configuration type 1 for base access' },
      { t: '[    0.892314] NET: Registered PF_PACKET protocol family' },
      { t: '[    0.934521] clocksource: tsc-early: mask: 0xffffffffffffffff max_cycles: 0x36d8e3f9938, max_idle_ns: 881590580619 ns' },
      { t: '[    1.123456] AppArmor: AppArmor initialized', cls: 'g' },
      { t: '[    1.234567] audit: type=1400 audit(1705313341.000:2): apparmor="STATUS" operation="profile_load" profile="unconfined" name="nvidia_modprobe"' },
      { t: '[    1.456789] e1000: Intel(R) PRO/1000 Network Driver', cls: 'b' },
      { t: '[    1.457891] e1000: Copyright (c) 1999-2006 Intel Corporation.' },
      { t: '[    1.502341] SCSI subsystem initialized' },
      { t: '[    1.823456] ata1: SATA max UDMA/133 cmd 0x1f0 ctl 0x3f6 bmdma 0xc000 irq 14', cls: 'b' },
      { t: '[    2.012345] EXT4-fs (sda1): mounted filesystem with ordered data mode. Quota mode: none.', cls: 'g' },
      { t: '[    2.134567] NET: Registered PF_INET6 protocol family' },
      { t: '[    2.456789] Bluetooth: Core ver 2.22' },
      { t: '[    2.567890] NET: Registered PF_BLUETOOTH protocol family' },
      { t: '[    3.234567] systemd[1]: systemd 252.22-1~deb12u1 running in system mode', cls: 'g' },
      { t: '[    3.456789] systemd[1]: Detected virtualization vmware.', cls: 'y' },
      { t: '[    3.678901] systemd[1]: Detected architecture x86-64.' },
      { t: '[   12.345678] audit: type=1400 audit(1705313351.000:42): apparmor="STATUS" operation="profile_replace" name="dhclient"' },
      { t: '[   14.456789] e1000 0000:02:01.0 eth0: renamed from ens33', cls: 'b' },
    ],
  },

  // ── journalctl ────────────────────────────────────────────────────────────
  {
    match: c => /^journalctl(\s|$)/.test(c),
    lines: [
      { t: '-- Logs begin at Mon 2024-01-15 12:09:01 EST, end at Mon 2024-01-15 14:23:01 EST. --', cls: 'd' },
      { t: 'Jan 15 12:09:01 rembrandt systemd[1]: Starting Rembrandt GNU/Linux Rolling...', cls: 'b' },
      { t: 'Jan 15 12:09:02 rembrandt kernel: Linux version 6.6.9-amd64' },
      { t: 'Jan 15 12:09:02 rembrandt kernel: Command line: BOOT_IMAGE=/vmlinuz-6.6.9-amd64 root=/dev/sda1 ro quiet splash' },
      { t: 'Jan 15 12:09:03 rembrandt systemd[1]: Starting Network Time Synchronization...' },
      { t: 'Jan 15 12:09:04 rembrandt systemd[1]: Started Network Time Synchronization.', cls: 'g' },
      { t: 'Jan 15 12:09:05 rembrandt systemd[1]: Starting Network Service...' },
      { t: 'Jan 15 12:09:05 rembrandt NetworkManager[432]: <info>  [1705313345.0000] NetworkManager (version 1.44.2) is starting' },
      { t: 'Jan 15 12:09:06 rembrandt NetworkManager[432]: <info>  [1705313346.0000] Read config: /etc/NetworkManager/NetworkManager.conf' },
      { t: 'Jan 15 12:09:08 rembrandt NetworkManager[432]: <info>  [1705313348.0000] device (eth0): state change: config -> ip-config (reason \'none\', sys-iface-state: \'managed\')' },
      { t: 'Jan 15 12:09:10 rembrandt dhclient[612]: DHCPREQUEST for 10.10.10.5 on eth0 to 255.255.255.255 port 67', cls: 'b' },
      { t: 'Jan 15 12:09:10 rembrandt dhclient[612]: DHCPACK of 10.10.10.5 from 10.10.10.1', cls: 'g' },
      { t: 'Jan 15 12:09:12 rembrandt sshd[591]: Server listening on 0.0.0.0 port 22.', cls: 'g' },
      { t: 'Jan 15 12:09:12 rembrandt sshd[591]: Server listening on :: port 22.' },
      { t: 'Jan 15 12:10:03 rembrandt gdm-launch-environment[811]: pam_unix(gdm-launch-environment:session): session opened for user gdm(uid=115) by (uid=0)' },
      { t: 'Jan 15 12:10:15 rembrandt sudo[1022]: pam_unix(sudo:auth): authentication failure; logname=rembrandt uid=1000 euid=0 tty=/dev/pts/0 ruser=rembrandt rhost=  user=rembrandt', cls: 'y' },
      { t: 'Jan 15 12:10:20 rembrandt sudo[1023]:     rembrandt : TTY=pts/0 ; PWD=/home/rembrandt ; USER=root ; COMMAND=/usr/bin/nmap -sn 10.10.10.0/24', cls: 'b' },
      { t: 'Jan 15 14:18:04 rembrandt sudo[1289]:     rembrandt : TTY=pts/0 ; PWD=/home/rembrandt ; USER=root ; COMMAND=/usr/bin/nmap -sV -sC 10.10.10.10', cls: 'b' },
      { t: 'Jan 15 14:22:31 rembrandt sudo[1421]:     rembrandt : TTY=pts/0 ; PWD=/home/rembrandt ; USER=root ; COMMAND=/usr/sbin/john hashes.kerberoast --wordlist=/usr/share/wordlists/rockyou.txt', cls: 'b' },
      { t: '-- No entries -- (use journalctl --no-pager for full output)', cls: 'd' },
    ],
  },

  // ── ss — improved with -tulpn support ────────────────────────────────────
  {
    match: c => /^ss\s.*(-t|-u|-l|-p|-n|tulpn|antp)/.test(c) || /^netstat\s.*(-t|-u|-l|-p|-n|tulpn)/.test(c),
    lines: [
      { t: 'Netid  State    Recv-Q  Send-Q  Local Address:Port     Peer Address:Port  Process', cls: 'b' },
      { t: 'tcp    LISTEN   0       128     0.0.0.0:22              0.0.0.0:*          users:(("sshd",pid=591,fd=3))', cls: 'g' },
      { t: 'tcp    LISTEN   0       128     127.0.0.1:631           0.0.0.0:*          users:(("cupsd",pid=798,fd=7))' },
      { t: 'tcp    LISTEN   0       5       127.0.0.53%lo:53        0.0.0.0:*          users:(("systemd-resolve",pid=412,fd=13))' },
      { t: 'tcp    ESTAB    0       0       10.10.10.5:51234        10.10.10.10:445    users:(("crackmapexec",pid=1201,fd=5))', cls: 'y' },
      { t: 'tcp6   LISTEN   0       128     [::]:22                 [::]:*             users:(("sshd",pid=591,fd=4))' },
      { t: 'udp    UNCONN   0       0       127.0.0.53%lo:53        0.0.0.0:*          users:(("systemd-resolve",pid=412,fd=12))' },
      { t: 'udp    UNCONN   0       0       0.0.0.0:68              0.0.0.0:*          users:(("dhclient",pid=612,fd=7))' },
    ],
  },

  // ── iptables ──────────────────────────────────────────────────────────────
  {
    match: c => /^iptables(\s|$)/.test(c),
    requireRoot: true,
    lines: [
      { t: 'Chain INPUT (policy ACCEPT)', cls: 'g' },
      { t: 'target     prot opt source               destination' },
      { t: '' },
      { t: 'Chain FORWARD (policy DROP)', cls: 'r' },
      { t: 'target     prot opt source               destination' },
      { t: '' },
      { t: 'Chain OUTPUT (policy ACCEPT)', cls: 'g' },
      { t: 'target     prot opt source               destination' },
    ],
  },

  // ── nft ───────────────────────────────────────────────────────────────────
  {
    match: c => /^nft(\s|$)/.test(c),
    requireRoot: true,
    lines: [
      { t: 'table inet filter {', cls: 'b' },
      { t: '\tchain input {' },
      { t: '\t\ttype filter hook input priority filter; policy accept;' },
      { t: '\t}' },
      { t: '\tchain forward {' },
      { t: '\t\ttype filter hook forward priority filter; policy drop;' },
      { t: '\t}' },
      { t: '\tchain output {' },
      { t: '\t\ttype filter hook output priority filter; policy accept;' },
      { t: '\t}' },
      { t: '}' },
    ],
  },

  // ── dig / nslookup ────────────────────────────────────────────────────────
  {
    match: c => /^dig(\s|$)/.test(c) || /^nslookup(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const isDig = cmd.startsWith('dig');
      const target = cmd.split(' ').filter(Boolean).slice(1).join(' ') || 'corp.local';
      if (isDig) return [
        `; <<>> DiG 9.18.19-1~deb12u1-Debian <<>> ${cmd.replace('dig ','').trim()}`,
        ';; global options: +cmd',
        ';; Got answer:',
        `;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ${Math.floor(Math.random()*60000)+1000}`,
        ';; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1',
        '',
        ';; QUESTION SECTION:',
        `;${target}.                       IN      A`,
        '',
        ';; ANSWER SECTION:',
        `${target}.              600     IN      A       10.10.10.10`,
        '',
        ';; Query time: 2 msec',
        `;; SERVER: 10.10.10.10#53(10.10.10.10) (UDP)`,
        `;; WHEN: ${new Date().toUTCString()}`,
        ';; MSG SIZE  rcvd: 55',
      ].join('\n');
      return [
        'Server:\t\t10.10.10.10',
        'Address:\t10.10.10.10#53',
        '',
        `Name:\t${target}`,
        'Address: 10.10.10.10',
      ].join('\n');
    }, cls: (cmd) => cmd.startsWith('dig') ? 'g' : ''}],
  },

  // ── traceroute / tracepath ────────────────────────────────────────────────
  {
    match: c => /^(traceroute|tracepath|mtr)(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const target = cmd.split(' ').filter(Boolean).slice(1).join(' ') || '10.10.10.10';
      return [
        `traceroute to ${target} (10.10.10.10), 30 hops max, 60 byte packets`,
        ` 1  10.10.10.1 (10.10.10.1)  0.412 ms  0.388 ms  0.374 ms`,
        ` 2  10.10.10.10 (10.10.10.10)  1.234 ms  1.198 ms  1.267 ms`,
      ].join('\n');
    }, cls: 'g'}],
  },

  // ── tcpdump ───────────────────────────────────────────────────────────────
  {
    match: c => /^tcpdump(\s|$)/.test(c),
    requireRoot: true,
    lines: [
      { t: () => `tcpdump: verbose output suppressed, use -v[v]... for full protocol decode\nlistening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes` },
      { t: () => `${new Date().toUTCString().slice(17,25)} IP 10.10.10.5.51234 > 10.10.10.10.445: Flags [S], seq 1234567890, win 64240, options [mss 1460,sackOK,TS val 1234567890 ecr 0,nop,wscale 7], length 0`, cls: 'g' },
      { t: () => `${new Date().toUTCString().slice(17,25)} IP 10.10.10.10.445 > 10.10.10.5.51234: Flags [S.], seq 987654321, ack 1234567891, win 65535, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0`, cls: 'b' },
      { t: () => `${new Date().toUTCString().slice(17,25)} IP 10.10.10.5.51234 > 10.10.10.10.445: Flags [.], ack 1, win 502, length 0` },
      { t: '' },
      { t: '3 packets captured' },
      { t: '3 packets received by filter' },
      { t: '0 packets dropped by kernel', cls: 'g' },
    ],
  },

  // ── dpkg ─────────────────────────────────────────────────────────────────
  {
    match: c => /^dpkg(\s|$)/.test(c) || /^apt\s+list/.test(c),
    lines: [{ t: (cmd) => {
      const pkgs = [
        ['adduser',            '3.134',                    'all',   'add and remove users and groups'],
        ['apt',               '2.7.6',                    'amd64', 'commandline package manager'],
        ['bash',              '5.2.21-2',                 'amd64', 'GNU Bourne Again SHell'],
        ['binutils',          '2.42',                     'amd64', 'GNU assembler, linker and binary utilities'],
        ['bzip2',             '1.0.8-5',                  'amd64', 'high-quality block-sorting file compressor'],
        ['crackmapexec',      '5.4.0-1rembrandt2',             'all',   'Network authentication attack tool'],
        ['curl',              '8.5.0-2',                  'amd64', 'command line tool for transferring data with URL syntax'],
        ['enum4linux',        '0.9.1-2rembrandt2',             'all',   'Windows/Samba enumeration tool'],
        ['ffuf',              '2.1.0-1rembrandt1',             'amd64', 'web fuzzer written in Go'],
        ['gcc',               '4:13.2.0-7',               'amd64', 'GNU C compiler'],
        ['gdb',               '14.1-2',                   'amd64', 'GNU Debugger'],
        ['git',               '1:2.43.0-1',               'amd64', 'fast, scalable, distributed revision control system'],
        ['gobuster',          '3.6.0-1rembrandt1',             'amd64', 'directory/vhost fuzzer in Go'],
        ['hashcat',           '6.2.6+ds1-1rembrandt2',         'amd64', 'World\'s fastest and most advanced password recovery utility'],
        ['hydra',             '9.5-1rembrandt1',               'amd64', 'very fast network log-on cracker'],
        ['impacket-scripts',  '0.11.0-1rembrandt3',            'all',   'Python network protocol library scripts'],
        ['john',              '1.9.0-jumbo-1+8.1rembrandt3',   'amd64', 'active password cracking tool'],
        ['kerbrute',          '1.0.3-0rembrandt1',             'amd64', 'fast Kerberos user enumeration tool'],
        ['rembrandt-linux-headless','2023.4.0',                 'all',   'Rembrandt Linux headless system'],
        ['nmap',              '7.94+git20230807.3be01efb1', 'amd64','The Network Mapper'],
        ['openssl',           '3.1.5-1',                  'amd64', 'Secure Sockets Layer toolkit - cryptographic utility'],
        ['python3',           '3.11.8-1',                 'amd64', 'interactive high-level object-oriented language'],
        ['python3-impacket',  '0.11.0-1rembrandt2',            'all',   'Python network protocol library'],
        ['ssh',               '1:9.6p1-3',                'amd64', 'secure shell client and server (metapackage)'],
        ['tcpdump',           '4.99.4-3',                 'amd64', 'command-line network traffic analyzer'],
        ['wget',              '1.21.4-1',                 'amd64', 'retrieves files from the web'],
        ['wireshark',         '4.2.2-1~rembrandt1',            'amd64', 'network traffic analyzer'],
        ['wordlists',         '2023.3.7',                 'all',   'Contains the rockyou.txt wordlist'],
      ];
      if (cmd.includes('apt list')) {
        return 'Listing... Done\n' + pkgs.map(([n,v,a]) => `${n}/${a} ${v} ${a} [installed]`).join('\n');
      }
      if (cmd.includes('-s') || cmd.includes('--status')) {
        const pkg = cmd.split(' ').pop();
        const p = pkgs.find(x => x[0] === pkg) || [pkg, '0.0.0', 'amd64', 'Package not found'];
        return `Package: ${p[0]}\nStatus: install ok installed\nPriority: optional\nSection: misc\nInstalled-Size: 4096\nMaintainer: Capy Developers <devel@rembrandt.org>\nArchitecture: ${p[2]}\nVersion: ${p[1]}\nDescription: ${p[3]}`;
      }
      const hdr = 'Desired=Unknown/Install/Remove/Purge/Hold\n| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n||/ Name                      Version                      Architecture Description\n+++-=========================-============================-============-====================================';
      return hdr + '\n' + pkgs.map(([n,v,a,d]) => `ii  ${n.padEnd(25)} ${v.padEnd(28)} ${a.padEnd(12)} ${d}`).join('\n');
    }}],
  },

  // ── stat ──────────────────────────────────────────────────────────────────
  {
    match: c => /^stat\s/.test(c),
    lines: [{ t: (cmd) => {
      const arg = cmd.replace(/^stat\s+/, '').trim();
      const name = arg.split('/').pop();
      const isDir = ['Desktop','Documents','Downloads','/','etc','home','root'].some(d => arg.includes(d) && !arg.includes('.'));
      if (isDir) return [
        `  File: ${arg}`,
        `  Size: 4096\t\tBlocks: 8\t IO Block: 4096   directory`,
        `Device: 8,1\tInode: 131073\t Links: 20`,
        `Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)`,
        `Access: 2024-01-15 12:10:33.000000000 -0500`,
        `Modify: 2024-01-15 12:09:01.000000000 -0500`,
        `Change: 2024-01-15 12:09:01.000000000 -0500`,
        ` Birth: 2024-01-10 08:00:00.000000000 -0500`,
      ].join('\n');
      const uid = isRoot() ? '0/    root' : '1000/    ' + SIM.user;
      return [
        `  File: ${name}`,
        `  Size: 248\t\tBlocks: 8\t IO Block: 4096   regular file`,
        `Device: 8,1\tInode: 1310722\t Links: 1`,
        `Access: (0644/-rw-r--r--)  Uid: (${uid})   Gid: (${uid})`,
        `Access: 2024-01-15 12:10:33.000000000 -0500`,
        `Modify: 2024-01-10 08:23:15.000000000 -0500`,
        `Change: 2024-01-10 08:23:15.000000000 -0500`,
        ` Birth: 2024-01-10 08:23:15.000000000 -0500`,
      ].join('\n');
    }}],
  },

  // ── file ─────────────────────────────────────────────────────────────────
  {
    match: c => /^file\s/.test(c),
    lines: [{ t: (cmd) => {
      const arg = cmd.replace(/^file\s+/, '').trim();
      if (arg.endsWith('.kerberoast') || arg.endsWith('.txt')) {
        return `${arg}: ASCII text`;
      }
      if (arg.endsWith('.py')) return `${arg}: Python script, ASCII text executable`;
      if (arg.endsWith('.sh')) return `${arg}: Bourne-Again shell script, ASCII text executable`;
      if (arg.endsWith('.dmp')) return `${arg}: Mini DuMP crash report, 64-bit, full memory`;
      if (arg.startsWith('/usr/bin/') || arg.startsWith('/bin/') || arg.startsWith('/sbin/')) {
        return `${arg}: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0, for GNU/Linux 3.2.0, stripped`;
      }
      return `${arg}: cannot open \`${arg}' (No such file or directory)`;
    }, cls: (cmd) => {
      const arg = cmd.replace(/^file\s+/, '').trim();
      return (arg.endsWith('.txt') || arg.endsWith('.kerberoast') || arg.startsWith('/usr/bin/')) ? 'g' : 'r';
    }}],
  },

  // ── wc ────────────────────────────────────────────────────────────────────
  {
    match: c => /^wc(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const arg = cmd.replace(/^wc\s*/, '').trim();
      if (arg.includes('rockyou')) return '14344392  14344392 139921507 /usr/share/wordlists/rockyou.txt';
      if (arg.includes('.kerberoast')) return '      3       3    3241 hashes.kerberoast';
      if (arg.includes('notes')) return '      5      22     248 notes.txt';
      if (arg.includes('-l')) {
        if (arg.includes('rockyou')) return '14344392 /usr/share/wordlists/rockyou.txt';
        return '5';
      }
      return `      5      22     248 ${arg.split(' ').pop()}`;
    }}],
  },

  // ── head ─────────────────────────────────────────────────────────────────
  {
    match: c => /^head(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const arg = cmd.replace(/^head\s+(-n\s*\d+\s+)?/, '').trim();
      const nMatch = cmd.match(/-n\s*(\d+)/);
      const n = nMatch ? parseInt(nMatch[1]) : 10;
      const files = { ...SIM.files };
      if (SIM.hashesOnDisk) files['/home/' + SIM.user + '/hashes.kerberoast'] = KRB5_HASHES;
      const abs = arg.startsWith('/') ? arg : SIM.cwd.replace(/\/?$/,'/') + arg;
      const content = files[abs] || files['/home/' + SIM.user + '/' + arg];
      if (content) return content.split('\n').slice(0, n).join('\n');
      return `head: cannot open '${arg}' for reading: No such file or directory`;
    }, cls: (cmd) => {
      const arg = cmd.replace(/^head\s+(-n\s*\d+\s+)?/, '').trim();
      const abs = arg.startsWith('/') ? arg : SIM.cwd.replace(/\/?$/,'/') + arg;
      const files = { ...SIM.files };
      if (SIM.hashesOnDisk) files['/home/' + SIM.user + '/hashes.kerberoast'] = KRB5_HASHES;
      return (files[abs] || files['/home/' + SIM.user + '/' + arg]) ? '' : 'r';
    }}],
  },

  // ── tail ─────────────────────────────────────────────────────────────────
  {
    match: c => /^tail(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const arg = cmd.replace(/^tail\s+(-n\s*\d+\s+|-f\s+)?/, '').trim();
      const nMatch = cmd.match(/-n\s*(\d+)/);
      const n = nMatch ? parseInt(nMatch[1]) : 10;
      const files = { ...SIM.files };
      if (SIM.hashesOnDisk) files['/home/' + SIM.user + '/hashes.kerberoast'] = KRB5_HASHES;
      const abs = arg.startsWith('/') ? arg : SIM.cwd.replace(/\/?$/,'/') + arg;
      const content = files[abs] || files['/home/' + SIM.user + '/' + arg];
      if (content) {
        const lines = content.split('\n');
        if (cmd.includes('-f')) return lines.slice(-n).join('\n') + '\n(tail: following - press Ctrl+C to stop)';
        return lines.slice(-n).join('\n');
      }
      return `tail: cannot open '${arg}' for reading: No such file or directory`;
    }, cls: 'g'}],
  },

  // ── md5sum / sha1sum / sha256sum / sha512sum ──────────────────────────────
  {
    match: c => /^(md5sum|sha1sum|sha256sum|sha512sum)\s/.test(c),
    lines: [{ t: (cmd) => {
      const tool = cmd.split(' ')[0];
      const arg  = cmd.replace(/^\S+\s+/, '').trim();
      const hashes = {
        'md5sum':    { 'notes.txt':'4b24ff9a7bea58d05f3b7a8ce35e1230', 'hashes.kerberoast':'9f3a8b2c1d4e5f6a7b8c9d0e1f2a3b4c' },
        'sha1sum':   { 'notes.txt':'a3f8d2c1b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9', 'hashes.kerberoast':'1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b' },
        'sha256sum': { 'notes.txt':'a3f8d2c1b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1', 'hashes.kerberoast':'b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6' },
        'sha512sum': { 'notes.txt':'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4', 'hashes.kerberoast':'b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3' },
      };
      const name = arg.split('/').pop();
      const h = hashes[tool]?.[name] || Array.from({length: tool === 'sha512sum' ? 128 : tool === 'sha256sum' ? 64 : tool === 'sha1sum' ? 40 : 32}, () => '0123456789abcdef'[Math.floor(Math.random()*16)]).join('');
      const exists = SIM.files['/home/' + SIM.user + '/' + name] || SIM.files['/root/'+name] || name === 'hashes.kerberoast';
      if (!exists) return `${tool}: ${arg}: No such file or directory`;
      return `${h}  ${arg}`;
    }, cls: 'g'}],
  },

  // ── base64 ────────────────────────────────────────────────────────────────
  {
    match: c => /^base64(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      if (cmd.includes('-d') || cmd.includes('--decode')) {
        const val = cmd.split(' ').pop();
        try { return atob(val); } catch { return `base64: invalid input`; }
      }
      const arg = cmd.replace(/^base64\s*/, '').trim();
      if (!arg) return `base64: extra operand`;
      const name = arg.split('/').pop();
      const content = SIM.files['/home/' + SIM.user + '/' + name] || SIM.files[arg] || 'Hello World';
      return btoa(content).match(/.{1,76}/g).join('\n');
    }}],
  },

  // ── xxd ───────────────────────────────────────────────────────────────────
  {
    match: c => /^xxd(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const arg = cmd.replace(/^xxd\s*/, '').trim();
      const name = arg.split('/').pop();
      const raw = SIM.files['/home/' + SIM.user + '/' + name] || SIM.files[arg] || '';
      if (!raw && arg) return `xxd: ${arg}: No such file or directory`;
      const src = raw || '# Notes - DO NOT SHARE\n';
      const bytes = src.slice(0, 128);
      const lines = [];
      for (let i = 0; i < bytes.length; i += 16) {
        const chunk = bytes.slice(i, i+16);
        const hex = Array.from(chunk).map(c => c.charCodeAt(0).toString(16).padStart(2,'0')).join(' ');
        const asc = Array.from(chunk).map(c => { const code = c.charCodeAt(0); return (code >= 32 && code < 127) ? c : '.'; }).join('');
        lines.push(`${i.toString(16).padStart(8,'0')}: ${hex.padEnd(47)}  ${asc}`);
      }
      return lines.join('\n');
    }, cls: 'g'}],
  },

  // ── strings ───────────────────────────────────────────────────────────────
  {
    match: c => /^strings(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const arg = cmd.replace(/^strings\s*/, '').trim();
      const name = arg.split('/').pop();
      const content = SIM.files['/home/' + SIM.user + '/' + name] || SIM.files[arg];
      if (content) return content.split('\n').filter(l => l.trim()).join('\n');
      if (arg.startsWith('/usr/bin/') || arg.startsWith('/bin/')) return [
        '/lib64/ld-linux-x86-64.so.2',
        'libcrypto.so.3',
        'libc.so.6',
        'GLIBC_2.34',
        '__gmon_start__',
        'Usage: ' + arg.split('/').pop() + ' [options]',
        'Copyright (C) 2024',
        'Compiled with GCC 13.2.0',
      ].join('\n');
      return `strings: Warning: could not locate '${arg}'.  reason: No such file`;
    }}],
  },

  // ── openssl ───────────────────────────────────────────────────────────────
  {
    match: c => /^openssl(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      if (cmd.includes('version')) return 'OpenSSL 3.1.5 30 Jan 2024 (Library: OpenSSL 3.1.5 30 Jan 2024)';
      if (cmd.includes('rand')) {
        const n = parseInt(cmd.match(/(\d+)/)?.[1] || '16');
        return Array.from({length:n}, () => Math.floor(Math.random()*256).toString(16).padStart(2,'0')).join('');
      }
      if (cmd.includes('genrsa') || cmd.includes('genpkey')) {
        return '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TSd39....\n[key truncated for display]\n-----END RSA PRIVATE KEY-----';
      }
      if (cmd.includes('s_client')) {
        const host = cmd.match(/(?:-connect\s+)?(\S+:\d+)/)?.[1] || '10.10.10.10:443';
        return `CONNECTED(00000003)\ndepth=0 CN = ${host.split(':')[0]}\nverify error:num=18:self-signed certificate\n---\nCertificate chain\n 0 s:CN = ${host.split(':')[0]}\n   i:CN = ${host.split(':')[0]}\n---\nSSL-Session:\n    Protocol  : TLSv1.3\n    Cipher    : TLS_AES_256_GCM_SHA384\n---`;
      }
      return 'openssl: Use openssl version, openssl rand <n>, openssl s_client -connect host:port';
    }}],
  },

  // ── gpg ───────────────────────────────────────────────────────────────────
  {
    match: c => /^gpg(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      if (cmd.includes('--version')) return 'gpg (GnuPG) 2.4.3\nlibgcrypt 1.10.2\nCopyright (C) 2023 g10 Code GmbH\nLicense GNU GPL-3.0-or-later <https://gnu.org/licenses/gpl.html>';
      if (cmd.includes('--list-keys') || cmd.includes('-k')) return `/home/${SIM.user}/.gnupg/pubring.kbx\n-----------------------------------\npub   rsa4096 2024-01-10 [SC]\n      A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0\nuid           [ultimate] Capy User <rembrandt@rembrandt.local>\nsub   rsa4096 2024-01-10 [E]`;
      if (cmd.includes('--encrypt') || cmd.includes('-e')) return 'gpg: ' + cmd.split(' ').pop() + '.gpg: encryption okay';
      if (cmd.includes('--decrypt') || cmd.includes('-d')) return 'gpg: AES256 encrypted data\ngpg: encrypted with 1 passphrase\n[decrypted content would appear here]';
      return 'gpg: no valid OpenPGP data found.';
    }}],
  },

  // ── ssh-keygen ────────────────────────────────────────────────────────────
  {
    match: c => /^ssh-keygen(\s|$)/.test(c),
    loadTime: () => jitter(400, 100),
    lines: [{ t: (cmd) => {
      if (cmd.includes('-l') || cmd.includes('--fingerprint')) {
        return `2048 SHA256:abc123def456xyz789 rembrandt@rembrandt (RSA)\n4096 SHA256:xyz789abc123def456 rembrandt@rembrandt (RSA)`;
      }
      const bits = cmd.match(/-b\s+(\d+)/)?.[1] || '4096';
      return [
        `Generating public/private ${cmd.includes('ed25519') ? 'ed25519' : 'rsa'} key pair.`,
        `Enter file in which to save the key (/home/${SIM.user}/.ssh/id_rsa): `,
        `Enter passphrase (empty for no passphrase): `,
        `Enter same passphrase again: `,
        `Your identification has been saved in /home/${SIM.user}/.ssh/id_rsa`,
        `Your public key has been saved in /home/${SIM.user}/.ssh/id_rsa.pub`,
        `The key fingerprint is:`,
        `SHA256:K1a2L3i4K5a6L7i8K9a0b1c2d3e4f5g6h7i8j9k0 ${SIM.user}@rembrandt`,
        `The key's randomart image is:`,
        `+---[RSA ${bits}]----+`,
        `|  .   .          |`,
        `|   + . .  .      |`,
        `|  . B o o =      |`,
        `| . + * = = .     |`,
        `|  . = O S . .    |`,
        `|   . = = o   .   |`,
        `|    . o   o o .  |`,
        `|     . . . + . . |`,
        `|          +.o.+  |`,
        `+----[SHA256]-----+`,
      ].join('\n');
    }, cls: 'g'}],
  },

  // ── kill / killall / pkill / pgrep ────────────────────────────────────────
  {
    match: c => /^(kill|killall|pkill|pgrep)(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const op = cmd.split(' ')[0];
      const target = cmd.split(' ').slice(1).join(' ').trim();
      if (!target) return `${op}: no process name specified`;
      if (op === 'pgrep') return `1234\n1338`;
      if (op === 'kill' && /^\d+$/.test(target)) {
        return parseInt(target) > 1500 ? `kill: (${target}): No such process` : '';
      }
      return '';
    }}],
  },

  // ── jobs / bg / fg ────────────────────────────────────────────────────────
  {
    match: c => /^(jobs|bg|fg)(\s|$)/.test(c),
    lines: [{ t: (cmd) => cmd === 'jobs' ? '' : `bash: ${cmd.split(' ')[0]}: current: no such job` }],
  },

  // ── strace ────────────────────────────────────────────────────────────────
  {
    match: c => /^strace(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const prog = cmd.replace(/^strace\s+/, '').split(' ')[0];
      return [
        `execve("/usr/bin/${prog}", ["${prog}"], 0x7fffd4a3b890 /* 28 vars */) = 0`,
        `brk(NULL)                               = 0x555555771000`,
        `arch_prctl(0x3001 /* ARCH_??? */, 0x7ffd7e4b3d50) = -1 EINVAL (Invalid argument)`,
        `access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)`,
        `openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3`,
        `fstat(3, {st_mode=S_IFREG|0644, st_size=25893, ...}) = 0`,
        `mmap(NULL, 25893, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f3a4b2c1000`,
        `close(3)                                = 0`,
        `openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3`,
        `--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=1339, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---`,
        `+++ exited with 0 +++`,
      ].join('\n');
    }, cls: 'd'}],
  },

  // ── seq ───────────────────────────────────────────────────────────────────
  {
    match: c => /^seq\s/.test(c),
    lines: [{ t: (cmd) => {
      const args = cmd.replace(/^seq\s+/,'').trim().split(/\s+/).map(Number);
      let start, step, end;
      if (args.length === 1) { start = 1; step = 1; end = args[0]; }
      else if (args.length === 2) { start = args[0]; step = 1; end = args[1]; }
      else { start = args[0]; step = args[1]; end = args[2]; }
      if (isNaN(end) || Math.abs((end - start) / step) > 100) return '(seq: too many values)';
      const out = [];
      for (let i = start; step > 0 ? i <= end : i >= end; i += step) out.push(i);
      return out.join('\n');
    }}],
  },

  // ── cal ───────────────────────────────────────────────────────────────────
  {
    match: c => /^(cal|ncal)(\s|$)/.test(c),
    lines: [{ t: () => {
      const now = new Date();
      const year = now.getFullYear();
      const month = now.getMonth();
      const monthNames = ['January','February','March','April','May','June','July','August','September','October','November','December'];
      const firstDay = new Date(year, month, 1).getDay();
      const daysInMonth = new Date(year, month+1, 0).getDate();
      const today = now.getDate();
      let out = `   ${monthNames[month]} ${year}\nSu Mo Tu We Th Fr Sa\n`;
      let day = 1;
      let line = ' '.repeat(firstDay * 3);
      for (let i = firstDay; i < 7; i++, day++) {
        line += (day === today ? `\x1b[7m${String(day).padStart(2)}\x1b[0m` : String(day).padStart(2)) + ' ';
      }
      out += line.trimEnd() + '\n';
      while (day <= daysInMonth) {
        line = '';
        for (let i = 0; i < 7 && day <= daysInMonth; i++, day++) {
          line += (day === today ? `\x1b[7m${String(day).padStart(2)}\x1b[0m` : String(day).padStart(2)) + ' ';
        }
        out += line.trimEnd() + '\n';
      }
      return out;
    }}],
  },

  // ── bc ────────────────────────────────────────────────────────────────────
  {
    match: c => /^bc(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const expr = cmd.replace(/^bc\s*(-l\s*)?/,'').trim();
      if (!expr) return 'bc 1.07.1 — An arbitrary precision calculator language\n(simulation: pass expression as argument, e.g. bc <<< "2^32")';
      try {
        // Very basic safe evaluation
        const safe = expr.replace(/[^0-9+\-*/().^% ]/g,'').replace(/\^/g,'**');
        const result = Function('"use strict"; return (' + safe + ')')();
        return String(result);
      } catch { return 'parse error'; }
    }}],
  },

  // ── factor ────────────────────────────────────────────────────────────────
  {
    match: c => /^factor(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const n = parseInt(cmd.replace(/^factor\s*/,'').trim());
      if (isNaN(n) || n < 1 || n > 1e9) return isNaN(n) ? '' : 'factor: `' + cmd.split(' ').pop() + '\': argument is not a natural number or too large';
      let num = n, factors = [];
      for (let f = 2; f * f <= num; f++) { while (num % f === 0) { factors.push(f); num /= f; } }
      if (num > 1) factors.push(num);
      return `${n}: ${factors.join(' ')}`;
    }}],
  },

  // ── sort / uniq ───────────────────────────────────────────────────────────
  {
    match: c => /^(sort|uniq)(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const arg = cmd.replace(/^\S+\s+(-\S+\s+)*/, '').trim();
      if (!arg) return '(reads from stdin — pipe or file required in simulation)';
      const name = arg.split('/').pop();
      const content = SIM.files['/home/' + SIM.user + '/' + name] || SIM.files[arg] || '';
      if (!content) return `sort: cannot read: ${arg}: No such file or directory`;
      const lines = content.split('\n').filter(Boolean);
      if (cmd.startsWith('uniq')) return [...new Set(lines)].join('\n');
      return [...lines].sort().join('\n');
    }}],
  },

  // ── cut ───────────────────────────────────────────────────────────────────
  {
    match: c => /^cut\s/.test(c),
    lines: [{ t: (cmd) => {
      const fMatch = cmd.match(/-f\s*(\d+)/);
      const dMatch = cmd.match(/-d\s*['"]?([^'"s\s])['"]?/);
      const f = fMatch ? parseInt(fMatch[1]) - 1 : 0;
      const d = dMatch ? dMatch[1] : '\t';
      const arg = cmd.split(' ').pop();
      const content = SIM.files['/home/' + SIM.user + '/' + arg.split('/').pop()] || '';
      if (!content) return `cut: ${arg}: No such file or directory`;
      return content.split('\n').map(l => l.split(d)[f] || '').filter(Boolean).join('\n');
    }}],
  },

  // ── awk ───────────────────────────────────────────────────────────────────
  {
    match: c => /^awk\s/.test(c),
    lines: [{ t: (cmd) => {
      if (cmd.includes('{print $')) {
        const fMatch = cmd.match(/\{print\s+\$(\d+)\}/);
        const f = fMatch ? parseInt(fMatch[1]) - 1 : 0;
        const fileArg = cmd.split(' ').pop();
        const content = SIM.files['/home/' + SIM.user + '/' + fileArg.split('/').pop()] || '';
        if (content) return content.split('\n').map(l => l.split(/\s+/)[f] || '').filter(Boolean).join('\n');
      }
      if (cmd.includes('NR')) return '5';
      return '(awk: complex patterns not simulated)';
    }}],
  },

  // ── sed ───────────────────────────────────────────────────────────────────
  {
    match: c => /^sed\s/.test(c),
    lines: [{ t: (cmd) => {
      const sMatch = cmd.match(/s\/([^\/]+)\/([^\/]*)\/g?/);
      if (!sMatch) return '(sed: expression not recognized)';
      const fileArg = cmd.split(' ').pop();
      const content = SIM.files['/home/' + SIM.user + '/' + fileArg.split('/').pop()] || '';
      if (!content) return `(reading stdin: pipe required in simulation)`;
      const re = new RegExp(sMatch[1], 'g');
      return content.replace(re, sMatch[2]);
    }}],
  },

  // ── tr ────────────────────────────────────────────────────────────────────
  {
    match: c => /^tr\s/.test(c),
    lines: [{ t: () => '(tr: pipe or stdin required in simulation)' }],
  },

  // ── diff ─────────────────────────────────────────────────────────────────
  {
    match: c => /^diff\s/.test(c),
    lines: [{ t: (cmd) => {
      const args = cmd.split(' ').slice(1);
      if (args[0] === args[1]) return '';
      return `--- ${args[0]}\n+++ ${args[1]}\n@@ -1,3 +1,3 @@\n-line 1 of ${args[0]}\n+line 1 of ${args[1]}`;
    }}],
  },

  // ── tee ───────────────────────────────────────────────────────────────────
  {
    match: c => /\|\s*tee\s+\S+/.test(c),
    lines: [{ t: (cmd) => {
      const outFile = cmd.match(/tee\s+(\S+)/)?.[1];
      return outFile ? `(output duplicated to ${outFile})` : '';
    }, cls: 'd'}],
  },

  // ── xargs ─────────────────────────────────────────────────────────────────
  {
    match: c => /\|\s*xargs\s+\S+/.test(c),
    lines: [{ t: () => '(xargs: executing against each item)' }],
  },

  // ── sleep ─────────────────────────────────────────────────────────────────
  {
    match: c => /^sleep\s/.test(c),
    loadTime: () => jitter(800, 200),
    lines: [{ t: () => '' }],
  },

  // ── yes ───────────────────────────────────────────────────────────────────
  {
    match: c => /^yes(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const val = cmd.replace(/^yes\s*/,'') || 'y';
      return Array(20).fill(val).join('\n') + '\n(^C to stop)';
    }, cls: 'd'}],
  },

  // ── printf ────────────────────────────────────────────────────────────────
  {
    match: c => /^printf\s/.test(c),
    lines: [{ t: (cmd) => cmd.replace(/^printf\s+/,'').replace(/^(['"])(.*)\1$/, '$2').replace(/\\n/g,'\n').replace(/\\t/g,'\t') }],
  },

  // ── alias ─────────────────────────────────────────────────────────────────
  {
    match: c => /^alias(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      if (cmd === 'alias') return [
        "alias cls='clear'",
        "alias grep='grep --color=auto'",
        "alias l='ls -CF'",
        "alias la='ls -A'",
        "alias ll='ls -alF'",
        "alias ls='ls --color=auto'",
        "alias python='python3'",
      ].join('\n');
      return '';  // silent success for setting aliases
    }}],
  },

  // ── type ─────────────────────────────────────────────────────────────────
  {
    match: c => /^type\s/.test(c),
    lines: [{ t: (cmd) => {
      const tool = cmd.replace(/^type\s+/, '').trim();
      const builtins = new Set(['cd','echo','exit','export','alias','type','pwd','history','jobs','bg','fg','source']);
      if (builtins.has(tool)) return `${tool} is a shell builtin`;
      const paths = { ls:'/usr/bin/ls', cat:'/usr/bin/cat', grep:'/usr/bin/grep', nmap:'/usr/bin/nmap', python3:'/usr/bin/python3', bash:'/usr/bin/bash', ssh:'/usr/bin/ssh', curl:'/usr/bin/curl', john:'/usr/sbin/john', hashcat:'/usr/bin/hashcat', crackmapexec:'/usr/bin/crackmapexec', enum4linux:'/usr/bin/enum4linux' };
      if (paths[tool]) return `${tool} is ${paths[tool]}`;
      return `${tool}: not found`;
    }, cls: (cmd) => {
      const t = cmd.replace(/^type\s+/,'').trim();
      return ['ls','cat','grep','nmap','bash','john','hashcat'].includes(t) ? 'g' : 'r';
    }}],
  },

  // ── export ────────────────────────────────────────────────────────────────
  {
    match: c => /^export(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      if (cmd === 'export') return [
        'declare -x HOME=("/home/" + SIM.user)',
        'declare -x LANG="en_US.UTF-8"',
        'declare -x LOGNAME="rembrandt"',
        'declare -x PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"',
        'declare -x PWD=("/home/" + SIM.user)',
        'declare -x SHELL="/bin/bash"',
        'declare -x TERM="xterm-256color"',
        `declare -x USER="${SIM.user}"`,
      ].join('\n');
      return '';  // silent
    }}],
  },

  // ── ulimit ────────────────────────────────────────────────────────────────
  {
    match: c => /^ulimit(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      if (cmd.includes('-a') || cmd === 'ulimit') return [
        'core file size          (blocks, -c) 0',
        'data seg size           (kbytes, -d) unlimited',
        'scheduling priority             (-e) 0',
        'file size               (blocks, -f) unlimited',
        'pending signals                 (-i) 62756',
        'max locked memory       (kbytes, -l) 8388608',
        'max memory size         (kbytes, -m) unlimited',
        'open files                      (-n) 1048576',
        'pipe size            (512 bytes, -p) 8',
        'POSIX message queues     (bytes, -q) 819200',
        'real-time priority              (-r) 0',
        'stack size              (kbytes, -s) 8192',
        'cpu time               (seconds, -t) unlimited',
        'max user processes              (-u) 62756',
        'virtual memory          (kbytes, -v) unlimited',
        'file locks                      (-x) unlimited',
      ].join('\n');
      if (cmd.includes('-n')) return '1048576';
      return 'unlimited';
    }}],
  },

  // ── mount ────────────────────────────────────────────────────────────────
  {
    match: c => c === 'mount' || /^mount\s+-l/.test(c),
    lines: [
      { t: 'sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)' },
      { t: 'proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)' },
      { t: 'devtmpfs on /dev type devtmpfs (rw,nosuid,size=4096k,nr_inodes=4096,mode=755)' },
      { t: '/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)', cls: 'g' },
      { t: 'tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)' },
      { t: 'tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=1630892k,mode=755)' },
      { t: '/dev/sda2 on /home type ext4 (rw,relatime)', cls: 'g' },
      { t: 'tmpfs on /tmp type tmpfs (rw,nosuid,nodev)' },
      { t: 'tmpfs on /run/user/1000 type tmpfs (rw,nosuid,nodev,relatime,size=1630888k,nr_inodes=407722,mode=700,uid=1000,gid=1000)' },
    ],
  },

  // ── neofetch ─────────────────────────────────────────────────────────────────
  {
    match: c => /^neofetch(\s|$)/.test(c),
    lines: [{ t: () => {
      const user = SIM.user;
      const host = 'rembrandt';
      const t = new Date();
      const upMins = 133;
      const upH = Math.floor(upMins / 60), upM = upMins % 60;
      return [
        ``,
        `        ##           ##        \x1b[1;32m${user}@${host}\x1b[0m`,
        `       ####         ####       \x1b[1;32m${'-'.repeat((user+'@'+host).length)}\x1b[0m`,
        `      ######       ######      \x1b[1;32mOS:\x1b[0m      Rembrandt GNU/Linux Rolling x86_64`,
        `     ########     ########     \x1b[1;32mHost:\x1b[0m    VMware Virtual Platform`,
        `    ##########   ##########    \x1b[1;32mKernel:\x1b[0m  6.6.9-amd64`,
        `   ############ ############  \x1b[1;32mUptime:\x1b[0m  ${upH} hours, ${upM} mins`,
        `  ##########################  \x1b[1;32mShell:\x1b[0m   bash 5.2.21`,
        `  ##########################  \x1b[1;32mCPU:\x1b[0m     Intel i7-10700K (4) @ 3.800GHz`,
        `  ##########################  \x1b[1;32mGPU:\x1b[0m     VMware SVGA II Adapter`,
        `  ##########################  \x1b[1;32mMemory:\x1b[0m  2845MiB / 8192MiB`,
        `   ########################   \x1b[1;32mDisk:\x1b[0m    18G / 50G (38%)`,
        `    ######################    \x1b[1;32mLocalIP:\x1b[0m 10.10.10.5`,
        `     ####################     `,
        ``,
      ].join('\n');
    }, cls: 'g' }],
  },

  // ── cowsay ───────────────────────────────────────────────────────────────
  {
    match: c => /^cowsay(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const msg = cmd.replace(/^cowsay\s*/,'').trim() || 'moo';
      const line = '-'.repeat(msg.length + 2);
      return [
        ` ${line}`,
        `< ${msg} >`,
        ` ${line}`,
        '        \\   ^__^',
        '         \\  (oo)\\_______',
        '            (__)\\       )\\/\\',
        '                ||----w |',
        '                ||     ||',
      ].join('\n');
    }, cls: 'g'}],
  },

  // ── fortune ───────────────────────────────────────────────────────────────
  {
    match: c => /^fortune(\s|$)/.test(c),
    lines: [{ t: () => {
      const fortunes = [
        'Security is a process, not a product.\n\t-- Bruce Schneier',
        'The only truly secure system is one that is powered off, cast in a block of concrete and sealed in a lead-lined room with armed guards.\n\t-- Gene Spafford',
        'Hackers are breaking the systems for profit. Before, it was about intellectual curiosity and pursuit of knowledge and thrill, and now hacking is big business.\n\t-- Kevin Mitnick',
        'There are two types of companies: those that have been hacked, and those who don\'t know they have been hacked.\n\t-- John Chambers',
        'Kerberoasting: because any domain user can request TGS tickets, and humans pick terrible passwords.',
        'The quieter you become, the more you are able to hear... the LDAP queries.',
        'rm -rf / : because sometimes you need to start over.',
        'There\'s no patch for human stupidity.\n\t-- (unknown)',
        'Never underestimate the bandwidth of a station wagon full of tapes hurtling down the highway.\n\t-- Andrew Tanenbaum',
      ];
      return fortunes[Math.floor(Math.random() * fortunes.length)];
    }, cls: 'y'}],
  },

  // ── sl (steam locomotive Easter egg) ─────────────────────────────────────
  {
    match: c => c === 'sl' || c === 'sl -al',
    lines: [
      { t: '                      (  ) (@@) ( )  (@)  ()    @@    O     @     O     @      O' },
      { t: '               (@@@)' },
      { t: '           (    )' },
      { t: '        (@@@@)' },
      { t: '     (   )' },
      { t: '                   |\\      _,,,---,,_' },
      { t: "                   /,`.-'`'    -.  ;-;;,_" },
      { t: '                  |,4-  ) )-,_..;\\ (  `\'-\'' },
      { t: "                 '---''(_/--'  `-'\\_)" },
      { t: '' },
      { t: '   ====        ________                ___________', cls: 'y' },
      { t: '  _D _|  |_______/        \\__I_I_____===__|_________|', cls: 'y' },
      { t: '   |(_)---  |   H\\________/ |   |        =|___ ___|', cls: 'y' },
      { t: '   /     |  |   H  |  |     |   |         ||_| |_||', cls: 'y' },
      { t: '  |      |  |   H  |__--------------------| [___] |', cls: 'y' },
      { t: '  | ________|___H__/__|_____/[][]~\\_______|       |', cls: 'y' },
      { t: '  |/ |   |-----------I_____I [][] []  D   |=======|--', cls: 'y' },
      { t: '__/ =| o |=-~~\\  /~~\\  /~~\\  /~~\\ ____Y___________|__', cls: 'r' },
      { t: ' |/-=|___|=   O=====O=====O=====O|_____/~\\___/        ', cls: 'r' },
      { t: '  \\_/      \\__/  \\__/  \\__/  \\__/      \\_/            ', cls: 'r' },
      { t: '' },
      { t: 'sl: command not found — but you found the Easter egg!', cls: 'd' },
    ],
  },

);

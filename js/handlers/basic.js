'use strict';

HANDLERS.push(
  // ── Basic system ──────────────────────────────────────────────────────────
  {
    match: c => c === 'whoami',
    lines: [{ t: () => SIM.user }],
  },
  {
    match: c => c === 'id',
    lines: [{ t: () => isRoot()
      ? 'uid=0(root) gid=0(root) groups=0(root)'
      : 'uid=1000(rembrandt) gid=1000(rembrandt) groups=1000(rembrandt),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),119(wireshark),142(kaboxer)' }],
  },
  {
    match: c => c === 'hostname',
    lines: [{ t: 'rembrandt' }],
  },
  {
    match: c => c.startsWith('uname'),
    lines: [{ t: 'Linux rembrandt 6.6.9-amd64 #1 SMP PREEMPT_DYNAMIC Rembrandt 6.6.9-1rembrandt1 (2024-01-08) x86_64 GNU/Linux' }],
  },
  {
    match: c => c === 'pwd',
    lines: [{ t: () => SIM.cwd }],
  },
  {
    match: c => c === 'date',
    lines: [{ t: () => new Date().toString() }],
  },
  {
    match: c => c === 'uptime',
    lines: [{ t: ' 14:23:01 up 2:11,  1 user,  load average: 0.12, 0.08, 0.05' }],
  },
  {
    match: c => c === 'env' || c === 'printenv',
    lines: [
      { t: 'SHELL=/bin/bash' },
      { t: () => `USER=${SIM.user}` },
      { t: () => `HOME=${isRoot() ? '/root' : ('/home/' + SIM.user)}` },
      { t: 'TERM=xterm-256color' },
      { t: 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' },
      { t: 'LANG=en_US.UTF-8' },
    ],
  },
  {
    match: c => c === 'history',
    lines: [{ t: () => ({ history: true }) }],
  },

  // ── ls ────────────────────────────────────────────────────────────────────
  {
    match: c => /^ls(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const showHidden = cmd.includes('-a') || cmd.includes('-la') || cmd.includes('-al');
      const longFmt    = cmd.includes('-l') || cmd.includes('-la') || cmd.includes('-al');
      const home = isRoot() ? '/root' : ('/home/' + SIM.user);
      const cwd  = SIM.cwd;

      // dirs: set of names that are directories
      let dirs    = new Set();
      let files   = [];
      let dotDirs = [];
      let dotFiles = [];

      if (cwd === ('/home/' + SIM.user)) {
        dirs  = new Set(['Desktop','Documents','Downloads','Music','Pictures','Public','Templates','Videos']);
        files = ['notes.txt'];
        if (SIM.hashesOnDisk) files.push('hashes.kerberoast');
        dotDirs  = ['.config', '.local', '.ssh', '.msf4'];
        dotFiles = ['.bash_history', '.bash_logout', '.bashrc', '.profile', '.zshrc'];
      } else if (cwd.startsWith('/home/') && cwd.split('/').length === 3 && !cwd.endsWith('/')) {
        // root visiting another user's home — /home/<user>
        dirs  = new Set(['Desktop','Documents','Downloads','Music','Pictures','Public','Templates','Videos']);
        files = ['notes.txt'];
        dotDirs  = ['.config', '.local', '.ssh', '.msf4'];
        dotFiles = ['.bash_history', '.bash_logout', '.bashrc', '.profile', '.zshrc'];
      } else if (cwd.startsWith('/home/') && cwd.split('/').length === 4 && !cwd.endsWith('/')) {
        // root visiting a subdir of another user's home
        const sub = cwd.split('/')[3];
        if (sub === 'Desktop') { dirs = new Set([]); files = ['README.txt','lab_notes.txt','target_list.txt']; }
        else if (sub === 'Documents') { dirs = new Set(['reports','tools','certs']); files = ['credentials.txt','network_notes.md','todo.txt']; }
        else if (sub === 'Downloads') { dirs = new Set([]); files = ['linpeas.sh','winpeas.exe','mimikatz.zip','pspy64','chisel','socat']; }
        else if (sub === 'Music') { dirs = new Set([]); files = ['playlist.m3u','lo-fi-hacking.mp3','synthwave_mix.mp3']; }
        else if (sub === 'Pictures') { dirs = new Set(['screenshots','wallpapers']); files = ['network_diagram.png','corp_topology.png']; }
        else if (sub === 'Templates') { dirs = new Set([]); files = ['pentest_report_template.md','bug_bounty_template.md']; }
        else if (sub === 'Videos') { dirs = new Set([]); files = ['htb_walkthrough.mp4','tcm_course_notes.txt']; }
        else if (['Public'].includes(sub)) { dirs = new Set([]); files = []; }
        else if (sub === '.ssh') { dirs = new Set([]); files = ['known_hosts']; dotFiles = ['id_rsa','id_rsa.pub']; }
        else if (sub === '.config') { dirs = new Set(['xfce4','gtk-3.0','pulse']); files = []; }
        else if (sub === '.local') { dirs = new Set(['share','bin']); files = []; }
        else if (sub === '.msf4') { dirs = new Set(['logs','loot','modules','plugins']); files = ['history']; }
      } else if (cwd === ('/home/' + SIM.user + '/Desktop')) {
        dirs = new Set([]); files = ['README.txt','lab_notes.txt','target_list.txt'];
      } else if (cwd === ('/home/' + SIM.user + '/Documents')) {
        dirs = new Set(['reports','tools','certs']); files = ['credentials.txt','network_notes.md','todo.txt'];
      } else if (cwd.startsWith('/home/') && cwd.endsWith('/Downloads')) {
        dirs = new Set([]); files = ['linpeas.sh','winpeas.exe','mimikatz.zip','pspy64','chisel','socat','ncat'];
      } else if (cwd === ('/home/' + SIM.user + '/Music')) {
        dirs = new Set([]); files = ['playlist.m3u','lo-fi-hacking.mp3','synthwave_mix.mp3'];
      } else if (cwd === ('/home/' + SIM.user + '/Pictures')) {
        dirs = new Set(['screenshots','wallpapers']); files = ['network_diagram.png','corp_topology.png'];
      } else if (cwd === ('/home/' + SIM.user + '/Public')) {
        dirs = new Set([]); files = [];
      } else if (cwd === ('/home/' + SIM.user + '/Templates')) {
        dirs = new Set([]); files = ['pentest_report_template.md','bug_bounty_template.md'];
      } else if (cwd === ('/home/' + SIM.user + '/Videos')) {
        dirs = new Set([]); files = ['htb_walkthrough.mp4','tcm_course_notes.txt'];
      } else if (cwd === ('/home/' + SIM.user + '/Documents/reports')) {
        dirs = new Set([]); files = ['pentest_report_draft.md','scope.txt','findings_summary.xlsx','executive_summary.docx'];
      } else if (cwd === ('/home/' + SIM.user + '/Documents/tools')) {
        dirs = new Set([]); files = ['nmap_cheatsheet.txt','ad_attack_notes.txt','rev_shell_oneliners.txt','payload_list.txt'];
      } else if (cwd === ('/home/' + SIM.user + '/Documents/certs')) {
        dirs = new Set([]); files = ['oscp_notes.md','ceh_study_guide.pdf','thm_progress.txt'];
      } else if (cwd === ('/home/' + SIM.user + '/.ssh')) {
        dirs = new Set([]); files = ['known_hosts']; dotFiles = ['id_rsa','id_rsa.pub'];
      } else if (cwd === ('/home/' + SIM.user + '/.config')) {
        dirs = new Set(['xfce4','gtk-3.0','pulse']); files = [];
      } else if (cwd === ('/home/' + SIM.user + '/.local')) {
        dirs = new Set(['share','bin']); files = [];
      } else if (cwd === ('/home/' + SIM.user + '/.msf4')) {
        dirs = new Set(['logs','loot','modules','plugins']); files = ['history'];
      } else if (cwd === '/root') {
        dirs     = new Set(['Desktop','Documents','Downloads','Music','Pictures','Public','Templates','Videos']);
        files    = [];
        if (SIM.hashesOnDisk) files.push('hashes.kerberoast');
        dotDirs  = ['.cache','.config','.local','.msf4','.ssh'];
        dotFiles = ['.bash_history','.bash_logout','.bashrc','.profile','.zshrc'];
      } else if (cwd === '/root/Desktop') {
        dirs = new Set([]); files = ['flag.txt','credentials_dump.txt','network_map.png'];
      } else if (cwd === '/root/Documents') {
        dirs = new Set(['engagements','tools']); files = ['loot.txt','master_credentials.txt','client_list.txt'];
      } else if (cwd === '/root/Downloads') {
        dirs = new Set([]); files = ['linpeas.sh','chisel','pspy64','socat','nc','bloodhound.zip'];
      } else if (cwd === '/root/.ssh') {
        dirs = new Set([]); files = ['known_hosts','authorized_keys','id_rsa','id_rsa.pub'];
      } else if (cwd === '/') {
        dirs  = new Set(['bin','boot','dev','etc','home','lib','lib64','media','mnt','opt','proc','root','run','sbin','srv','sys','tmp','usr','var']);
        files = [];
      } else if (cwd === '/etc') {
        dirs  = new Set(['apt','cron.d','cron.daily','cron.weekly','default','init.d','ld.so.conf.d','logrotate.d','network','pam.d','security','ssl','ssh','systemd','udev','X11']);
        files = ['bash.bashrc','crontab','environment','fstab','group','gshadow','hostname','hosts','hosts.allow','hosts.deny','issue','issue.net','locale.gen','localtime','login.defs','motd','mtab','nsswitch.conf','os-release','passwd','profile','protocols','resolv.conf','services','shadow','shells','sudoers','sysctl.conf','timezone'];
      } else if (cwd === '/etc/ssh') {
        dirs = new Set([]); files = ['ssh_config','sshd_config','ssh_host_ecdsa_key.pub','ssh_host_ed25519_key.pub','ssh_host_rsa_key.pub'];
      } else if (cwd === '/etc/apt') {
        dirs = new Set(['sources.list.d','trusted.gpg.d','preferences.d']); files = ['sources.list'];
      } else if (cwd === '/etc/systemd') {
        dirs = new Set(['system','user','network','resolved.conf.d']); files = ['journald.conf','logind.conf','resolved.conf','system.conf','timesyncd.conf','user.conf'];
      } else if (cwd === '/etc/ssl') {
        dirs = new Set(['certs','private']); files = ['openssl.cnf'];
      } else if (cwd === '/etc/pam.d') {
        dirs = new Set([]); files = ['common-auth','common-account','common-password','common-session','login','sshd','sudo','su'];
      } else if (cwd === '/home') {
        const registeredUser = localStorage.getItem('hacklet_user') || SIM.user;
        dirs  = new Set([registeredUser]);
        files = [];
      } else if (cwd === '/tmp') {
        dirs  = new Set(['systemd-private-abc123','snap-private-tmp','vmware-root']);
        files = ['sysinfo.txt','linpeas_output.txt','privesc_check.sh','exploit.py'];
        // Append any files written into /tmp at runtime (e.g. exfiltrated dumps)
        for (const k of Object.keys(SIM.files)) {
          if (k.startsWith('/tmp/') && k.indexOf('/', 5) === -1) {
            const name = k.slice(5);
            if (!files.includes(name)) files.push(name);
          }
        }
        dotFiles = ['.font-unix', '.ICE-unix', '.X11-unix'];
      } else if (cwd === '/opt') {
        dirs = new Set(['metasploit-framework','impacket','crackmapexec','kerbrute','chisel']); files = [];
      } else if (cwd === '/opt/metasploit-framework') {
        dirs = new Set(['bin','data','modules','plugins','scripts','tools']); files = ['README.md','LICENSE'];
      } else if (cwd === '/opt/impacket') {
        dirs = new Set(['impacket','examples','build']); files = ['README.md','setup.py'];
      } else if (cwd === '/proc') {
        dirs = new Set(['1','2','432','591','623','1234']); files = ['cpuinfo','meminfo','version','uptime','loadavg','mounts','net'];
      } else if (cwd === '/proc/net') {
        dirs = new Set([]); files = ['arp','dev','if_inet6','route','tcp','tcp6','udp','udp6'];
      } else if (cwd === '/dev') {
        dirs = new Set(['block','bus','char','disk','input','mapper','net','pts','shm','snd']); files = ['console','full','kmsg','mem','null','ptmx','random','sda','sda1','sda2','stderr','stdin','stdout','tty','urandom','zero'];
      } else if (cwd === '/sys') {
        dirs = new Set(['block','bus','class','dev','devices','firmware','fs','kernel','module','power']); files = [];
      } else if (cwd === '/run') {
        dirs = new Set(['lock','log','mount','network','sshd','systemd','udev','user']); files = ['motd.dynamic','utmp'];
      } else if (cwd === '/media') {
        dirs = new Set([SIM.user]); files = [];
      } else if (cwd === '/mnt') {
        dirs = new Set([]); files = [];
      } else if (cwd === '/srv') {
        dirs = new Set(['http','ftp']); files = [];
      } else if (cwd === '/boot') {
        dirs = new Set(['grub','efi']); files = ['config-6.6.9-amd64','initrd.img-6.6.9-amd64','System.map-6.6.9-amd64','vmlinuz-6.6.9-amd64'];
      } else if (cwd === '/lib' || cwd === '/lib64') {
        dirs = new Set(['firmware','modules','systemd','udev','x86_64-linux-gnu']); files = [];
      } else if (cwd === '/sbin' || cwd === '/bin') {
        dirs = new Set([]); files = ['bash','cat','chmod','chown','cp','date','df','echo','find','grep','gzip','hostname','id','ip','kill','ln','ls','mkdir','mount','mv','netstat','ping','ps','rm','sed','sh','ss','su','tar','touch','uname','which'];
      } else if (cwd === '/usr') {
        dirs = new Set(['bin','include','lib','lib32','lib64','libexec','local','sbin','share','src']); files = [];
      } else if (cwd === '/usr/bin') {
        dirs = new Set([]); files = ['awk','base64','crackmapexec','curl','cut','diff','dig','dpkg','enum4linux','env','file','gobuster','gpg','hashcat','head','htop','hydra','impacket-GetUserSPNs','impacket-psexec','impacket-secretsdump','john','kerbrute','less','md5sum','more','nano','netcat','nmap','openssl','perl','python3','python3.11','sha256sum','sort','ssh','ssh-keygen','strace','strings','tail','tcpdump','top','traceroute','uniq','vim','wc','wget','whoami','xxd'];
      } else if (cwd === '/usr/sbin') {
        dirs = new Set([]); files = ['adduser','apache2','cron','deluser','dmidecode','groupadd','groupdel','iptables','nft','sshd','tcpdump','useradd','userdel','usermod'];
      } else if (cwd === '/usr/local') {
        dirs = new Set(['bin','etc','include','lib','sbin','share','src']); files = [];
      } else if (cwd.startsWith('/usr/share/wordlists')) {
        dirs  = new Set(['dirb','dirbuster','metasploit','nmap','wfuzz']);
        files = ['fasttrack.txt','rockyou.txt'];
      } else if (cwd === '/usr/share/metasploit-framework') {
        dirs = new Set(['data','documentation','lib','modules','plugins','scripts','tools']); files = ['README.md'];
      } else if (cwd === '/usr/share/nmap') {
        dirs = new Set(['nselib','scripts']); files = ['nmap-mac-prefixes','nmap-os-db','nmap-payloads','nmap-protocols','nmap-rpc','nmap-service-probes','nmap-services'];
      } else if (cwd.startsWith('/usr/share')) {
        dirs = new Set(['applications','doc','fonts','icons','man','metasploit-framework','nmap','wordlists','zsh']); files = [];
      } else if (cwd === '/var/log') {
        dirs = new Set(['apt','journal','nginx']); files = ['auth.log','bootstrap.log','daemon.log','dpkg.log','faillog','kern.log','lastlog','messages','syslog','wtmp'];
      } else if (cwd === '/var/log/apt') {
        dirs = new Set([]); files = ['history.log','term.log'];
      } else if (cwd === '/var/lib') {
        dirs = new Set(['apt','dpkg','misc','NetworkManager','systemd','udev']); files = [];
      } else if (cwd === '/var/cache') {
        dirs = new Set(['apt','debconf','ldconfig','man']); files = [];
      } else if (cwd.startsWith('/var')) {
        dirs  = new Set(['backups','cache','lib','lock','log','mail','opt','run','spool','tmp']); files = [];
      } else {
        dirs = new Set([]); files = [];
      }

      // Merge in any dirs/files created at runtime (mkdir/touch)
      const cwdSlash = cwd === '/' ? '/' : cwd + '/';
      for (const d of SIM.dirs) {
        if (d.startsWith(cwdSlash) && !d.slice(cwdSlash.length).includes('/')) {
          dirs.add(d.slice(cwdSlash.length));
        }
      }
      for (const f of Object.keys(SIM.files)) {
        if (f.startsWith(cwdSlash) && !f.slice(cwdSlash.length).includes('/')) {
          const name = f.slice(cwdSlash.length);
          if (!files.includes(name)) files.push(name);
        }
      }

      // Build display list
      const allDirs  = [...dirs].sort();
      const allFiles = [...files].sort();
      let entries = [...allDirs, ...allFiles];
      let dotEntries = [...dotDirs.sort(), ...dotFiles.sort()];

      if (!longFmt) {
        let out = [];
        if (showHidden) out.push('. ', '.. ', ...dotEntries.map(e => e + (dotDirs.includes(e) ? '/' : '')));
        out.push(...allDirs.map(d => d + '/'), ...allFiles);
        // remove trailing slashes for display and colour dirs — just return plain for simplicity
        return out.map(e => e.replace(/\/$/, '')).join('  ') || '';
      }

      // Long format
      const now = 'Jan 15 14:23';
      const owner = SIM.user;
      const fmt = (name, isDir, sz, perm) => {
        const p = perm || (isDir ? 'drwxr-xr-x' : '-rw-r--r--');
        const s = String(sz || (isDir ? 4096 : 248)).padStart(8);
        return `${p}  1 ${owner} ${owner} ${s} ${now} ${name}`;
      };

      const lines = [];
      if (showHidden) {
        lines.push(fmt('.', true, 4096, 'drwxr-xr-x'));
        lines.push(fmt('..', true, 4096, 'drwxr-xr-x'));
        dotDirs.forEach(d  => lines.push(fmt(d, true)));
        dotFiles.forEach(f => lines.push(fmt(f, false, f === '.bash_history' ? 1423 : 220, '-rw-------')));
      }
      allDirs.forEach(d  => lines.push(fmt(d, true)));
      allFiles.forEach(f => {
        const sz = f.endsWith('.kerberoast') ? 3241 : f === 'rockyou.txt' ? 139921507 : 248;
        lines.push(fmt(f, false, sz));
      });
      return lines.join('\n') || '';
    }}],
  },

  // ── cat ───────────────────────────────────────────────────────────────────
  {
    match: c => /^cat\s/.test(c),
    lines: [{ t: (cmd) => {
      const arg = cmd.replace(/^cat\s+/, '').trim();
      const abs = arg.startsWith('/') ? arg : SIM.cwd.replace(/\/?$/, '/') + arg;
      // Privilege-gated paths
      if (!isRoot() && (abs === '/etc/shadow' || abs.startsWith('/root') || abs === '/etc/sudoers' || abs === '/etc/gshadow')) {
        return `cat: ${arg}: Permission denied`;
      }
      const files = simFiles();
      const content = files[abs] || files[arg];
      if (content !== undefined) return content;
      return `cat: ${arg}: No such file or directory`;
    }, cls: (cmd) => {
      const arg = cmd.replace(/^cat\s+/, '').trim();
      const abs = arg.startsWith('/') ? arg : SIM.cwd.replace(/\/?$/, '/') + arg;
      if (!isRoot() && (abs === '/etc/shadow' || abs.startsWith('/root') || abs === '/etc/sudoers' || abs === '/etc/gshadow')) return 'r';
      const files = simFiles();
      return (files[abs] || files[arg]) !== undefined ? '' : 'r';
    }}],
    event: (cmd) => cmd.includes('notes') ? 'cat-notes' : null,
  },

  // ── cd ────────────────────────────────────────────────────────────────────
  {
    match: c => /^cd(\s|$)/.test(c),
    lines: [{ t: (cmd) => {
      const home = isRoot() ? '/root' : ('/home/' + SIM.user);
      let arg = cmd.replace(/^cd\s*/, '').trim() || home;
      if (arg === '~') arg = home;
      else if (arg.startsWith('~/')) arg = home + arg.slice(1);
      if (arg !== '/') arg = arg.replace(/\/+$/, '');
      let target;
      if (!arg || arg === home) target = home;
      else if (arg === '..') target = SIM.cwd.split('/').slice(0, -1).join('/') || '/';
      else if (arg === '-') target = home;
      else if (arg.startsWith('/')) target = arg;
      else target = (SIM.cwd === '/' ? '' : SIM.cwd) + '/' + arg;
      if (!isRoot() && (target === '/root' || target.startsWith('/root/'))) {
        return `bash: cd: ${arg}: Permission denied`;
      }
      // Case-sensitive existence check against known paths
      const knownPaths = new Set([
        '/', '/home', '/root', '/etc', '/etc/ssh', '/etc/apt', '/etc/systemd', '/etc/ssl', '/etc/pam.d',
        '/tmp', '/opt', '/opt/metasploit-framework', '/opt/impacket', '/proc', '/proc/net',
        '/dev', '/sys', '/run', '/media', '/mnt', '/srv', '/boot', '/lib', '/lib64',
        '/sbin', '/bin', '/usr', '/usr/bin', '/usr/sbin', '/usr/local', '/usr/share',
        '/usr/share/wordlists', '/usr/share/metasploit-framework', '/usr/share/nmap',
        '/var', '/var/log', '/var/log/apt', '/var/lib', '/var/cache',
        '/home/' + SIM.user,
        '/home/' + SIM.user + '/Desktop', '/home/' + SIM.user + '/Documents',
        '/home/' + SIM.user + '/Downloads', '/home/' + SIM.user + '/Music',
        '/home/' + SIM.user + '/Pictures', '/home/' + SIM.user + '/Public',
        '/home/' + SIM.user + '/Templates', '/home/' + SIM.user + '/Videos',
        '/home/' + SIM.user + '/.ssh', '/home/' + SIM.user + '/.config',
        '/home/' + SIM.user + '/.local', '/home/' + SIM.user + '/.msf4',
        '/home/' + SIM.user + '/Documents/reports', '/home/' + SIM.user + '/Documents/tools',
        '/home/' + SIM.user + '/Documents/certs',
        '/home/' + SIM.user + '/Music', '/home/' + SIM.user + '/Pictures',
        '/home/' + SIM.user + '/Pictures/screenshots', '/home/' + SIM.user + '/Pictures/wallpapers',
        '/home/' + SIM.user + '/Public', '/home/' + SIM.user + '/Templates', '/home/' + SIM.user + '/Videos',
        '/root', '/root/Desktop', '/root/Documents', '/root/Documents/engagements', '/root/Documents/tools',
        '/root/Downloads', '/root/.ssh', '/root/.config', '/root/.msf4',
      ]);
      // Also allow any path that exists in SIM.dirs or SIM.files
      const existsInSim = SIM.dirs.has(target) || Object.keys(simFiles()).some(f => f.startsWith(target + '/'));
      if (!knownPaths.has(target) && !existsInSim) {
        return `bash: cd: ${arg}: No such file or directory`;
      }
      SIM.cwd = target;
      return '';
    }, cls: '' }],
  },

  // ── rm -rf / easter egg ──────────────────────────────────────────────────────────────────────────
  {
    match: c => /^(sudo\s+)?rm\s+.*-[a-z]*r[a-z]*f[a-z]*\s+\/\*?$/.test(c) || /^(sudo\s+)?rm\s+.*-[a-z]*f[a-z]*r[a-z]*\s+\/\*?$/.test(c),
    stepLines: [
      { t: 'rm: it is dangerous to operate recursively on \'/\'', cls: 'r', delay: 0 },
      { t: 'rm: use --no-preserve-root to override this failsafe', cls: 'r', delay: 400 },
    ],
    lines: [],
    after: () => {},
  },
  {
    match: c => /^(sudo\s+)?rm\s+.*--no-preserve-root.*-[a-z]*r[a-z]*f[a-z]*\s+\/\*?$/.test(c) || /^(sudo\s+)?rm\s+.*-[a-z]*r[a-z]*f[a-z]*.*--no-preserve-root\s+\/\*?$/.test(c),
    stepLines: [
      { t: '', delay: 0 },
      // /proc errors flood first
      { t: "rm: cannot remove '/proc/1/fd/0': Operation not permitted", cls: 'r', delay: 30 },
      { t: "rm: cannot remove '/proc/1/fd/1': Operation not permitted", cls: 'r', delay: 25 },
      { t: "rm: cannot remove '/proc/1/fd/2': Operation not permitted", cls: 'r', delay: 20 },
      { t: "rm: cannot remove '/proc/1/maps': Operation not permitted", cls: 'r', delay: 20 },
      { t: "rm: cannot remove '/proc/1/mem': Operation not permitted", cls: 'r', delay: 20 },
      { t: "rm: cannot remove '/proc/2/fd/0': Operation not permitted", cls: 'r', delay: 18 },
      { t: "rm: cannot remove '/proc/2/fd/1': Operation not permitted", cls: 'r', delay: 18 },
      { t: "rm: cannot remove '/proc/432/fd/0': Operation not permitted", cls: 'r', delay: 15 },
      { t: "rm: cannot remove '/proc/432/fd/1': Operation not permitted", cls: 'r', delay: 15 },
      { t: "rm: cannot remove '/proc/591/fd/0': Operation not permitted", cls: 'r', delay: 15 },
      { t: "rm: cannot remove '/proc/591/exe': Operation not permitted", cls: 'r', delay: 15 },
      { t: "rm: cannot remove '/proc/623/fd/0': Operation not permitted", cls: 'r', delay: 15 },
      { t: "rm: cannot remove '/proc/1234/fd/0': Operation not permitted", cls: 'r', delay: 15 },
      { t: "rm: cannot remove '/proc/1234/fd/1': Operation not permitted", cls: 'r', delay: 15 },
      { t: "rm: cannot remove '/proc/1234/fd/2': Operation not permitted", cls: 'r', delay: 15 },
      { t: "rm: cannot remove '/proc/sysrq-trigger': Operation not permitted", cls: 'r', delay: 20 },
      { t: "rm: cannot remove '/proc/kcore': Operation not permitted", cls: 'r', delay: 20 },
      // /sys errors
      { t: "rm: cannot remove '/sys/kernel/security/apparmor/policy': Read-only file system", cls: 'r', delay: 25 },
      { t: "rm: cannot remove '/sys/kernel/security/apparmor/profiles': Read-only file system", cls: 'r', delay: 20 },
      { t: "rm: cannot remove '/sys/fs/cgroup/memory/memory.limit_in_bytes': Read-only file system", cls: 'r', delay: 20 },
      { t: "rm: cannot remove '/sys/devices/virtual/net/lo/operstate': Read-only file system", cls: 'r', delay: 20 },
      { t: "rm: cannot remove '/sys/bus/pci/devices/0000:00:0f.0/resource': Read-only file system", cls: 'r', delay: 18 },
      // normal deletions start — things actually getting wiped
      { t: "removed '/bin/bash'", cls: 'd', delay: jitter(120, 30) },
      { t: "removed '/bin/ls'", cls: 'd', delay: jitter(80, 20) },
      { t: "removed '/bin/cat'", cls: 'd', delay: jitter(70, 20) },
      { t: "removed '/bin/rm'", cls: 'd', delay: jitter(90, 20) },
      { t: "removed '/bin/sh'", cls: 'd', delay: jitter(70, 20) },
      { t: "removed '/bin/cp'", cls: 'd', delay: jitter(60, 15) },
      { t: "removed '/bin/mv'", cls: 'd', delay: jitter(60, 15) },
      { t: "removed '/bin/mkdir'", cls: 'd', delay: jitter(60, 15) },
      { t: "removed '/bin/chmod'", cls: 'd', delay: jitter(60, 15) },
      { t: "removed '/bin/chown'", cls: 'd', delay: jitter(60, 15) },
      { t: "removed '/etc/passwd'", cls: 'd', delay: jitter(100, 30) },
      { t: "removed '/etc/shadow'", cls: 'd', delay: jitter(80, 20) },
      { t: "removed '/etc/hosts'", cls: 'd', delay: jitter(70, 20) },
      { t: "removed '/etc/fstab'", cls: 'd', delay: jitter(70, 20) },
      { t: "removed '/etc/sudoers'", cls: 'd', delay: jitter(80, 20) },
      { t: "removed '/etc/ssh/sshd_config'", cls: 'd', delay: jitter(70, 20) },
      { t: "removed '/etc/systemd/system.conf'", cls: 'd', delay: jitter(70, 20) },
      { t: "removed '/lib/x86_64-linux-gnu/libc.so.6'", cls: 'd', delay: jitter(110, 30) },
      { t: "removed '/lib/x86_64-linux-gnu/libm.so.6'", cls: 'd', delay: jitter(90, 20) },
      { t: "removed '/lib/x86_64-linux-gnu/libpthread.so.0'", cls: 'd', delay: jitter(80, 20) },
      { t: "removed '/lib/x86_64-linux-gnu/libdl.so.2'", cls: 'd', delay: jitter(70, 20) },
      { t: "removed '/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'", cls: 'd', delay: jitter(90, 20) },
      // things start breaking — garbled/partial output
      { t: "removed '/usr/bin/python3.11'", cls: 'd', delay: jitter(120, 30) },
      { t: "removed '/usr/bin/perl'", cls: 'd', delay: jitter(90, 20) },
      { t: "removed '/usr/bin/ssh'", cls: 'd', delay: jitter(80, 20) },
      { t: "removed '/usr/sbin/sshd'", cls: 'd', delay: jitter(100, 25) },
      { t: "removed '/usr/lib/systemd/systemd'", cls: 'd', delay: jitter(130, 30) },
      { t: "removed '/usr/lib/x86_64-linux-gnu/libssl.so.3'", cls: 'd', delay: jitter(90, 20) },
      { t: "removed '/usr/lib/x86_64-linux-gnu/libcrypto.so.3'", cls: 'd', delay: jitter(90, 20) },
      // X11/display starts dying
      { t: "removed '/usr/lib/xorg/Xorg'", cls: 'd', delay: jitter(150, 40) },
      { t: "removed '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'", cls: 'd', delay: jitter(80, 20) },
      // network drops
      { t: "removed '/usr/sbin/NetworkManager'", cls: 'd', delay: jitter(120, 30) },
      { t: 'RTNETLINK answers: Network is down', cls: 'r', delay: jitter(400, 100) },
      // more /proc errors as kernel fights back
      { t: "rm: cannot remove '/proc/1338/fd/0': No such process", cls: 'r', delay: 25 },
      { t: "rm: cannot remove '/proc/1338/fd/1': No such process", cls: 'r', delay: 20 },
      { t: "removed '/var/log/syslog'", cls: 'd', delay: jitter(80, 20) },
      { t: "removed '/var/log/auth.log'", cls: 'd', delay: jitter(70, 20) },
      { t: "removed '/home/rembrandt/.bashrc'", cls: 'd', delay: jitter(80, 20) },
      { t: "removed '/home/rembrandt/.bash_history'", cls: 'd', delay: jitter(70, 20) },
      { t: "removed '/root/root.txt'", cls: 'd', delay: jitter(90, 20) },
      // things get weird — partial output, corruption
      { t: "rm: cannot remove '/run/systemd/private': Device or resource busy", cls: 'r', delay: jitter(200, 50) },
      { t: "rm: cannot remove '/run/dbus/system_bus_socket': Device or resource busy", cls: 'r', delay: jitter(150, 40) },
      { t: "removed '/sbin/init'", cls: 'd', delay: jitter(200, 50) },
      { t: '', delay: 300 },
      // output starts corrupting
      { t: '\x1b[?25l\x1b[38;5;196mrm: \x1b[0mcannot remove \x1b[38;5;214m\'/dev/null\'\x1b[0m: \x1b[38;5;196mOperation not permitted\x1b[0m', delay: 200 },
      { t: '\x1b[38;5;196mrm: \x1b[0mcannot remove \x1b[38;5;214m\'/dev/urandom\'\x1b[0m: \x1b[38;5;196mOperation not permitted\x1b[0m', delay: 150 },
      { t: '\x1b[38;5;220mremoved \'/dev/sda\'\x1b[0m', delay: jitter(300, 80) },
      { t: '', delay: 400 },
      // kernel panic begins
      { t: '\x1b[1;37m[  892.341521] \x1b[0m\x1b[1;31mKernel panic - not syncing: Attempted to kill init! exitcode=0x00000100\x1b[0m', delay: 600 },
      { t: '\x1b[1;37m[  892.341598] \x1b[0mCPU: 0 PID: 1 Comm: systemd Not tainted 6.6.9-amd64 #1', delay: 80 },
      { t: '\x1b[1;37m[  892.341612] \x1b[0mHardware name: VMware, Inc. VMware Virtual Platform/440BX Desktop Reference Platform', delay: 80 },
      { t: '\x1b[1;37m[  892.341631] \x1b[0mCall Trace:', delay: 80 },
      { t: '\x1b[1;37m[  892.341644] \x1b[0m <TASK>', delay: 60 },
      { t: '\x1b[1;37m[  892.341658] \x1b[0m dump_stack_lvl+0x37/0x50', delay: 50 },
      { t: '\x1b[1;37m[  892.341672] \x1b[0m panic+0x118/0x2e0', delay: 50 },
      { t: '\x1b[1;37m[  892.341685] \x1b[0m do_exit+0xb2c/0xb40', delay: 50 },
      { t: '\x1b[1;37m[  892.341698] \x1b[0m do_group_exit+0x2d/0x90', delay: 50 },
      { t: '\x1b[1;37m[  892.341711] \x1b[0m __x64_sys_exit_group+0x14/0x20', delay: 50 },
      { t: '\x1b[1;37m[  892.341724] \x1b[0m do_syscall_64+0x5b/0x90', delay: 50 },
      { t: '\x1b[1;37m[  892.341737] \x1b[0m entry_SYSCALL_64_after_hwframe+0x6e/0xd8', delay: 50 },
      { t: '\x1b[1;37m[  892.341751] \x1b[0m </TASK>', delay: 60 },
      { t: '\x1b[1;37m[  892.341812] \x1b[0m\x1b[1;31m---[ end Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000100 ]---\x1b[0m', delay: 200 },
      { t: '', delay: 800 },
      // desktop environment starts dying
      { t: '\x1b[1;33m(xfce4-session:1189): GLib-CRITICAL **: g_main_loop_quit: assertion failed\x1b[0m', delay: 500 },
      { t: '\x1b[1;33m(xfwm4:1201): GLib-WARNING **: cannot open display: :0\x1b[0m', delay: 200 },
      { t: '\x1b[1;33m(xfdesktop:1203): Gdk-ERROR **: The program xfdesktop received an X Window System error.\x1b[0m', delay: 200 },
      { t: '\x1b[1;33mThis probably reflects a bug in the program.\x1b[0m', delay: 80 },
      { t: '\x1b[1;33mThe error was \x27BadAlloc (insufficient resources for operation)\x27.\x1b[0m', delay: 80 },
      { t: '\x1b[1;33m  (Details: serial 412 error_code 11 request_code 53 minor_code 0)\x1b[0m', delay: 80 },
      { t: '\x1b[1;33m  (Note to programmers: normally, X errors are reported asynchronously;\x1b[0m', delay: 60 },
      { t: '\x1b[1;33m   that is, you will receive the error a while after causing it.)\x1b[0m', delay: 60 },
      { t: '', delay: 200 },
      // audio dies
      { t: '\x1b[90mW: [pulseaudio] core-util.c: Failed to open /proc/self/oom_score_adj: No such file or directory\x1b[0m', delay: 300 },
      { t: '\x1b[90mW: [pulseaudio] pid.c: Stale PID file, overwriting.\x1b[0m', delay: 150 },
      { t: '\x1b[1;31mE: [pulseaudio] core-util.c: Failed to create secure directory: No such file or directory\x1b[0m', delay: 150 },
      { t: '\x1b[1;31mE: [pulseaudio] main.c: Failed to initialize daemon.\x1b[0m', delay: 100 },
      { t: '', delay: 200 },
      // display manager segfaults
      { t: '\x1b[1;31mlightdm[891]: segfault at 0 ip 00007f3a4b2c1000 sp 00007ffd7e4b3d50 error 4 in libglib-2.0.so.0\x1b[0m', delay: 400 },
      { t: '\x1b[1;31mxfce4-session[1189]: segfault at 8 ip 00007f3a4b3d2100 sp 00007ffd7e4b3e60 error 6 in libxfce4util.so.7\x1b[0m', delay: 200 },
      { t: '\x1b[1;31mXorg[891]: segfault at 0 ip 00007f3a4b1a0000 sp 00007ffd7e4b2d40 error 4 in libpixman-1.so.0\x1b[0m', delay: 200 },
      { t: '', delay: 300 },
      // systemd desperately trying to restart things
      { t: '\x1b[1;37m[  887.112341] \x1b[0msystemd[1]: lightdm.service: Main process exited, code=dumped, status=11/SEGV', delay: 300 },
      { t: '\x1b[1;37m[  887.112398] \x1b[0msystemd[1]: lightdm.service: Failed with result \x27core-dump\x27.', delay: 100 },
      { t: '\x1b[1;37m[  887.112441] \x1b[0msystemd[1]: Failed to start Light Display Manager.', delay: 100 },
      { t: '\x1b[1;37m[  887.234521] \x1b[0msystemd[1]: networking.service: Main process exited, code=killed, status=9/KILL', delay: 200 },
      { t: '\x1b[1;37m[  887.234598] \x1b[0msystemd[1]: Reached target Network is Unreachable.', delay: 100 },
      { t: '\x1b[1;37m[  888.001234] \x1b[0msystemd[1]: systemd-logind.service: Main process exited, code=dumped, status=11/SEGV', delay: 300 },
      { t: '\x1b[1;37m[  888.001312] \x1b[0msystemd[1]: Stopping User Login Management...', delay: 100 },
      { t: '\x1b[1;37m[  888.445123] \x1b[0msystemd[1]: dbus.service: Main process exited, code=killed, status=9/KILL', delay: 400 },
      { t: '\x1b[1;37m[  888.445201] \x1b[0m\x1b[1;31msystemd[1]: dbus.service: Failed. D-Bus is required for further operation. Aborting.\x1b[0m', delay: 200 },
      { t: '', delay: 400 },
      // filesystem going read-only as kernel detects corruption
      { t: '\x1b[1;37m[  889.123456] \x1b[0m\x1b[1;31mEXT4-fs error (device sda1): ext4_find_entry:1455: inode #2: comm rm: reading directory lblock 0\x1b[0m', delay: 300 },
      { t: '\x1b[1;37m[  889.234567] \x1b[0m\x1b[1;31mEXT4-fs error (device sda1): ext4_journal_check_start:61: Detected aborted journal\x1b[0m', delay: 150 },
      { t: '\x1b[1;37m[  889.234612] \x1b[0m\x1b[1;31mEXT4-fs (sda1): Remounting filesystem read-only\x1b[0m', delay: 150 },
      { t: '\x1b[1;37m[  889.345678] \x1b[0mBuffer I/O error on dev sda1, logical block 0, async page read', delay: 100 },
      { t: '\x1b[1;37m[  889.345712] \x1b[0mBuffer I/O error on dev sda1, logical block 1, async page read', delay: 80 },
      { t: '\x1b[1;37m[  889.345734] \x1b[0mBuffer I/O error on dev sda1, logical block 2, async page read', delay: 80 },
      { t: '\x1b[1;37m[  889.456789] \x1b[0m\x1b[1;31msd 0:0:0:0: [sda] tag#0 FAILED Result: hostbyte=DID_OK driverbyte=DRIVER_SENSE\x1b[0m', delay: 200 },
      { t: '\x1b[1;37m[  889.456834] \x1b[0m\x1b[1;31msd 0:0:0:0: [sda] tag#0 Sense Key : Medium Error [current]\x1b[0m', delay: 100 },
      { t: '\x1b[1;37m[  889.456878] \x1b[0m\x1b[1;31msd 0:0:0:0: [sda] tag#0 Add. Sense: Unrecovered read error\x1b[0m', delay: 100 },
      { t: '', delay: 500 },
      // kernel panic
      { t: '\x1b[1;37m[  892.341521] \x1b[0m\x1b[1;31mKernel panic - not syncing: Attempted to kill init! exitcode=0x00000100\x1b[0m', delay: 600 },
      { t: '\x1b[1;37m[  892.341598] \x1b[0mCPU: 0 PID: 1 Comm: systemd Not tainted 6.6.9-amd64 #1', delay: 80 },
      { t: '\x1b[1;37m[  892.341612] \x1b[0mHardware name: VMware, Inc. VMware Virtual Platform/440BX Desktop Reference Platform', delay: 80 },
      { t: '\x1b[1;37m[  892.341631] \x1b[0mCall Trace:', delay: 80 },
      { t: '\x1b[1;37m[  892.341644] \x1b[0m <TASK>', delay: 60 },
      { t: '\x1b[1;37m[  892.341658] \x1b[0m dump_stack_lvl+0x37/0x50', delay: 50 },
      { t: '\x1b[1;37m[  892.341672] \x1b[0m panic+0x118/0x2e0', delay: 50 },
      { t: '\x1b[1;37m[  892.341685] \x1b[0m do_exit+0xb2c/0xb40', delay: 50 },
      { t: '\x1b[1;37m[  892.341698] \x1b[0m do_group_exit+0x2d/0x90', delay: 50 },
      { t: '\x1b[1;37m[  892.341711] \x1b[0m __x64_sys_exit_group+0x14/0x20', delay: 50 },
      { t: '\x1b[1;37m[  892.341724] \x1b[0m do_syscall_64+0x5b/0x90', delay: 50 },
      { t: '\x1b[1;37m[  892.341737] \x1b[0m entry_SYSCALL_64_after_hwframe+0x6e/0xd8', delay: 50 },
      { t: '\x1b[1;37m[  892.341751] \x1b[0m </TASK>', delay: 60 },
      { t: '\x1b[1;37m[  892.341812] \x1b[0m\x1b[1;31m---[ end Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000100 ]---\x1b[0m', delay: 200 },
      { t: '', delay: 600 },
      { t: '\x1b[5m\x1b[1;31m*** KERNEL PANIC — SYSTEM HALTED ***\x1b[0m', delay: 800 },
      { t: '', delay: 400 },
      { t: '\x1b[90mType  reset  to reboot the simulation.\x1b[0m', delay: 600 },
    ],
    lines: [],
    after: () => {
      // dramatic desktop visual crash
      const desktop = document.getElementById('desktop');
      if (desktop) {
        // flicker effect
        let flickers = 0;
        const flicker = setInterval(() => {
          desktop.style.filter = flickers % 2 === 0
            ? 'brightness(3) contrast(0) invert(1)'
            : 'brightness(0.1) saturate(0) hue-rotate(180deg)';
          flickers++;
          if (flickers > 6) {
            clearInterval(flicker);
            // freeze on corrupted frame then go black
            desktop.style.filter = 'brightness(0.05) saturate(0) blur(2px)';
            setTimeout(() => {
              desktop.style.filter = 'brightness(0) saturate(0)';
              desktop.style.transition = 'filter 0.8s';
            }, 400);
          }
        }, 120);
      }
      // wipe the simulated filesystem
      SIM.files = {};
      SIM.dirs = new Set();
      SIM.hashesOnDisk = false;
      SIM.cwd = '/';
    },
  },

  // ── mkdir / touch / rm ──────────────────────────────────────────────────────────────────────────
  {
    match: c => /^(mkdir|touch|rm|cp|mv|chmod)(\s|$)/.test(c),
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

);

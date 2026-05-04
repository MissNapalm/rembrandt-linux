'use strict';

const ETERNALBLUE_CHALLENGES = [
  {
    id: 1, title: 'Scan the target', pts: 150,
    flag: 'FLAG{ms17_010_eternalblue_confirmed}',
    hint: 'sudo nmap -sC -sV 10.10.10.10',
    explain: 'Recon first. We know there\'s a Windows 7 machine at 10.10.10.10 — now we knock on its door to see if it has the bug we\'re looking for.\n\nThe script we\'re running checks for MS17-010 — a 2017 flaw in Windows\'s file-sharing protocol (SMB). It\'s the same bug that powered WannaCry, the ransomware that took down the UK\'s NHS and 230,000 other machines in 150 countries.\n\nIf the scan reports State: VULNERABLE, the door is open.',
    done: false,
    check: r => r.id === 'nmap-eb-vuln',
  },
  {
    id: 2, title: 'Open Metasploit', pts: 100,
    flag: 'FLAG{msfconsole_ready}',
    hint: 'msfconsole',
    explain: 'Metasploit is a giant toolbox of pre-written exploits. Pick the right tool, aim it at a target, pull the trigger.\n\nmsfconsole opens the console. When you see msf6 >, it\'s ready.',
    done: false,
    check: r => r.id === 'msfconsole',
  },
  {
    id: 3, title: 'Pick the exploit', pts: 150,
    flag: 'FLAG{eternalblue_module_loaded}',
    hint: 'use exploit/windows/smb/ms17_010_eternalblue',
    explain: 'Read the module path like a sentence: an exploit, for Windows, over SMB, named ms17_010_eternalblue. That\'s the bug we just confirmed.\n\nuse loads it. The prompt changes to show it\'s active.\n\nType show options anytime to see what settings the module still needs.',
    done: false,
    check: r => r.id === 'msf-use',
  },
  {
    id: 4, title: 'Aim it', pts: 150,
    flag: 'FLAG{rhosts_lhost_configured}',
    hint: 'set RHOSTS 10.10.10.10',
    explain: 'One setting before we fire:\n\nRHOSTS — the target. R for Remote.\n\nLHOST (your own IP, where the shell will phone home) is auto-set from your machine. Why phone home instead of us connecting in? Firewalls usually let outbound traffic out but block incoming. A reverse shell looks like normal outbound and slips past.',
    done: false,
    check: r => r.id === 'msf-set',
  },
  {
    id: 5, title: 'Fire', pts: 400,
    flag: 'FLAG{meterpreter_session_opened}',
    hint: 'run',
    explain: 'Type run and watch.\n\nEternalBlue sends a malformed SMB packet that crashes through Windows\'s memory protection and runs our code — before any login check happens.\n\nOur payload is Meterpreter, a shell that lives in RAM and never writes to disk. Antivirus barely sees it.\n\nMeterpreter session 1 opened means you\'re in.',
    done: false,
    check: r => r.id === 'msf-run',
  },
  {
    id: 6, title: 'Check who you are', pts: 200,
    flag: 'FLAG{nt_authority_system_eternalblue}',
    hint: 'getuid\nsysinfo',
    explain: 'First thing on any shell: figure out who you are.\n\ngetuid answers it. NT AUTHORITY\\\\SYSTEM is the highest privilege on Windows — above even Administrator. Total control.\n\nEternalBlue runs in the kernel, so you land as SYSTEM automatically. No privilege escalation needed.\n\nsysinfo confirms the box: OS, hostname, architecture.',
    done: false,
    check: r => r.id === 'msf-getuid',
  },
  {
    id: 7, title: 'Steal password hashes', pts: 300,
    flag: 'FLAG{sam_hashes_dumped}',
    hint: 'hashdump',
    explain: 'Windows keeps account passwords in a file called the SAM, scrambled into hashes (not plain text).\n\nNormally the SAM is locked while Windows is running. As SYSTEM, we can read it anyway.\n\nhashdump dumps every local hash. From there you can crack them offline with hashcat — or use them as-is to log into other machines (pass-the-hash). In real networks, the same admin password often unlocks hundreds of boxes.',
    done: false,
    check: r => r.id === 'msf-hashdump',
  },
  {
    id: 8, title: 'Grab the loot', pts: 250,
    flag: 'FLAG{secret_docs_exfiltrated}',
    hint: 'shell\ncd C:\\CORP_DATA\\Customer\\Credit_Card_Records\ntype root.txt',
    explain: 'shell drops you into a normal Windows cmd.exe — running as SYSTEM, on the target.\n\nWalk into C:\\\\CORP_DATA\\\\Customer\\\\Credit_Card_Records and you\'ll find the kind of file that turns a quiet breach into a headline.\n\nThis is the exfiltration phase — the part that actually justifies the operation. Type exit when done to return to Meterpreter.',
    done: false,
    check: r => r.id === 'msf-shell-loot',
  },
];

const CTF = {
  _lab: 'eternalblue',
  _labs: {
    eternalblue: ETERNALBLUE_CHALLENGES,
  },

  get challenges() { return this._labs[this._lab]; },

  _loadState() {
    try {
      const s = JSON.parse(localStorage.getItem('ctf_state_' + this._lab) || '{}');
      this.challenges.forEach(c => { if (s[c.id]) c.done = true; });
    } catch {}
  },

  _saveState() {
    const s = {};
    this.challenges.forEach(c => { if (c.done) s[c.id] = true; });
    localStorage.setItem('ctf_state_' + this._lab, JSON.stringify(s));
  },

  score()    { return this.challenges.filter(c => c.done).reduce((a, c) => a + c.pts, 0); },
  maxScore() { return this.challenges.reduce((a, c) => a + c.pts, 0); },
  doneCount(){ return this.challenges.filter(c => c.done).length; },

  switchLab(labId) {
    if (!this._labs[labId]) return;
    this._lab = labId;
    this._resetLabState();
    this._loadState();
    this._renderSidebar();
  },

  check(result) {
    if (!result || !result.id) return null;
    for (const c of this.challenges) {
      if (!c.done && c.check(result)) {
        c.done = true;
        this._saveState();
        return c;
      }
    }
    return null;
  },

  reset() {
    this.challenges.forEach(c => c.done = false);
    localStorage.removeItem('ctf_state_' + this._lab);
    this._resetLabState();
    this._renderSidebar();
  },

  // Shared lab-state reset. Touches only flags actually defined in SIM.
  _resetLabState() {
    SIM.windowsShell = false;
    SIM.hashesOnDisk = false;
    SIM.lootExfiltrated = false;
    SIM.msf = false;
    SIM.msfModule = null;
    SIM.msfOpts = {};
    SIM.msfSessions = [];
    SIM.msfMeter = false;
    SIM.msfMeterId = null;
    SIM.msfMeterWin = false;
    SIM.msfLastSearch = [];
    SIM.legacyPwned = false;
    SIM.kiwiLoaded = false;
    SIM.lsassDumped = false;
    SIM.persistenceInstalled = false;
    SIM.isRoot = false;
    const home = '/home/' + SIM.user;
    SIM.cwd = home;
    TERM_INSTANCES.forEach(t => {
      t._cwd = home;
      t._isRoot = false;
      t._windowsShell = false;
      t._winCwd = 'C:\\Windows\\system32';
      t._updatePrompt && t._updatePrompt();
    });
  },

  // ── Sidebar UI ─────────────────────────────────────────────────────────────
  _renderSidebar() {
    const list    = document.getElementById('ctf-list');
    const scoreEl = document.getElementById('ctf-score');
    const barEl   = document.getElementById('ctf-bar');
    const progEl  = document.getElementById('ctf-progress-label');
    const maxEl   = document.getElementById('ctf-max');
    if (!list) return;

    scoreEl.textContent = this.score().toLocaleString();
    if (maxEl) maxEl.textContent = ' / ' + this.maxScore().toLocaleString() + ' pts';
    const pct = Math.round(this.score() / this.maxScore() * 100);
    barEl.style.width = pct + '%';
    progEl.textContent = `${this.doneCount()} / ${this.challenges.length} completed`;

    list.innerHTML = this.challenges.map(c => `
      <div class="ctf-item${c.done ? ' done' : ''}" data-cid="${c.id}" style="cursor:pointer">
        <div class="ctf-item-header">
          <div class="ctf-num">${c.done ? '✓' : c.id}</div>
          <div class="ctf-title">${c.title}</div>
          <div class="ctf-pts">${c.pts}pts</div>
          <i class="fa fa-circle-info ctf-info-btn" title="What is this?"></i>
        </div>
        ${c.done
          ? `<div class="ctf-flag">${c.flag}</div>`
          : `<div class="ctf-hint-row"><span class="ctf-hint">${c.hint.split('\n')[0]}</span><button class="ctf-copy-btn" data-cmd="${c.hint.replace(/"/g,'&quot;')}" title="Copy command"><i class="fa fa-copy"></i></button></div>`}
      </div>`
    ).join('');

    list.querySelectorAll('.ctf-item').forEach(el => {
      el.addEventListener('click', e => {
        if (e.target.closest('.ctf-copy-btn')) return;
        const cid = parseInt(el.dataset.cid);
        const ch  = this.challenges.find(c => c.id === cid);
        if (ch) this._showExplain(ch);
      });
    });

    list.querySelectorAll('.ctf-copy-btn').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const cmd = btn.dataset.cmd.split('\n')[0];
        CTF._pasteToTerminal(cmd);
        btn.innerHTML = '<i class="fa fa-check"></i>';
        setTimeout(() => { btn.innerHTML = '<i class="fa fa-copy"></i>'; }, 1500);
      });
    });
  },

  _pasteToTerminal(cmd) {
    // Prefer the currently visible/active terminal pane so the paste lands where the user is looking
    const activePane = document.querySelector('.term-pane.active');
    const activeInst = activePane?._termInst;
    const inst = (activeInst && !activeInst._nano)
      ? activeInst
      : (TERM_INSTANCES.find(t => !t._busy && !t._nano) || TERM_INSTANCES[TERM_INSTANCES.length - 1]);
    if (!inst) return;
    inst._setInput(cmd);
    inst.focus();
  },

  _showExplain(ch) {
    document.getElementById('ctf-explain-num').textContent   = ch.id;
    document.getElementById('ctf-explain-title').textContent = ch.title;
    document.getElementById('ctf-explain-text').textContent  = ch.explain;
    document.getElementById('ctf-explain-hint').textContent  = ch.hint;
    const copyBtn = document.getElementById('ctf-explain-copy');
    const cmdBox  = document.getElementById('ctf-explain-cmd');
    const modal   = document.getElementById('ctf-explain-modal');
    const onKey = e => {
      if (modal.classList.contains('hidden')) {
        document.removeEventListener('keydown', onKey, true);
        return;
      }
      if (e.key === 'Enter') {
        e.preventDefault();
        e.stopPropagation();
        pasteAndClose();
      }
    };
    const pasteAndClose = () => {
      CTF._pasteToTerminal(ch.hint.split('\n')[0]);
      copyBtn.innerHTML = '<i class="fa fa-check"></i> Pasted';
      setTimeout(() => { copyBtn.innerHTML = '<i class="fa fa-copy"></i> Copy'; }, 1500);
      modal.classList.add('hidden');
      document.removeEventListener('keydown', onKey, true);
    };
    copyBtn.onclick = e => { e.stopPropagation(); pasteAndClose(); };
    cmdBox.onclick = pasteAndClose;
    document.addEventListener('keydown', onKey, true);
    modal.classList.remove('hidden');
  },

  showFlagPopup(challenge) {
    document.getElementById('fp-challenge').textContent = challenge.title;
    document.getElementById('fp-flag').textContent = challenge.flag;
    document.getElementById('fp-pts').textContent = `+${challenge.pts} points`;
    document.getElementById('flag-popup').classList.remove('hidden');
    clearTimeout(this._popupTimer);
    this._popupTimer = setTimeout(() => {
      document.getElementById('flag-popup').classList.add('hidden');
    }, 9000);
  },

  init() {
    // Always start fresh — reset progress on every new session
    this.challenges.forEach(c => c.done = false);
    localStorage.removeItem('ctf_state_eternalblue');
    this._renderSidebar();

    document.getElementById('ctf-lab-select').addEventListener('change', e => {
      this.switchLab(e.target.value);
    });

    document.getElementById('ctf-reset-btn').addEventListener('click', () => {
      if (confirm('Reset all CTF progress?')) this.reset();
    });

    const closeExplain = () => document.getElementById('ctf-explain-modal').classList.add('hidden');
    document.getElementById('ctf-explain-close').addEventListener('click', closeExplain);
    document.getElementById('ctf-explain-ok').addEventListener('click', closeExplain);
    document.getElementById('ctf-explain-modal').addEventListener('click', e => {
      if (e.target === document.getElementById('ctf-explain-modal')) closeExplain();
    });

    document.getElementById('ctf-close-btn')?.addEventListener('click', () => {
      document.getElementById('ctf-sidebar').classList.add('collapsed');
    });
  },
};

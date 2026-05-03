'use strict';

HANDLERS.push(

  // ── sudo nano/vim — allow through to editor ────────────────────────────
  {
    match: c => /^sudo\s+(nano|vim?)\b/.test(c),
    waitSudo: true,
    lines: [],
  },
  // ── sudo <other editors> — refuse ────────────────────────────────────────
  {
    match: c => /^sudo\s+(gedit|emacs|micro)\b/.test(c),
    lines: [{ t: (c) => `${c.replace(/^sudo\s+/, '').split(' ')[0]}: interactive editors not supported in this simulation`, cls: 'y' }],
  },

  // ── sudo (bare) ───────────────────────────────────────────────────────────
  {
    match: c => /^sudo\s*$/.test(c),
    lines: [{ t: 'usage: sudo [-ABknS] [-g group] [-H] [-p prompt] [-u user] [-i|-s] [command]', cls: 'r' }],
  },

  // ── sudo ─────────────────────────────────────────────────────────────────
  {
    match: c => /^sudo\s+./.test(c),
    waitSudo: true,
    lines: [],
  },

  // ── sudo -i / sudo su (become root permanently) ───────────────────────────
  // These are called by runAsSudo() after auth, not directly
  {
    id: 'become-root',
    match: c => c === '-i' || c === 'su' || c === 'su -' || c === '-s /bin/bash',
    loadTime: () => jitter(800, 200),
    lines: [],   // prompt change only
    after: (c) => { SIM.user = 'root'; if (c === '-i' || c === 'su -') SIM.cwd = '/root'; },
  },

  // ── doom (easter egg) ─────────────────────────────────────────────────────
  {
    id: 'doom',
    match: c => /^doom\s*$/i.test(c),
    lines: [
      { t: '       ▄▄▄▄    ▄▄▄▄▄    ▄▄▄▄    ▄▄    ▄▄', cls: 'r' },
      { t: '       ██  ██  ██  ██  ██  ██  ███▄▄███', cls: 'r' },
      { t: '       ██  ██  ██  ██  ██  ██  ██ ██ ██', cls: 'r' },
      { t: '       ██████  ██████  ██████  ██    ██', cls: 'r' },
      { t: '' },
      { t: 'Knee-Deep in the Dead — loading shareware WAD...', cls: 'y' },
      { t: 'Hint: click the window, then press ENTER to start. Arrow keys + Ctrl to fire.', cls: 'd' },
    ],
    after: () => { if (typeof window._openDoom === 'function') window._openDoom(); },
  },

  // ── apt / apt-get ─────────────────────────────────────────────────────────
  {
    match: c => /^apt(-get)?\s+update/.test(c),
    loadTime: () => jitter(3500, 900),
    lines: [
      { t: 'Hit:1 http://http.rembrandt.org/rembrandt rembrandt-rolling InRelease', cls: 'b' },
      { t: 'Get:2 http://http.rembrandt.org/rembrandt rembrandt-rolling/main amd64 Packages [19.1 MB]' },
      { t: 'Get:3 http://http.rembrandt.org/rembrandt rembrandt-rolling/contrib amd64 Packages [98.8 kB]' },
      { t: 'Get:4 http://http.rembrandt.org/rembrandt rembrandt-rolling/non-free amd64 Packages [149 kB]' },
      { t: 'Get:5 http://http.rembrandt.org/rembrandt rembrandt-rolling/non-free-firmware amd64 Packages [9,660 B]' },
      { t: 'Fetched 19.4 MB in 8s (2,425 kB/s)' },
      { t: 'Reading package lists... Done', cls: 'g' },
    ],
    requireRoot: true,
  },
  {
    match: c => /^apt(-get)?\s+install/.test(c),
    loadTime: () => jitter(2200, 600),
    lines: [
      { t: 'Reading package lists... Done' },
      { t: 'Building dependency tree... Done' },
      { t: 'Reading state information... Done' },
      { t: (c) => {
        const pkg = c.replace(/^apt(-get)?\s+install\s+(-y\s+)?/, '').trim() || 'package';
        return `${pkg} is already the newest version.`;
      }, cls: 'g' },
      { t: '0 upgraded, 0 newly installed, 0 to remove and 127 not upgraded.' },
    ],
    requireRoot: true,
  },
  {
    match: c => /^apt(-get)?\s+upgrade/.test(c),
    loadTime: () => jitter(1800, 500),
    lines: [
      { t: 'Reading package lists... Done' },
      { t: 'Building dependency tree... Done' },
      { t: 'Calculating upgrade... Done' },
      { t: '0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.' },
    ],
    requireRoot: true,
  },
  {
    match: c => /^apt(-get)?\b/.test(c),
    lines: [{ t: (c) => `E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\nE: Unable to acquire the dpkg frontend lock, are you root?`, cls: 'r' }],
  },

);

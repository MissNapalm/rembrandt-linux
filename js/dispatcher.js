'use strict';

// ── Dispatcher ────────────────────────────────────────────────────────────────
function runCommand(rawInput) {
  const cmd = rawInput.trim().replace(/\s+/g, ' ');
  if (!cmd) return null;

  // Windows shell mode (after psexec)
  if (SIM.windowsShell) {
    if (cmd === 'exit' || cmd === 'logout') {
      SIM.windowsShell = false;
      SIM.winCwd = 'C:\\Windows\\system32';
      return { lines: [{ t: '' }] };
    }

    // ── cd ───────────────────────────────────────────────────────────────────
    if (/^cd(\s|$)/i.test(cmd)) {
      const arg = cmd.replace(/^cd\s*/i, '').trim().replace(/\//g, '\\');
      if (!arg || arg === '\\') { SIM.winCwd = 'C:\\'; return { lines: [{ t: '' }] }; }
      // Resolve path
      const resolve = (base, rel) => {
        if (/^[A-Za-z]:\\/.test(rel)) return rel.replace(/\\+$/, '') || rel; // absolute
        if (/^[A-Za-z]:$/.test(rel)) return rel + '\\';
        if (rel === '..') {
          const parts = base.replace(/\\+$/, '').split('\\');
          if (parts.length <= 1) return 'C:\\';
          const up = parts.slice(0, -1).join('\\');
          return up.match(/^[A-Za-z]:$/) ? up + '\\' : up;
        }
        return (base.replace(/\\+$/, '') + '\\' + rel).replace(/\\{2,}/g, '\\');
      };
      const target = resolve(SIM.winCwd, arg);
      // Validate against known dirs
      const knownDirs = [
        'C:\\', 'C:\\Windows', 'C:\\Windows\\system32', 'C:\\Windows\\system32\\config',
        'C:\\Windows\\Temp', 'C:\\Temp',
        'C:\\Users', 'C:\\Users\\Administrator', 'C:\\Users\\Administrator\\Desktop',
        'C:\\Users\\Administrator\\Documents', 'C:\\Users\\Administrator\\Downloads',
        'C:\\Program Files', 'C:\\Program Files (x86)',
        'C:\\CORP_DATA', 'C:\\CORP_DATA\\Finance', 'C:\\CORP_DATA\\HR',
        'C:\\CORP_DATA\\Customer', 'C:\\CORP_DATA\\Customer\\Credit_Card_Records', 'C:\\CORP_DATA\\IT',
        'C:\\inetpub', 'C:\\inetpub\\wwwroot',
        'C:\\Windows\\NTDS', 'C:\\Windows\\SYSVOL',
      ];
      const match = knownDirs.find(d => d.toLowerCase() === target.toLowerCase());
      if (match) {
        SIM.winCwd = match;
        return { lines: [{ t: '' }] };
      }
      return { lines: [{ t: `The system cannot find the path specified.`, cls: 'r' }] };
    }

    // Meterpreter-only commands don't work in cmd.exe shell
    if (cmd === 'getuid' || cmd === 'sysinfo' || cmd === 'hashdump' || cmd === 'getsystem') {
      return { lines: [{ t: `'${cmd}' is not recognized as an internal or external command,\noperable program or batch file.`, cls: 'r' }] };
    }

    if (cmd === 'whoami') return { lines: [{ t: 'nt authority\\system', cls: 'g' }] };
    if (cmd === 'whoami /priv') return { lines: [
      { t: 'PRIVILEGES INFORMATION' }, { t: '----------------------' }, { t: '' },
      { t: 'Privilege Name                  Description                         State', cls: 'b' },
      { t: '=============================== =================================== =======', cls: 'd' },
      { t: 'SeAssignPrimaryTokenPrivilege   Replace a process level token       Enabled', cls: 'g' },
      { t: 'SeTcbPrivilege                  Act as part of the operating system Enabled', cls: 'g' },
      { t: 'SeDebugPrivilege                Debug programs                      Enabled', cls: 'g' },
      { t: 'SeImpersonatePrivilege          Impersonate a client after auth     Enabled', cls: 'g' },
    ]};
    if (cmd === 'hostname') return { lines: [{ t: 'DC01' }] };
    if (cmd === 'ipconfig' || cmd === 'ipconfig /all') return { lines: [
      { t: 'Windows IP Configuration' }, { t: '' },
      { t: 'Ethernet adapter Ethernet0:', cls: 'b' },
      { t: '   Connection-specific DNS Suffix  . : corp.local' },
      { t: '   IPv4 Address. . . . . . . . . . . : 10.10.10.10' },
      { t: '   Subnet Mask . . . . . . . . . . . : 255.255.255.0' },
      { t: '   Default Gateway . . . . . . . . . : 10.10.10.1' },
    ]};
    if (/^net user/.test(cmd)) return { lines: [
      { t: 'User accounts for \\\\DC01', cls: 'b' },
      { t: '-------------------------------------------------------------------------------' },
      { t: 'Administrator            Guest                    krbtgt' },
      { t: 'john.doe                 svc_backup               svc_sql                svc_web' },
    ]};
    if (/^net localgroup/.test(cmd)) return { lines: [
      { t: 'Aliases for \\\\DC01', cls: 'b' },
      { t: '-------------------------------------------------------------------------------' },
      { t: '*Administrators          *Backup Operators        *Domain Admins' },
      { t: '*Domain Users            *Remote Desktop Users' },
    ]};

    // ── dir ──────────────────────────────────────────────────────────────────
    if (/^dir(\s|$)/i.test(cmd)) {
      // Explicit path arg overrides cwd
      const arg = cmd.replace(/^dir\s*/i, '').trim().replace(/\/[a-z]/gi, '').trim();
      const target = arg || SIM.winCwd;
      const t = target.toLowerCase().replace(/\\+$/, '');
      const dirMap = {
        'c:':                         [['<DIR>','Windows'],['<DIR>','Users'],['<DIR>','Program Files'],['<DIR>','Program Files (x86)'],['<DIR>','inetpub'],['<DIR>','CORP_DATA']],
        'c:\\':                       [['<DIR>','Windows'],['<DIR>','Users'],['<DIR>','Program Files'],['<DIR>','Program Files (x86)'],['<DIR>','inetpub'],['<DIR>','CORP_DATA']],
        'c:\\windows':                [['<DIR>','system32'],['<DIR>','SysWOW64'],['<DIR>','NTDS'],['<DIR>','SYSVOL'],['<DIR>','Temp'],['<DIR>','inf']],
        'c:\\windows\\system32':       [['<DIR>','config'],['<DIR>','drivers'],['<DIR>','wbem'],['32,768','cmd.exe'],['45,056','net.exe'],['36,864','whoami.exe'],['28,672','ipconfig.exe']],
        'c:\\windows\\system32\\config':[['262,144','SAM'],['262,144','SECURITY'],['786,432','SOFTWARE'],['1,048,576','SYSTEM'],['32,768','DEFAULT']],
        'c:\\windows\\temp':           SIM.lsassDumped ? [['49,283,072','lsass.dmp']] : [],
        'c:\\temp':                    SIM.lsassDumped ? [['49,283,072','lsass.dmp']] : [],
        'c:\\windows\\ntds':           [['18,874,368','ntds.dit'],['1,048,576','edb.log'],['8,192','edb.chk']],
        'c:\\windows\\sysvol':         [['<DIR>','domain'],['<DIR>','staging'],['<DIR>','sysvol']],
        'c:\\users':                  [['<DIR>','Administrator'],['<DIR>','Default'],['<DIR>','Public']],
        'c:\\users\\administrator':    [['<DIR>','Desktop'],['<DIR>','Documents'],['<DIR>','Downloads'],['<DIR>','AppData'],['<DIR>','Favorites']],
        'c:\\users\\administrator\\desktop':   [['1,337','flag.txt'],['2,048','notes.txt']],
        'c:\\users\\administrator\\documents': [['4,096','passwords_old.txt'],['8,192','network_map.txt']],
        'c:\\users\\administrator\\downloads': [['2,048','winpeas.exe'],['1,024','nc.exe']],
        'c:\\program files':          [['<DIR>','Common Files'],['<DIR>','Internet Explorer'],['<DIR>','Windows Defender'],['<DIR>','Microsoft SQL Server']],
        'c:\\program files (x86)':    [['<DIR>','Common Files'],['<DIR>','Internet Explorer']],
        'c:\\inetpub':                [['<DIR>','wwwroot'],['<DIR>','logs'],['<DIR>','temp']],
        'c:\\inetpub\\wwwroot':        [['1,234','iisstart.htm'],['98,304','iisstart.png'],['<DIR>','aspnet_client']],
        'c:\\corp_data':              [['<DIR>','Finance'],['<DIR>','HR'],['<DIR>','Customer'],['<DIR>','IT']],
        'c:\\corp_data\\finance':      [['2,349,012','Q4_2023_Revenue_Final.xlsx'],['982,034','Annual_Budget_2024.xlsx'],['450,123','Payroll_Jan2024.xlsx']],
        'c:\\corp_data\\hr':           [['12,492,048','All_Employees_PII.csv'],['823,440','Salary_Database_2024.xlsx']],
        'c:\\corp_data\\customer':     [['<DIR>','Credit_Card_Records'],['4,128,903','Loyalty_Members.csv']],
        'c:\\corp_data\\customer\\credit_card_records': [['89,234,502','Credit_Card_Database.csv'],['142','root.txt']],
        'c:\\corp_data\\it':           [['4,832','VPN_Credentials.txt'],['32,840','Network_Diagram.vsdx'],['128,934','Backup_Schedule.xlsx']],
      };
      const entries = dirMap[t];
      if (entries === undefined) return { lines: [{ t: `File Not Found`, cls: 'r' }] };
      const displayPath = arg || SIM.winCwd;
      const out = [
        { t: ` Volume in drive C has no label.  Volume Serial Number is 1337-D34D` },
        { t: '' },
        { t: ` Directory of ${displayPath}`, cls: 'b' },
        { t: '' },
        { t: `01/15/2024  02:23 PM    <DIR>          .` },
        { t: `01/15/2024  02:23 PM    <DIR>          ..` },
      ];
      let fileCount = 0, fileBytes = 0, dirCount = 0;
      for (const [size, name] of entries) {
        if (size === '<DIR>') {
          out.push({ t: `01/15/2024  02:23 PM    <DIR>          ${name}`, cls: 'b' });
          dirCount++;
        } else {
          const cls = name.endsWith('.csv') ? 'r' : name.endsWith('.txt') ? 'y' : name.endsWith('.dmp') ? 'g' : '';
          out.push({ t: `01/15/2024  02:23 PM    ${size.padStart(14)}     ${name}`, cls });
          fileCount++;
          fileBytes += parseInt(size.replace(/,/g, '')) || 0;
        }
      }
      out.push({ t: `               ${fileCount} File(s)    ${fileBytes.toLocaleString()} bytes` });
      out.push({ t: `               ${dirCount} Dir(s)   32,456,789,120 bytes free` });
      return { lines: out };
    }

    // ── type / cat (Linux alias) ─────────────────────────────────────────────
    if (/^(type|cat)\s/i.test(cmd)) {
      const f = cmd.replace(/^(type|cat)\s+/i, '').trim().toLowerCase();
      if (f.includes('root.txt')) {
        SIM.lootExfiltrated = true;
        return { id: 'loot-exfil', lines: [
          { t: 'FLAG{secret_docs_exfiltrated}', cls: 'g' },
        ]};
      }
      if (f.includes('credit_card_database')) {
        return { id: 'loot-exfil', lines: [
          { t: 'CustomerID,FirstName,LastName,Email,CardNumber,CVV,ExpDate,SSN', cls: 'b' },
          { t: '10001,James,Wilson,j.wilson@email.com,4532-1234-5678-9012,341,03/27,123-45-6789', cls: 'g' },
          { t: '10002,Sarah,Chen,s.chen@email.com,5412-7534-1234-5678,229,08/25,234-56-7890', cls: 'g' },
          { t: '10003,Robert,Martinez,r.martinez@email.com,4916-8765-4321-0987,512,12/26,345-67-8901', cls: 'g' },
          { t: '10004,Emily,Johnson,e.johnson@email.com,3782-822463-10005,091,06/28,456-78-9012', cls: 'g' },
          { t: '10005,David,Kim,d.kim@email.com,6011-9876-5432-1098,774,11/25,567-89-0123', cls: 'g' },
          { t: '...', cls: 'd' },
          { t: '[23,452 records total — Credit_Card_Database.csv  (89.2 MB)]', cls: 'y' },
          { t: '' },
          { t: '*** SENSITIVE: PCI-DSS PROTECTED DATA — UNAUTHORIZED ACCESS IS A FEDERAL CRIME ***', cls: 'r' },
        ]};
      }
      if (f.includes('vpn_credentials')) return { lines: [
        { t: '# VPN Gateway Credentials — CONFIDENTIAL' }, { t: '' },
        { t: 'Gateway: vpn.corp.local:443', cls: 'b' },
        { t: 'admin_vpn     : VPNAdmin2024!', cls: 'g' },
        { t: 'backup_vpn    : Backup@Remote#99', cls: 'g' },
        { t: 'emergency_vpn : Em3rg3ncy!2024', cls: 'g' },
      ]};
      if (f.includes('all_employees_pii')) return { lines: [
        { t: 'EmployeeID,Name,SSN,DOB,Salary,Department', cls: 'b' },
        { t: '1001,John Doe,123-45-6789,1985-03-15,$85000,IT', cls: 'g' },
        { t: '1002,Jane Smith,234-56-7890,1979-07-22,$120000,Management', cls: 'g' },
        { t: '1003,Robert Brown,345-67-8901,1990-11-08,$72000,Finance', cls: 'g' },
        { t: '...', cls: 'd' },
        { t: '[3,842 employee records — All_Employees_PII.csv  (12.4 MB)]', cls: 'y' },
      ]};
      if (f.includes('flag.txt')) return { lines: [{ t: 'FLAG{dc01_compromised_nt_authority_system}', cls: 'g' }] };
      if (f.includes('passwords_old')) return { lines: [
        { t: '# Old passwords — archived 2022' },
        { t: 'Administrator: P@ssw0rd2022!', cls: 'y' },
        { t: 'svc_backup: Backup2021!', cls: 'y' },
      ]};
      return { lines: [{ t: `The system cannot find the file specified.`, cls: 'r' }] };
    }

    if (cmd === 'whoami /groups') return { lines: [
      { t: 'GROUP INFORMATION' }, { t: '-----------------' }, { t: '' },
      { t: 'Group Name                                Type             SID          Attributes', cls: 'b' },
      { t: '========================================= ================ ============ ==============================', cls: 'd' },
      { t: 'BUILTIN\\Administrators                    Alias            S-1-5-32-544 Enabled by default, Enabled group, Group owner', cls: 'g' },
      { t: 'BUILTIN\\Users                             Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group' },
      { t: 'NT AUTHORITY\\SYSTEM                       Well-known group S-1-5-18     Enabled by default, Enabled group', cls: 'g' },
      { t: 'NT AUTHORITY\\Authenticated Users          Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group' },
      { t: 'NT AUTHORITY\\This Organization            Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group' },
      { t: 'Mandatory Label\\System Mandatory Level    Label            S-1-16-16384' },
    ]};

    if (cmd === 'systeminfo') return { lines: [
      { t: 'Host Name:                 DC01', cls: 'b' },
      { t: 'OS Name:                   Microsoft Windows 7 Ultimate', cls: 'b' },
      { t: 'OS Version:                6.1.7601 Service Pack 1 Build 7601' },
      { t: 'OS Manufacturer:           Microsoft Corporation' },
      { t: 'OS Configuration:          Standalone Workstation' },
      { t: 'OS Build Type:             Multiprocessor Free' },
      { t: 'Registered Owner:          Windows User' },
      { t: 'Registered Organization:   ' },
      { t: 'Product ID:                00426-OEM-8992662-00010' },
      { t: 'Original Install Date:     1/8/2024, 11:42:18 AM' },
      { t: 'System Boot Time:          1/15/2024, 7:14:33 AM' },
      { t: 'System Manufacturer:       VMware, Inc.' },
      { t: 'System Model:              VMware Virtual Platform' },
      { t: 'System Type:               x64-based PC' },
      { t: 'Processor(s):              1 Processor(s) Installed.' },
      { t: '                           [01]: Intel64 Family 6 Model 158 Stepping 9 GenuineIntel ~2904 Mhz' },
      { t: 'BIOS Version:              Phoenix Technologies LTD 6.00, 7/29/2019' },
      { t: 'Windows Directory:         C:\\Windows' },
      { t: 'System Directory:          C:\\Windows\\system32' },
      { t: 'Boot Device:               \\Device\\HarddiskVolume1' },
      { t: 'System Locale:             en-us;English (United States)' },
      { t: 'Input Locale:              en-us;English (United States)' },
      { t: 'Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)' },
      { t: 'Total Physical Memory:     2,047 MB' },
      { t: 'Available Physical Memory: 1,438 MB' },
      { t: 'Virtual Memory: Max Size:  4,095 MB' },
      { t: 'Virtual Memory: Available: 3,602 MB' },
      { t: 'Virtual Memory: In Use:    493 MB' },
      { t: 'Page File Location(s):     C:\\pagefile.sys' },
      { t: 'Domain:                    WORKGROUP' },
      { t: 'Logon Server:              \\\\DC01' },
      { t: 'Hotfix(s):                 3 Hotfix(s) Installed.', cls: 'y' },
      { t: '                           [01]: KB2479628' },
      { t: '                           [02]: KB2491683' },
      { t: '                           [03]: KB2506014' },
      { t: 'Network Card(s):           1 NIC(s) Installed.' },
      { t: '                           [01]: Intel(R) PRO/1000 MT Network Connection' },
      { t: '                                 Connection Name: Local Area Connection' },
      { t: '                                 DHCP Enabled:    No' },
      { t: '                                 IP address(es)' },
      { t: '                                 [01]: 10.10.10.10' },
    ]};

    if (cmd === 'ver') return { lines: [
      { t: '' },
      { t: 'Microsoft Windows [Version 6.1.7601]' },
    ]};

    if (cmd === 'wmic qfe list' || cmd === 'wmic qfe list brief' || cmd === 'wmic qfe') return { lines: [
      { t: 'Caption                                     Description      HotFixID   InstalledBy           InstalledOn', cls: 'b' },
      { t: 'http://support.microsoft.com/?kbid=2479628  Update           KB2479628  NT AUTHORITY\\SYSTEM   1/8/2024' },
      { t: 'http://support.microsoft.com/?kbid=2491683  Security Update  KB2491683  NT AUTHORITY\\SYSTEM   1/8/2024' },
      { t: 'http://support.microsoft.com/?kbid=2506014  Security Update  KB2506014  NT AUTHORITY\\SYSTEM   1/8/2024' },
      { t: '' },
      { t: '[!] Notably absent: KB4012212 (MS17-010 patch)', cls: 'y' },
    ]};

    if (/^wmic\s+os\s+get/i.test(cmd)) return { lines: [
      { t: 'BuildNumber  Caption                            Version', cls: 'b' },
      { t: '7601         Microsoft Windows 7 Ultimate       6.1.7601' },
    ]};

    if (cmd === 'arp -a') return { lines: [
      { t: '' },
      { t: 'Interface: 10.10.10.10 --- 0xb', cls: 'b' },
      { t: '  Internet Address      Physical Address      Type' },
      { t: '  10.10.10.1            00-50-56-c0-00-08     dynamic' },
      { t: '  10.10.10.5            00-0c-29-3a-7f-2e     dynamic' },
      { t: '  10.10.10.20           00-0c-29-1d-44-91     dynamic' },
      { t: '  10.10.10.50           00-0c-29-9b-15-c8     dynamic' },
      { t: '  10.10.10.255          ff-ff-ff-ff-ff-ff     static' },
      { t: '  224.0.0.22            01-00-5e-00-00-16     static' },
    ]};

    if (cmd === 'route print') return { lines: [
      { t: '===========================================================================', cls: 'd' },
      { t: 'Interface List' },
      { t: ' 11...00 0c 29 1d 44 91 ......Intel(R) PRO/1000 MT Network Connection' },
      { t: '  1...........................Software Loopback Interface 1' },
      { t: '===========================================================================', cls: 'd' },
      { t: '' },
      { t: 'IPv4 Route Table', cls: 'b' },
      { t: '===========================================================================', cls: 'd' },
      { t: 'Active Routes:' },
      { t: 'Network Destination        Netmask          Gateway       Interface  Metric' },
      { t: '          0.0.0.0          0.0.0.0       10.10.10.1     10.10.10.10     10' },
      { t: '       10.10.10.0    255.255.255.0         On-link      10.10.10.10    266' },
      { t: '      10.10.10.10  255.255.255.255         On-link      10.10.10.10    266' },
      { t: '        127.0.0.0        255.0.0.0         On-link        127.0.0.1    306' },
      { t: '===========================================================================', cls: 'd' },
    ]};

    if (cmd === 'netstat -ano' || cmd === 'netstat -an' || cmd === 'netstat') return { lines: [
      { t: '' },
      { t: 'Active Connections', cls: 'b' },
      { t: '' },
      { t: '  Proto  Local Address          Foreign Address        State           PID' },
      { t: '  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       824' },
      { t: '  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4', cls: 'y' },
      { t: '  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1148' },
      { t: '  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4' },
      { t: '  TCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       452' },
      { t: '  TCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       848' },
      { t: '  TCP    10.10.10.10:139        0.0.0.0:0              LISTENING       4' },
      { t: '  TCP    10.10.10.10:49158      10.10.10.5:4444        ESTABLISHED     1337', cls: 'g' },
      { t: '  UDP    0.0.0.0:137            *:*                                    4' },
      { t: '  UDP    0.0.0.0:138            *:*                                    4' },
      { t: '  UDP    0.0.0.0:5355           *:*                                    1024' },
    ]};

    if (cmd === 'net view') return { lines: [
      { t: 'Server Name            Remark', cls: 'b' },
      { t: '-------------------------------------------------------------------------------', cls: 'd' },
      { t: '\\\\DC01' },
      { t: '\\\\WS-FINANCE-01' },
      { t: '\\\\WS-HR-02' },
      { t: '\\\\FILESERVER01' },
      { t: 'The command completed successfully.', cls: 'g' },
    ]};

    if (cmd === 'net view /domain') return { lines: [
      { t: 'Domain', cls: 'b' },
      { t: '-------------------------------------------------------------------------------', cls: 'd' },
      { t: 'CORP' },
      { t: 'WORKGROUP' },
      { t: 'The command completed successfully.', cls: 'g' },
    ]};

    if (cmd === 'net user /domain') return { lines: [
      { t: 'User accounts for \\\\DC01.corp.local', cls: 'b' },
      { t: '-------------------------------------------------------------------------------', cls: 'd' },
      { t: 'Administrator            Guest                    krbtgt' },
      { t: 'john.doe                 jane.smith               r.brown' },
      { t: 'svc_backup               svc_sql                  svc_web' },
      { t: 'svc_iis                  helpdesk                 it.admin' },
      { t: 'The command completed successfully.', cls: 'g' },
    ]};

    if (/^net\s+group\s+"domain admins"\s+\/domain$/i.test(cmd)) return { lines: [
      { t: 'Group name     Domain Admins', cls: 'b' },
      { t: 'Comment        Designated administrators of the domain' },
      { t: '' },
      { t: 'Members', cls: 'b' },
      { t: '-------------------------------------------------------------------------------', cls: 'd' },
      { t: 'Administrator            it.admin                 svc_backup', cls: 'g' },
      { t: 'The command completed successfully.', cls: 'g' },
    ]};

    if (/^net\s+group\s+"enterprise admins"\s+\/domain$/i.test(cmd)) return { lines: [
      { t: 'Group name     Enterprise Admins', cls: 'b' },
      { t: 'Comment        Designated administrators of the enterprise' },
      { t: '' },
      { t: 'Members', cls: 'b' },
      { t: '-------------------------------------------------------------------------------', cls: 'd' },
      { t: 'Administrator', cls: 'g' },
      { t: 'The command completed successfully.', cls: 'g' },
    ]};

    if (cmd === 'nltest /domain_trusts') return { lines: [
      { t: 'List of domain trusts:', cls: 'b' },
      { t: '    0: CORP corp.local (NT 5) (Forest Tree Root) (Primary Domain) (Native)' },
      { t: '    1: PARTNER partner.local (NT 5) (Forest: 1)' },
      { t: 'The command completed successfully', cls: 'g' },
    ]};

    if (cmd === 'set') return { lines: [
      { t: 'ALLUSERSPROFILE=C:\\ProgramData' },
      { t: 'APPDATA=C:\\Users\\Administrator\\AppData\\Roaming' },
      { t: 'COMPUTERNAME=DC01' },
      { t: 'ComSpec=C:\\Windows\\system32\\cmd.exe' },
      { t: 'HOMEDRIVE=C:' },
      { t: 'HOMEPATH=\\Users\\Administrator' },
      { t: 'LOGONSERVER=\\\\DC01', cls: 'y' },
      { t: 'NUMBER_OF_PROCESSORS=1' },
      { t: 'OS=Windows_NT' },
      { t: 'Path=C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem' },
      { t: 'PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC' },
      { t: 'PROCESSOR_ARCHITECTURE=AMD64' },
      { t: 'PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 158 Stepping 9, GenuineIntel' },
      { t: 'PUBLIC=C:\\Users\\Public' },
      { t: 'SystemDrive=C:' },
      { t: 'SystemRoot=C:\\Windows' },
      { t: 'TEMP=C:\\Users\\ADMINI~1\\AppData\\Local\\Temp' },
      { t: 'USERDNSDOMAIN=CORP.LOCAL', cls: 'y' },
      { t: 'USERDOMAIN=CORP', cls: 'y' },
      { t: 'USERNAME=Administrator' },
      { t: 'USERPROFILE=C:\\Users\\Administrator' },
      { t: 'windir=C:\\Windows' },
    ]};

    if (cmd === 'tasklist') return { stepLines: [
      { t: 'Image Name                     PID Session Name        Session#    Mem Usage', cls: 'b',        delay: jitter(220, 80) },
      { t: '========================= ======== ================ =========== ============', cls: 'd',        delay: jitter(40, 15) },
      { t: 'System Idle Process              0 Services                   0          4 K',                  delay: jitter(35, 15) },
      { t: 'System                           4 Services                   0        268 K',                  delay: jitter(28, 12) },
      { t: 'smss.exe                       272 Services                   0      1,068 K',                  delay: jitter(28, 12) },
      { t: 'csrss.exe                      352 Services                   0      4,892 K',                  delay: jitter(32, 14) },
      { t: 'wininit.exe                    412 Services                   0      3,920 K',                  delay: jitter(28, 12) },
      { t: 'services.exe                   452 Services                   0      6,784 K',                  delay: jitter(32, 14) },
      { t: 'lsass.exe                      460 Services                   0     11,236 K', cls: 'y',        delay: jitter(36, 14) },
      { t: 'svchost.exe                    824 Services                   0      9,012 K',                  delay: jitter(28, 12) },
      { t: 'spoolsv.exe                    848 Services                   0      8,448 K',                  delay: jitter(28, 12) },
      { t: 'explorer.exe                  1980 Console                    1     22,108 K',                  delay: jitter(38, 14) },
      { t: 'cmd.exe                       1337 Services                   0      2,840 K', cls: 'g',        delay: jitter(32, 12) },
      { t: 'conhost.exe                   1338 Services                   0      4,212 K',                  delay: jitter(28, 12) },
    ]};

    if (cmd === 'tasklist /svc') return { stepLines: [
      { t: 'Image Name                     PID Services', cls: 'b',                                         delay: jitter(280, 90) },
      { t: '========================= ======== ============================================', cls: 'd',     delay: jitter(40, 15) },
      { t: 'System Idle Process              0 N/A',                                                         delay: jitter(35, 15) },
      { t: 'System                           4 N/A',                                                         delay: jitter(28, 12) },
      { t: 'smss.exe                       272 N/A',                                                         delay: jitter(28, 12) },
      { t: 'services.exe                   452 N/A',                                                         delay: jitter(32, 14) },
      { t: 'lsass.exe                      460 KeyIso, SamSs, VaultSvc',                                     delay: jitter(38, 14) },
      { t: 'svchost.exe                    624 DcomLaunch, PlugPlay, Power',                                 delay: jitter(34, 14) },
      { t: 'svchost.exe                    688 RpcEptMapper, RpcSs',                                         delay: jitter(28, 12) },
      { t: 'svchost.exe                    824 Dhcp, EventLog, lmhosts',                                     delay: jitter(28, 12) },
      { t: 'svchost.exe                    900 LanmanServer, Schedule, SENS',                                delay: jitter(28, 12) },
      { t: 'spoolsv.exe                    848 Spooler',                                                     delay: jitter(28, 12) },
      { t: 'sqlservr.exe                  1148 MSSQLSERVER', cls: 'y',                                       delay: jitter(38, 14) },
      { t: 'cmd.exe                       1337 N/A',                                                         delay: jitter(32, 12) },
    ]};

    if (cmd === 'sc query') return { lines: [
      { t: 'SERVICE_NAME: BFE', cls: 'b' },
      { t: 'DISPLAY_NAME: Base Filtering Engine' },
      { t: '        TYPE               : 20  WIN32_SHARE_PROCESS' },
      { t: '        STATE              : 4  RUNNING' },
      { t: '' },
      { t: 'SERVICE_NAME: LanmanServer', cls: 'b' },
      { t: 'DISPLAY_NAME: Server' },
      { t: '        TYPE               : 20  WIN32_SHARE_PROCESS' },
      { t: '        STATE              : 4  RUNNING' },
      { t: '' },
      { t: 'SERVICE_NAME: MSSQLSERVER', cls: 'b' },
      { t: 'DISPLAY_NAME: SQL Server (MSSQLSERVER)' },
      { t: '        TYPE               : 10  WIN32_OWN_PROCESS' },
      { t: '        STATE              : 4  RUNNING' },
      { t: '' },
      { t: 'SERVICE_NAME: Spooler', cls: 'b' },
      { t: 'DISPLAY_NAME: Print Spooler' },
      { t: '        TYPE               : 110 WIN32_OWN_PROCESS  (interactive)' },
      { t: '        STATE              : 4  RUNNING' },
      { t: '' },
      { t: 'SERVICE_NAME: TermService' },
      { t: 'DISPLAY_NAME: Remote Desktop Services' },
      { t: '        STATE              : 4  RUNNING' },
    ]};

    if (/^schtasks\s+\/query/i.test(cmd)) return { lines: [
      { t: '' },
      { t: 'Folder: \\', cls: 'b' },
      { t: 'TaskName                                 Next Run Time          Status' },
      { t: '======================================== ====================== ===============' },
      { t: 'GoogleUpdateTaskMachineCore              1/16/2024 8:00:00 AM   Ready' },
      { t: 'GoogleUpdateTaskMachineUA                1/15/2024 9:30:00 PM   Ready' },
      { t: 'BackupJob_Nightly                        1/16/2024 2:00:00 AM   Ready', cls: 'y' },
      { t: 'SystemSoundsService                      N/A                    Disabled' },
    ]};

    if (/^reg\s+query\s+.*currentversion\\?run/i.test(cmd)) return { lines: [
      { t: '' },
      { t: 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', cls: 'b' },
      { t: '    VMware Tools    REG_SZ    "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" -n vmusr' },
      { t: '    SecurityHealth  REG_SZ    %windir%\\system32\\SecurityHealthSystray.exe' },
      { t: '    BackupAgent     REG_SZ    "C:\\Program Files\\BackupCo\\agent.exe" --user svc_backup --pwd Backup2024!', cls: 'y' },
    ]};

    if (cmd === 'cmdkey /list') return { lines: [
      { t: '' },
      { t: 'Currently stored credentials:', cls: 'b' },
      { t: '' },
      { t: '    Target: Domain:interactive=CORP\\svc_backup', cls: 'y' },
      { t: '    Type: Domain Password' },
      { t: '    User: CORP\\svc_backup' },
      { t: '' },
      { t: '    Target: LegacyGeneric:target=fileserver01.corp.local', cls: 'y' },
      { t: '    Type: Generic' },
      { t: '    User: CORP\\Administrator' },
    ]};

    if (/^findstr\s+/i.test(cmd)) {
      // Match the classic password-grep idiom
      if (/password/i.test(cmd)) return { lines: [
        { t: 'C:\\inetpub\\wwwroot\\web.config:    <add key="DBPassword" value="Sql$erver2024!" />', cls: 'g' },
        { t: 'C:\\Users\\Administrator\\Documents\\passwords_old.txt:Administrator: P@ssw0rd2022!', cls: 'g' },
        { t: 'C:\\Program Files\\BackupCo\\config.ini:backup_password=Backup2024!', cls: 'g' },
        { t: 'C:\\Users\\Administrator\\AppData\\Roaming\\notes.xml:    <password>Sup3rS3cret!</password>', cls: 'g' },
      ]};
      return { lines: [{ t: 'FINDSTR: No match found', cls: 'd' }] };
    }

    // ── procdump.exe — dump LSASS process memory ─────────────────────────────
    if (/^procdump(\.exe)?\s.+lsass(\.exe)?/i.test(cmd)) {
      const wantsAccept = /-accepteula/i.test(cmd);
      const dumpPath = (cmd.match(/[Cc]:\\[^\s]+\.dmp/) || ['C:\\Windows\\Temp\\lsass.dmp'])[0];
      const stepLines = [];
      if (!wantsAccept) {
        stepLines.push(
          { t: '',                                                                                 delay: jitter(80, 30) },
          { t: 'ProcDump v11.0 - Sysinternals process dump utility',                      cls: 'b', delay: jitter(15, 10) },
          { t: 'Copyright (C) 2009-2022 Mark Russinovich and Andrew Richards',            cls: 'd', delay: jitter(15, 10) },
          { t: 'Sysinternals - www.sysinternals.com',                                     cls: 'd', delay: jitter(15, 10) },
          { t: '',                                                                                 delay: jitter(15, 10) },
          { t: 'You have not accepted the Sysinternals license terms.',                   cls: 'r', delay: jitter(220, 60) },
          { t: 'Use the -accepteula option to accept the EULA.',                          cls: 'y', delay: jitter(15, 10) },
        );
        return { stepLines };
      }
      stepLines.push(
        { t: '',                                                                                   delay: jitter(80, 30) },
        { t: 'ProcDump v11.0 - Sysinternals process dump utility',                        cls: 'b', delay: jitter(15, 10) },
        { t: 'Copyright (C) 2009-2022 Mark Russinovich and Andrew Richards',              cls: 'd', delay: jitter(15, 10) },
        { t: 'Sysinternals - www.sysinternals.com',                                       cls: 'd', delay: jitter(15, 10) },
        { t: 'With contributions from Andrew Richards',                                   cls: 'd', delay: jitter(15, 10) },
        { t: '',                                                                                   delay: jitter(420, 140) },
        { t: '[19:42:11] Dump 1 initiated: ' + dumpPath,                                  cls: 'b', delay: jitter(680, 200) },
        { t: '[19:42:14] Dump 1 writing: Estimated dump file size is 47 MB.',                      delay: jitter(2200, 600) },
        { t: '[19:42:21] Dump 1 complete: 47 MB written in 6.8 seconds',                  cls: 'g', delay: jitter(6800, 1400) },
        { t: '[19:42:21] Dump count reached.',                                            cls: 'g', delay: jitter(280, 80) },
        { t: '',                                                                                   delay: jitter(50, 20) },
      );
      SIM.lsassDumped = true;
      return { stepLines };
    }

    // ── rundll32 comsvcs.dll MiniDump (LOLBAS LSASS dump trick) ──────────────
    if (/^rundll32(\.exe)?\s+.*comsvcs\.dll.*minidump/i.test(cmd)) {
      const hasArgs = /minidump\s+\d+\s+\S+/i.test(cmd);
      if (!hasArgs) {
        return { stepLines: [
          { t: 'Error: missing arguments. Usage: rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <PID> <OutputPath> full', cls: 'r', delay: jitter(120, 40) },
        ]};
      }
      SIM.lsassDumped = true;
      // comsvcs.dll MiniDump prints nothing on success — it writes the file and exits silently.
      return { stepLines: [
        { t: '', delay: jitter(2400, 800) },
      ]};
    }

    // ── reg save HKLM\SAM / HKLM\SYSTEM (offline SAM dump) ───────────────────
    if (/^reg\s+save\s+hklm\\(sam|system|security)\s+/i.test(cmd)) {
      return { stepLines: [
        { t: '',                                                                          delay: jitter(180, 60) },
        { t: 'The operation completed successfully.',                            cls: 'g', delay: jitter(420, 140) },
      ]};
    }

    // ── tasklist | findstr lsass (find PID before comsvcs trick) ─────────────
    if (/^tasklist\s.*lsass/i.test(cmd) || /tasklist.*\|\s*findstr.*lsass/i.test(cmd)) {
      return { stepLines: [
        { t: 'lsass.exe                      460 Services                   0     11,236 K', cls: 'y', delay: jitter(120, 40) },
      ]};
    }

    // ── wevtutil cl <log> — clear an event log (writes Event 1102 to Security) ─
    if (/^wevtutil\s+cl\s+\S+/i.test(cmd)) {
      // wevtutil cl is silent on success — but the act creates Event ID 1102.
      return { stepLines: [
        { t: '', delay: jitter(380, 120) },
      ]};
    }

    // ── download — Meterpreter-only, hint the user to exit shell first ──────
    if (/^download\s/i.test(cmd)) {
      return { lines: [
        { t: `'download' is not recognized as an internal or external command,`, cls: 'r' },
        { t: `operable program or batch file.`, cls: 'r' },
        { t: `[sim] download is a Meterpreter command — type 'exit' first to leave the cmd.exe shell.`, cls: 'y' },
      ]};
    }

    // ── del <path> — delete a file (silent on success) ──────────────────────
    if (/^del\s+(\/[a-z]\s+)*\S+/i.test(cmd)) {
      const m = cmd.match(/^del\s+(?:\/[a-z]\s+)*(\S+)/i);
      const target = m ? m[1] : '';
      const targetLower = target.toLowerCase();
      // If they're nuking the lsass dump, drop the flag so subsequent dir doesn't show it
      if (targetLower.includes('lsass.dmp') && SIM.lsassDumped) {
        SIM.lsassDumped = false;
      }
      return { stepLines: [
        { t: '', delay: jitter(120, 40) },
        // Real `del` is silent on success — return to prompt with a single blank line.
      ]};
    }

    if (cmd === 'cls') return { clear: true };
    if (cmd === 'echo %cd%' || cmd === 'cd') return { lines: [{ t: SIM.winCwd }] };
    if (/^(ls|cat|pwd|grep|nano|vim|bash|sh|python3?)(\s|$)/.test(cmd)) {
      return { lines: [{ t: `'${cmd.split(' ')[0]}' is not recognized as an internal or external command,\noperable program or batch file.`, cls: 'r' }] };
    }
    return { lines: [{ t: `'${cmd.split(' ')[0]}' is not recognized as an internal or external command,\noperable program or batch file.`, cls: 'r' }] };
  }

  if (cmd === 'clear') return { clear: true };

  // ── msfconsole prompt — reject anything that isn't a known msf verb ───────
  if (SIM.msf && !SIM.msfMeter && !SIM.msfMeterWin) {
    const verb = cmd.split(' ')[0].toLowerCase();
    const knownMsfVerbs = new Set([
      'use','set','setg','unset','unsetg','show','run','exploit','check',
      'sessions','search','info','back','exit','quit','help','?','banner',
      'version','save','get','getg','spool','jobs','load','reload','clear',
    ]);
    if (!knownMsfVerbs.has(verb)) {
      return { lines: [{ t: `[-] Unknown command: ${verb}.`, cls: 'r' }] };
    }
  }

  // ── Meterpreter shell mode ────────────────────────────────────────────────
  if (SIM.msf && SIM.msfMeter && !SIM.msfMeterWin) {
    // exit/quit in meterpreter only closes the session, returns to msf prompt
    if (cmd === 'exit' || cmd === 'quit') {
      SIM.msfMeter = false;
      SIM.msfMeterId = null;
      SIM.msfSessions = [];
      return { openMsf: true, msfEcho: '[*] Shutting down Meterpreter...\n\n[*] 10.10.10.5 - Meterpreter session 1 closed.  Reason: User exit' };
    }
    // Valid meterpreter built-in commands
    if (cmd === 'whoami' || cmd === 'getuid') {
      return { openMsf: true, msfEcho: 'Server username: NT AUTHORITY\\SYSTEM' };
    }
    if (cmd === 'pwd' || cmd === 'getwd') {
      return { openMsf: true, msfEcho: 'C:\\Windows\\system32' };
    }
    if (cmd === 'ls' || cmd === 'dir') {
      return { openMsf: true, msfEcho: [
        'Listing: C:\\Windows\\system32',
        '==============================',
        '',
        'Mode              Size     Type  Last modified              Name',
        '----              ----     ----  -------------              ----',
        '40777/rwxrwxrwx   4096     dir   2024-01-15 14:23:01 +0000  config',
        '40777/rwxrwxrwx   4096     dir   2024-01-15 14:23:01 +0000  drivers',
        '40777/rwxrwxrwx   4096     dir   2024-01-15 14:23:01 +0000  wbem',
        '100666/rw-rw-rw-  32768    fil   2024-01-15 14:23:01 +0000  cmd.exe',
        '100666/rw-rw-rw-  45056    fil   2024-01-15 14:23:01 +0000  net.exe',
        '100666/rw-rw-rw-  36864    fil   2024-01-15 14:23:01 +0000  whoami.exe',
        '100666/rw-rw-rw-  28672    fil   2024-01-15 14:23:01 +0000  ipconfig.exe',
      ].join('\n') };
    }
    if (cmd === 'ps') {
      return { openMsf: true, msfEcho: [
        'Process List',
        '============',
        '',
        ' PID   PPID  Name                  Arch  Session  User                          Path',
        ' ---   ----  ----                  ----  -------  ----                          ----',
        ' 0     0     [System Process]',
        ' 4     0     System                x64   0',
        ' 416   4     smss.exe              x64   0        NT AUTHORITY\\SYSTEM',
        ' 544   536   csrss.exe             x64   0        NT AUTHORITY\\SYSTEM',
        ' 592   536   wininit.exe           x64   0        NT AUTHORITY\\SYSTEM',
        ' 604   584   csrss.exe             x64   1        NT AUTHORITY\\SYSTEM',
        ' 648   592   services.exe          x64   0        NT AUTHORITY\\SYSTEM',
        ' 656   592   lsass.exe             x64   0        NT AUTHORITY\\SYSTEM',
        ' 760   648   svchost.exe           x64   0        NT AUTHORITY\\SYSTEM',
        ' 828   648   svchost.exe           x64   0        NT AUTHORITY\\NETWORK SERVICE',
        ' 1024  648   spoolsv.exe           x64   0        NT AUTHORITY\\SYSTEM',
        ' 1337  648   cmd.exe               x64   0        NT AUTHORITY\\SYSTEM           C:\\Windows\\system32\\cmd.exe',
      ].join('\n') };
    }
    if (cmd === 'sysinfo') {
      return { openMsf: true, msfEcho: [
        'Computer        : WIN7-PC',
        'OS              : Windows 7 (6.1 Build 7601, Service Pack 1).',
        'Architecture    : x64',
        'System Language : en_US',
        'Domain          : WORKGROUP',
        'Logged On Users : 2',
        'Meterpreter     : x64/windows',
      ].join('\n') };
    }
    if (cmd === 'ipconfig' || cmd === 'ifconfig') {
      return { openMsf: true, msfEcho: [
        'Interface  1',
        '============',
        'Name         : Software Loopback Interface 1',
        'Hardware MAC : 00:00:00:00:00:00',
        'MTU          : 4294967295',
        'IPv4 Address : 127.0.0.1',
        'IPv4 Netmask : 255.0.0.0',
        '',
        'Interface 11',
        '============',
        'Name         : Intel(R) PRO/1000 MT Network Connection',
        'Hardware MAC : 00:0c:29:3a:bc:de',
        'MTU          : 1500',
        'IPv4 Address : 10.10.10.10',
        'IPv4 Netmask : 255.255.255.0',
        'IPv4 Gateway : 10.10.10.1',
      ].join('\n') };
    }
    // Block everything else that isn't a real meterpreter command
    if (/^(cat|grep|nano|vim|bash|sh|find|echo|ss|netstat|arp|ip|uname|id|df|free|top|htop|history|type|cls)(\s|$)/.test(cmd)) {
      return { lines: [{ t: `[-] Unknown command: ${cmd.split(' ')[0]}`, cls: 'r' }] };
    }
  }

  // ── Meterpreter Windows shell (shell command) ──────────────────────────────
  if (SIM.msf && SIM.msfMeterWin) {
    if (cmd === 'exit' || cmd === 'logout') {
      SIM.msfMeterWin = false;
      return { lines: [{ t: '' }] };
    }
    if (/^(ls|cat|pwd|grep|nano|vim|bash|sh|python3?)(\s|$)/.test(cmd)) {
      return { lines: [{ t: `'${cmd.split(' ')[0]}' is not recognized as an internal or external command,\noperable program or batch file.`, cls: 'r' }] };
    }
    // Route through Windows shell block by temporarily setting windowsShell=true, msfMeterWin=false
    SIM.windowsShell = true;
    SIM.msfMeterWin = false;
    const _res = runCommand(cmd);
    SIM.windowsShell = false;
    SIM.msfMeterWin = true;
    return _res;
  }
  if (cmd === 'reset') {
    const savedUser = localStorage.getItem('hacklet_user') || 'rembrandt';
    SIM.user = savedUser;
    SIM.cwd = '/home/' + savedUser;
    SIM.windowsShell = false;
    SIM.winCwd = 'C:\\Windows\\system32';
    SIM.hashesOnDisk = false;
    SIM.lootExfiltrated = false;
    SIM.dirs = new Set();
    SIM.msf = false; SIM.msfModule = null; SIM.msfOpts = {};
    SIM.msfSessions = []; SIM.msfMeter = false; SIM.msfMeterId = null; SIM.msfMeterWin = false;
    SIM.legacyPwned = false;
    SIM.files = Object.fromEntries(Object.entries(SIM.files).filter(([k]) => k.startsWith('/etc') || k.startsWith('/home/' + savedUser + '/.') || k === '/home/' + savedUser + '/notes.txt' || k === '/root/notes.txt'));
    if (typeof CTF !== 'undefined') CTF._reset?.();
    return { clear: true };
  }
  if (cmd === 'exit' || cmd === 'logout') {
    if (SIM.msf) {
      SIM.msf = false; SIM.msfModule = null; SIM.msfMeter = false; SIM.msfMeterWin = false;
      return { lines: [{ t: '' }] };
    }
    if (SIM.isRoot) return { dropRoot: true };
    return { lines: [{ t: 'There is no job to resume.', cls: 'd' }] };
  }

  // Walk handlers in order, first match wins
  for (const h of HANDLERS) {
    if (h.match(cmd)) {
      if (h.waitSudo) {
        // Already root? Skip the password prompt and re-dispatch the bare command.
        if (isRoot()) return runCommand(cmd.replace(/^sudo\s*/, ''));
        return { waitSudo: true, pendingCmd: cmd.replace(/^sudo\s*/, '') };
      }
      if (h.requireRoot && !isRoot()) {
        return { lines: [{ t: `E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\nE: Unable to acquire the dpkg frontend lock, are you root?\nHint: try  sudo ${cmd}`, cls: 'r' }] };
      }
      if (h.after && !h.stepLines) h.after(cmd);
      const event = typeof h.event === 'function' ? h.event(cmd) : h.event;
      const lines = h.lines.map(l => ({
        t: typeof l.t === 'function' ? l.t(cmd) : l.t,
        cls: typeof l.cls === 'function' ? l.cls(cmd) : (l.cls || ''),
      }));
      // openEditor result — returned as object inside lines[0].t
      if (lines.length === 1 && lines[0].t && typeof lines[0].t === 'object' && lines[0].t.openEditor) {
        return lines[0].t;
      }
      // openMsf result
      if (lines.length === 1 && lines[0].t && typeof lines[0].t === 'object' && lines[0].t.openMsf) {
        return lines[0].t;
      }
      // history result
      if (lines.length === 1 && lines[0].t && typeof lines[0].t === 'object' && lines[0].t.history) {
        return lines[0].t;
      }
      const loadTime = typeof h.loadTime === 'function' ? h.loadTime(cmd) : (h.loadTime || 0);
      return { id: h.id || null, lines, event, loadTime, progressFn: h.progressFn || null,
               progressOnEnter: h.progressOnEnter || false,
               liveDisplay: h.liveDisplay || false, displayFn: h.displayFn || null, refreshMs: h.refreshMs || 2000,
               stepLines: h.stepLines ? h.stepLines.map(s => ({ ...s, t: typeof s.t === 'function' ? s.t(cmd) : s.t })) : null, after: h.stepLines ? h.after : null };
    }
  }

  // Unknown command — friendly hint that points at the lab objectives
  const tool = cmd.split(' ')[0];
  return { lines: [
    { t: `[sim] That \`${tool}\` invocation isn't wired up in this lab.`, cls: 'y' },
    { t: `       Check the objectives panel on the right — each step shows the exact command to run.`, cls: 'd' },
  ] };
}

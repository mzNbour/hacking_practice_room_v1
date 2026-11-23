import {
  HttpLogEntry,
  HttpRequest,
  ProxyToolMode,
  RemoteSession,
  SystemState,
  TargetServer,
  TerminalLine,
  VirtualFile,
} from '../types/lab';
import { executeHttpRequest, findTargetByHost, getDiscoveredPaths, parseTargetUrl } from './httpEngine';
import { getDirChildren, resolvePath } from './vfs';

export interface CommandContext {
  system: SystemState;
  setSystem: React.Dispatch<React.SetStateAction<SystemState>>;
  fs: Record<string, VirtualFile>;
  setFs: React.Dispatch<React.SetStateAction<Record<string, VirtualFile>>>;
  targets: TargetServer[];
  mutateTarget: (targetId: string, updater: (prev: TargetServer) => TargetServer) => void;
  remoteSession: RemoteSession | null;
  setRemoteSession: React.Dispatch<React.SetStateAction<RemoteSession | null>>;
  onOpenProxyTool: (tool: ProxyToolMode, url?: string) => void;
  onLogHttp: (entry: Omit<HttpLogEntry, 'id' | 'timestamp'>) => void;
  onSubmitFlag: (flag: string) => { ok: boolean; message: string };
  onClearTerminal: () => void;
}

function line(kind: TerminalLine['kind'], text: string): TerminalLine {
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    kind,
    text,
  };
}

function tokenizeCommand(input: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else {
        current += ch;
      }
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (/\s/.test(ch)) {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }
  if (current.length > 0) tokens.push(current);
  return tokens;
}

export const ALL_COMMANDS = [
  // System & Network (21)
  'ip',
  'ss',
  'dig',
  'resolvectl',
  'systemctl',
  'journalctl',
  'apt',
  'timedatectl',
  'chronyc',
  'snap',
  'netplan',
  'ufw',
  'do-release-upgrade',
  'ubuntu-drivers',
  'pro',
  'hostnamectl',
  'localectl',
  'loginctl',
  'networkctl',
  'nmcli',
  'resolvconf',
  // Security & Pentesting (22)
  'burpsuite',
  'owasp-zap',
  'zaproxy',
  'caido',
  'nikto',
  'ffuf',
  'gobuster',
  'nuclei',
  'wappalyzer',
  'sqlmap',
  'wpscan',
  'hydra',
  'dirb',
  'dirbuster',
  'wfuzz',
  'whatweb',
  'wapiti',
  'skipfish',
  'commix',
  'xsser',
  'joomscan',
  'weevely',
  'nmap',
  // Core Shell
  'ls',
  'll',
  'cd',
  'pwd',
  'cat',
  'head',
  'tail',
  'grep',
  'find',
  'echo',
  'touch',
  'mkdir',
  'rm',
  'cp',
  'mv',
  'chmod',
  'whoami',
  'id',
  'uname',
  'hostname',
  'env',
  'export',
  'clear',
  'history',
  'help',
  'man',
  'curl',
  'wget',
  'ping',
  'nc',
  'ssh',
  'python3',
  'base64',
  'sudo',
  'ps',
  'df',
  'free',
  'uptime',
  'date',
  'which',
  'submit',
  'exit',
];

function handleRemoteShellCommand(rawInput: string, ctx: CommandContext): TerminalLine[] {
  const session = ctx.remoteSession!;
  const target = ctx.targets.find((t) => t.id === session.targetId);
  const tokens = tokenizeCommand(rawInput.trim());
  if (tokens.length === 0) return [];

  let isSudo = false;
  let cmd = tokens[0];
  let args = tokens.slice(1);

  if (cmd === 'sudo') {
    if (args[0] === '-l') {
      const rule = target?.sshUser?.sudoRule || '(ALL) NOPASSWD: /usr/bin/cat /root/*';
      return [
        line(
          'output',
          `Matching Defaults entries for ${session.user} on ${session.hostname}:\n    env_reset, mail_badpass\n\nUser ${session.user} may run the following commands on ${session.hostname}:\n    ${rule}`
        ),
      ];
    }
    if (args[0] === 'su' || args[0] === '-i') {
      ctx.setRemoteSession({ ...session, user: 'root', isRoot: true, cwd: '/root' });
      return [line('success', `Escalated to root on ${session.hostname}!`)];
    }
    isSudo = true;
    cmd = args[0] || '';
    args = args.slice(1);
  }

  switch (cmd) {
    case 'exit':
    case 'logout':
      ctx.setRemoteSession(null);
      return [line('info', `Connection to ${session.ip} closed.`)];
    case 'clear':
      ctx.onClearTerminal();
      return [];
    case 'whoami':
      return [line('output', isSudo || session.isRoot ? 'root' : session.user)];
    case 'id':
      return [
        line(
          'output',
          isSudo || session.isRoot
            ? 'uid=0(root) gid=0(root) groups=0(root)'
            : `uid=1001(${session.user}) gid=1001(${session.user}) groups=1001(${session.user})`
        ),
      ];
    case 'pwd':
      return [line('output', session.cwd)];
    case 'hostname':
      return [line('output', session.hostname)];
    case 'uname':
      return [line('output', `Linux ${session.hostname} 6.8.0-45-generic #45-Ubuntu SMP x86_64 GNU/Linux`)];
    case 'cd': {
      const dest = args[0] || (session.isRoot ? '/root' : `/home/${session.user}`);
      const next = resolvePath(session.cwd, dest, session.isRoot ? '/root' : `/home/${session.user}`);
      ctx.setRemoteSession({ ...session, cwd: next });
      return [];
    }
    case 'ls': {
      const dir = args.find((a) => !a.startsWith('-'))
        ? resolvePath(session.cwd, args.find((a) => !a.startsWith('-'))!, session.cwd)
        : session.cwd;
      const files = (target?.remoteFiles || []).filter((f) => f.path.startsWith(dir === '/' ? '/' : dir + '/'));
      if (dir === '/var/www/html' || dir === '/var/www') {
        const names = new Set<string>(['index.html']);
        files.forEach((f) => {
          const rel = f.path.slice(dir.length + 1).split('/')[0];
          if (rel) names.add(rel);
        });
        return [line('output', Array.from(names).join('  '))];
      }
      if (files.length > 0) {
        return [
          line(
            'output',
            files
              .map((f) => `${f.permissions} ${f.owner} ${f.path}`)
              .join('\n')
          ),
        ];
      }
      if (dir === '/root' && (isSudo || session.isRoot)) {
        const rootFiles = (target?.remoteFiles || []).filter((f) => f.path.startsWith('/root/'));
        return [line('output', rootFiles.map((f) => f.path.replace('/root/', '')).join('  ') || '(empty)')];
      }
      return [line('output', 'readme.txt')];
    }
    case 'cat': {
      const fileArg = args[0];
      if (!fileArg) return [line('error', 'cat: missing file operand')];
      const full = resolvePath(session.cwd, fileArg, `/home/${session.user}`);
      const matched = (target?.remoteFiles || []).find((f) => f.path === full || f.path.endsWith('/' + fileArg));
      if (!matched) {
        return [line('error', `cat: ${fileArg}: No such file or directory`)];
      }
      if (matched.path.startsWith('/root/') && !isSudo && !session.isRoot && session.type === 'ssh') {
        return [line('error', `cat: ${matched.path}: Permission denied (hint: try sudo -l)`)];
      }
      return [line(matched.content.includes('FLAG{') ? 'success' : 'output', matched.content)];
    }
    case 'find': {
      const all = (target?.remoteFiles || []).map((f) => f.path).join('\n');
      return [line('output', all || '/var/www/html/index.html')];
    }
    case 'systemctl': {
      return [line('output', `● ${target?.webServer || 'nginx.service'} - active (running) on ${session.hostname}`)];
    }
    case 'help':
      return [
        line(
          'info',
          `Remote shell (${session.type}) commands: ls, cd, pwd, cat, find, id, whoami, sudo -l, sudo cat <file>, systemctl, exit`
        ),
      ];
    default:
      return [line('error', `${cmd}: command not found on remote host ${session.hostname}`)];
  }
}

export function executeTerminalCommand(rawLine: string, ctx: CommandContext): TerminalLine[] {
  const trimmed = rawLine.trim();
  if (!trimmed) return [];

  // Record history
  ctx.setSystem((prev) => ({
    ...prev,
    commandHistory: [...prev.commandHistory, trimmed].slice(-200),
  }));

  if (ctx.remoteSession) {
    return handleRemoteShellCommand(trimmed, ctx);
  }

  // Handle chained && commands sequentially
  if (trimmed.includes('&&') && !trimmed.includes('127.0.0.1')) {
    const parts = trimmed.split('&&').map((s) => s.trim()).filter(Boolean);
    const allOut: TerminalLine[] = [];
    for (const part of parts) {
      allOut.push(...executeSingleCommand(part, ctx));
    }
    return allOut;
  }

  // Handle output redirection `> file` or `>> file`
  const redirMatch = trimmed.match(/^(.+?)\s*(>>|>)\s*([^\s|]+)$/);
  let mainCmd = trimmed;
  let redirMode: '>' | '>>' | null = null;
  let redirTarget = '';
  if (redirMatch && !trimmed.startsWith('echo ')) {
    mainCmd = redirMatch[1].trim();
    redirMode = redirMatch[2] as '>' | '>>';
    redirTarget = redirMatch[3].trim();
  } else if (redirMatch && trimmed.startsWith('echo ')) {
    mainCmd = redirMatch[1].trim();
    redirMode = redirMatch[2] as '>' | '>>';
    redirTarget = redirMatch[3].trim();
  }

  // Handle simple pipe `cmd | grep pattern` or `cmd | head` or `cmd | tail`
  let pipeStage: string | null = null;
  if (mainCmd.includes('|') && !mainCmd.includes('http://') && !mainCmd.includes('https://')) {
    const idx = mainCmd.indexOf('|');
    pipeStage = mainCmd.slice(idx + 1).trim();
    mainCmd = mainCmd.slice(0, idx).trim();
  }

  let output = executeSingleCommand(mainCmd, ctx);

  if (pipeStage) {
    const pipeTokens = tokenizeCommand(pipeStage);
    const pCmd = pipeTokens[0];
    const joined = output.map((o) => o.text).join('\n');
    if (pCmd === 'grep') {
      const pattern = (pipeTokens[1] || '').toLowerCase();
      const filtered = joined
        .split('\n')
        .filter((l) => l.toLowerCase().includes(pattern))
        .join('\n');
      output = filtered ? [line('output', filtered)] : [];
    } else if (pCmd === 'head') {
      const n = parseInt(pipeTokens[1]?.replace('-', '') || '10', 10) || 10;
      output = [line('output', joined.split('\n').slice(0, n).join('\n'))];
    } else if (pCmd === 'tail') {
      const n = parseInt(pipeTokens[1]?.replace('-', '') || '10', 10) || 10;
      output = [line('output', joined.split('\n').slice(-n).join('\n'))];
    } else if (pCmd === 'wc') {
      const linesCount = joined ? joined.split('\n').length : 0;
      output = [line('output', `${linesCount} lines`)];
    }
  }

  if (redirMode && redirTarget) {
    const destPath = resolvePath(ctx.system.cwd, redirTarget, '/home/operator');
    const content = output.map((o) => o.text).join('\n');
    ctx.setFs((prev) => {
      const existing = prev[destPath];
      const nextContent = redirMode === '>>' && existing?.content ? `${existing.content}\n${content}` : content;
      return {
        ...prev,
        [destPath]: {
          type: 'file',
          permissions: '-rw-r--r--',
          owner: ctx.system.username,
          size: nextContent.length,
          modified: '2026-11-22 04:12',
          content: nextContent,
        },
      };
    });
    return [];
  }

  return output;
}

function executeSingleCommand(cmdLine: string, ctx: CommandContext): TerminalLine[] {
  // Support multi-word exact tool names requested by user: "Burp Suite" and "OWASP ZAP"
  let normalizedLine = cmdLine;
  if (/^burp\s+suite\b/i.test(normalizedLine)) {
    normalizedLine = normalizedLine.replace(/^burp\s+suite\b/i, 'burpsuite');
  } else if (/^owasp\s+zap\b/i.test(normalizedLine)) {
    normalizedLine = normalizedLine.replace(/^owasp\s+zap\b/i, 'zaproxy');
  }

  const tokens = tokenizeCommand(normalizedLine);
  if (tokens.length === 0) return [];

  let cmd = tokens[0];
  let args = tokens.slice(1);

  // Strip sudo prefix smoothly for local Ubuntu commands
  if (cmd === 'sudo' && args.length > 0) {
    cmd = args[0];
    args = args.slice(1);
  }

  const lowerCmd = cmd.toLowerCase();

  switch (lowerCmd) {
    // =========================================================================
    // 1. LINUX SYSTEM & NETWORKING COMMANDS (21 requested commands)
    // =========================================================================
    case 'ip': {
      const sub = args[0] || 'a';
      if (sub.startsWith('r')) {
        return [
          line(
            'output',
            `default via ${ctx.system.gateway} dev eth0 proto static\n10.10.0.0/24 dev eth0 proto kernel scope link src ${ctx.system.ipAddress.split('/')[0]}\n10.10.1.0/24 via ${ctx.system.gateway} dev eth0\n10.10.20.0/24 via ${ctx.system.gateway} dev eth0`
          ),
        ];
      }
      if (sub.startsWith('l')) {
        return [
          line(
            'output',
            `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT\n    link/ether 02:42:ac:11:00:05 brd ff:ff:ff:ff:ff:ff`
          ),
        ];
      }
      if (sub.startsWith('n')) {
        const neighs = ctx.targets
          .filter((t) => t.status === 'running')
          .slice(0, 6)
          .map((t, idx) => `${t.ip} dev eth0 lladdr 02:42:0a:0a:0${idx + 1}:10 REACHABLE`)
          .join('\n');
        return [line('output', `${ctx.system.gateway} dev eth0 lladdr 02:42:0a:0a:00:01 REACHABLE\n${neighs}`)];
      }
      return [
        line(
          'output',
          `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    link/ether 02:42:ac:11:00:05 brd ff:ff:ff:ff:ff:ff\n    inet ${ctx.system.ipAddress} brd 10.10.0.255 scope global eth0\n       valid_lft forever preferred_lft forever`
        ),
      ];
    }

    case 'ss': {
      const listening = [
        'Netid  State   Recv-Q  Send-Q   Local Address:Port     Peer Address:Port  Process',
        'tcp    LISTEN  0       128            0.0.0.0:22            0.0.0.0:*      users:(("sshd",pid=612,fd=3))',
        'tcp    LISTEN  0       128          127.0.0.1:8080          0.0.0.0:*      users:(("burp-proxy",pid=880,fd=7))',
        'tcp    LISTEN  0       50           127.0.0.53%lo:53        0.0.0.0:*      users:(("systemd-resolve",pid=412,fd=14))',
        'udp    UNCONN  0       0            127.0.0.53%lo:53        0.0.0.0:*      users:(("systemd-resolve",pid=412,fd=13))',
        'udp    UNCONN  0       0              0.0.0.0:323           0.0.0.0:*      users:(("chronyd",pid=540,fd=5))',
      ];
      return [line('output', listening.join('\n'))];
    }

    case 'dig': {
      const qHost = args.find((a) => !a.startsWith('+') && !a.startsWith('@')) || 'portal.nova-corp.local';
      const short = args.includes('+short');
      const target = findTargetByHost(ctx.targets, qHost);
      if (!target) {
        return [
          line(
            'output',
            short
              ? ''
              : `; <<>> DiG 9.18.28-0ubuntu0.24.04.1 <<>> ${qHost}\n;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 42819\n;; ANSWER SECTION: (0 records)`
          ),
        ];
      }
      if (short) return [line('output', target.ip)];
      return [
        line(
          'output',
          `; <<>> DiG 9.18.28-0ubuntu0.24.04.1 <<>> ${target.hostname}
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51923
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;${target.hostname}.		IN	A

;; ANSWER SECTION:
${target.hostname}.	60	IN	A	${target.ip}

;; Query time: 1 msec
;; SERVER: ${ctx.system.dnsServers[0]}#53(${ctx.system.dnsServers[0]})
;; MSG SIZE  rcvd: 68`
        ),
      ];
    }

    case 'resolvectl': {
      const sub = args[0] || 'status';
      if (sub === 'query' && args[1]) {
        const t = findTargetByHost(ctx.targets, args[1]);
        if (!t) return [line('error', `${args[1]}: resolve call failed: Name not known`)];
        return [line('output', `${t.hostname}: ${t.ip} -- link: eth0 (Data acquired via DNS)`)];
      }
      if (sub === 'flush-caches') {
        return [line('success', 'DNS caches flushed.')];
      }
      return [
        line(
          'output',
          `Global
       Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
resolv.conf mode: stub

Link 2 (eth0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: ${ctx.system.dnsServers[0]}
       DNS Servers: ${ctx.system.dnsServers.join(' ')}
        DNS Domain: nova-corp.local`
        ),
      ];
    }

    case 'systemctl': {
      const sub = args[0] || 'list-units';
      const unitArg = args[1];
      if (sub === 'list-units' || sub === 'list') {
        const rows = ctx.system.units.map(
          (u) => `  ${u.name.padEnd(28)} ${u.load.padEnd(8)} ${u.active.padEnd(9)} ${u.sub.padEnd(10)} ${u.description}`
        );
        return [
          line(
            'output',
            `  UNIT                         LOAD     ACTIVE    SUB        DESCRIPTION\n${rows.join('\n')}\n\n${ctx.system.units.length} loaded units listed.`
          ),
        ];
      }
      if (sub === 'status') {
        if (!unitArg) {
          return [
            line(
              'output',
              `● ${ctx.system.hostname}\n    State: running\n    Units: ${ctx.system.units.length} loaded\n     Jobs: 0 queued\n   Failed: 0 units`
            ),
          ];
        }
        const unit = ctx.system.units.find((u) => u.name === unitArg || u.name === `${unitArg}.service`);
        if (!unit) return [line('error', `Unit ${unitArg}.service could not be found.`)];
        return [
          line(
            unit.active === 'active' ? 'success' : 'warning',
            `● ${unit.name} - ${unit.description}
     Loaded: ${unit.load} (/usr/lib/systemd/system/${unit.name}; enabled)
     Active: ${unit.active} (${unit.sub})
       Docs: man:${unit.name}(8)\n\n${unit.logs.join('\n')}`
          ),
        ];
      }
      if ((sub === 'start' || sub === 'stop' || sub === 'restart') && unitArg) {
        const targetUnit = ctx.system.units.find((u) => u.name === unitArg || u.name === `${unitArg}.service`);
        if (!targetUnit) return [line('error', `Failed to ${sub} ${unitArg}.service: Unit not found.`)];
        const nextActive = sub === 'stop' ? 'inactive' : 'active';
        const nextSub = sub === 'stop' ? 'dead' : 'running';
        ctx.setSystem((prev) => ({
          ...prev,
          units: prev.units.map((u) =>
            u.name === targetUnit.name
              ? {
                  ...u,
                  active: nextActive,
                  sub: nextSub,
                  logs: [...u.logs, `systemd[1]: ${sub === 'stop' ? 'Stopped' : 'Started'} ${u.description}.`],
                }
              : u
          ),
        }));
        return [line('success', `${targetUnit.name} ${sub}ed (${nextActive}/${nextSub}).`)];
      }
      return [line('info', 'Usage: systemctl [list-units|status|start|stop|restart] [UNIT]')];
    }

    case 'journalctl': {
      const uIdx = args.indexOf('-u');
      const unitFilter = uIdx !== -1 ? args[uIdx + 1] : null;
      if (unitFilter) {
        const u = ctx.system.units.find((x) => x.name === unitFilter || x.name === `${unitFilter}.service`);
        if (!u) return [line('output', `-- No entries for ${unitFilter} --`)];
        return [
          line(
            'output',
            u.logs.map((l) => `Nov 22 04:10:12 ${ctx.system.hostname} ${l}`).join('\n')
          ),
        ];
      }
      const allLogs = ctx.system.units.flatMap((u) =>
        u.logs.map((l) => `Nov 22 04:10:12 ${ctx.system.hostname} ${l}`)
      );
      return [line('output', allLogs.slice(-15).join('\n'))];
    }

    case 'apt': {
      const sub = args[0] || '--help';
      if (sub === 'update') {
        return [
          line(
            'output',
            `Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease\nHit:2 http://security.ubuntu.com/ubuntu noble-security InRelease\nReading package lists... Done\nBuilding dependency tree... Done\nAll packages are up to date.`
          ),
        ];
      }
      if (sub === 'list') {
        return [
          line(
            'output',
            `Listing... Done\n${ctx.system.aptPackages
              .map((p) => `${p.name}/noble,now ${p.version} ${p.arch} [installed]`)
              .join('\n')}`
          ),
        ];
      }
      if (sub === 'search' && args[1]) {
        const q = args[1].toLowerCase();
        const matches = ctx.system.aptPackages.filter(
          (p) => p.name.includes(q) || p.description.toLowerCase().includes(q)
        );
        return [
          line(
            'output',
            matches.length
              ? matches.map((p) => `${p.name}/noble ${p.version} ${p.arch}\n  ${p.description}`).join('\n')
              : `No packages matching "${args[1]}".`
          ),
        ];
      }
      if (sub === 'install' && args[1]) {
        const pkgName = args[1];
        if (ctx.system.aptPackages.some((p) => p.name === pkgName)) {
          return [line('output', `${pkgName} is already the newest version.`)];
        }
        ctx.setSystem((prev) => ({
          ...prev,
          aptPackages: [
            ...prev.aptPackages,
            { name: pkgName, version: '1.0.0-1ubuntu1', arch: 'amd64', description: 'User installed package' },
          ],
        }));
        return [
          line(
            'success',
            `Reading package lists... Done\nThe following NEW packages will be installed: ${pkgName}\nUnpacking ${pkgName} (1.0.0-1ubuntu1) ...\nSetting up ${pkgName} ... Done.`
          ),
        ];
      }
      return [line('info', 'Usage: apt [update|upgrade|list|search <pkg>|install <pkg>]')];
    }

    case 'timedatectl': {
      const sub = args[0];
      if (sub === 'set-timezone' && args[1]) {
        ctx.setSystem((prev) => ({ ...prev, timezone: args[1] }));
        return [line('success', `Timezone updated to ${args[1]}`)];
      }
      if (sub === 'list-timezones') {
        return [line('output', 'Asia/Tokyo\nUTC\nAmerica/New_York\nEurope/London\nAsia/Singapore')];
      }
      return [
        line(
          'output',
          `               Local time: Sun 2026-11-22 04:11:31 JST
           Universal time: Sat 2026-11-21 19:11:31 UTC
                 RTC time: Sat 2026-11-21 19:11:31
                Time zone: ${ctx.system.timezone}
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no`
        ),
      ];
    }

    case 'chronyc': {
      const sub = args[0] || 'tracking';
      if (sub === 'sources') {
        return [
          line(
            'output',
            `MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
^* ntp.nova-corp.local           2   6   377    21   +142us[ +188us] +/- 12ms
^+ time.cloudflare.com           3   6   377    24   -412us[ -390us] +/- 28ms`
          ),
        ];
      }
      return [
        line(
          'output',
          `Reference ID    : 0A0A0001 (ntp.nova-corp.local)
Stratum         : 3
Ref time (UTC)  : Sat Nov 21 19:11:20 2026
System time     : 0.000142819 seconds fast of NTP time
Last offset     : +0.000046102 seconds
RMS offset      : 0.000119042 seconds
Leap status     : Normal`
        ),
      ];
    }

    case 'snap': {
      const sub = args[0] || 'list';
      if (sub === 'list') {
        const rows = ctx.system.snapPackages.map(
          (s) => `${s.name.padEnd(20)} ${s.version.padEnd(10)} ${s.rev.padEnd(6)} ${s.tracking.padEnd(14)} ${s.publisher.padEnd(12)} ${s.notes}`
        );
        return [
          line('output', `Name                 Version    Rev    Tracking       Publisher    Notes\n${rows.join('\n')}`),
        ];
      }
      if (sub === 'info' && args[1]) {
        const found = ctx.system.snapPackages.find((s) => s.name === args[1]);
        if (!found) return [line('error', `error: no snap found for "${args[1]}"`)];
        return [
          line(
            'output',
            `name:      ${found.name}\npublisher: ${found.publisher}\ninstalled: ${found.version} (${found.rev})\ntracking:  ${found.tracking}`
          ),
        ];
      }
      if (sub === 'install' && args[1]) {
        ctx.setSystem((prev) => ({
          ...prev,
          snapPackages: [
            ...prev.snapPackages,
            { name: args[1], version: '1.2.0', rev: '10', tracking: 'latest/stable', publisher: 'community', notes: '-' },
          ],
        }));
        return [line('success', `${args[1]} 1.2.0 from community installed`)];
      }
      return [line('info', 'Usage: snap [list|info <pkg>|install <pkg>|refresh]')];
    }

    case 'netplan': {
      const sub = args[0] || 'status';
      if (sub === 'get') {
        return [line('output', ctx.system.netplanConfig)];
      }
      if (sub === 'apply' || sub === 'try') {
        return [line('success', `Netplan configuration applied cleanly (${ctx.system.ipAddress} via eth0).`)];
      }
      return [
        line(
          'output',
          `     Online state: online
    DNS Addresses: ${ctx.system.dnsServers.join(', ')}
       DNS Search: nova-corp.local

●  1: lo ethernet UNKNOWN/UP (unmanaged)
      MAC Address: 00:00:00:00:00:00
        Addresses: 127.0.0.1/8

●  2: eth0 ethernet UP (networkd: eth0)
      MAC Address: 02:42:ac:11:00:05
        Addresses: ${ctx.system.ipAddress}
    DNS Addresses: ${ctx.system.dnsServers.join(', ')}
           Routes: default via ${ctx.system.gateway} (static)`
        ),
      ];
    }

    case 'ufw': {
      const sub = args[0] || 'status';
      if (sub === 'enable') {
        ctx.setSystem((prev) => ({ ...prev, ufwActive: true }));
        return [line('success', 'Firewall is active and enabled on system startup')];
      }
      if (sub === 'disable') {
        ctx.setSystem((prev) => ({ ...prev, ufwActive: false }));
        return [line('warning', 'Firewall stopped and disabled on system startup')];
      }
      if ((sub === 'allow' || sub === 'deny') && args[1]) {
        const portSpec = args[1];
        const action = sub === 'allow' ? 'ALLOW IN' : 'DENY IN';
        ctx.setSystem((prev) => ({
          ...prev,
          ufwRules: [...prev.ufwRules, { id: prev.ufwRules.length + 1, to: portSpec, action, from: 'Anywhere' }],
        }));
        return [line('success', `Rule added: ${action} ${portSpec}`)];
      }
      if (sub === 'delete' && args[1]) {
        const idNum = parseInt(args[1], 10);
        ctx.setSystem((prev) => ({
          ...prev,
          ufwRules: prev.ufwRules.filter((r) => r.id !== idNum),
        }));
        return [line('success', `Deleted rule #${idNum}`)];
      }
      const verbose = args.includes('verbose');
      const numbered = args.includes('numbered');
      if (!ctx.system.ufwActive) return [line('output', 'Status: inactive')];
      const rules = ctx.system.ufwRules
        .map((r, i) =>
          numbered
            ? `[ ${i + 1}] ${r.to.padEnd(22)} ${r.action.padEnd(12)} ${r.from}`
            : `${r.to.padEnd(24)} ${r.action.padEnd(12)} ${r.from}`
        )
        .join('\n');
      return [
        line(
          'output',
          `Status: active${verbose ? '\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)' : ''}\n\nTo                         Action       From\n--                         ------       ----\n${rules}`
        ),
      ];
    }

    case 'do-release-upgrade': {
      return [
        line(
          'output',
          `Checking for a new Ubuntu release\nYour Ubuntu release (${ctx.system.ubuntuVersion}) is currently the latest LTS.\nNo new release found.`
        ),
      ];
    }

    case 'ubuntu-drivers': {
      const sub = args[0] || 'list';
      return [
        line(
          'output',
          sub === 'devices'
            ? `== /sys/devices/pci0000:00/0000:00:02.0 ==\nmodalias : pci:v00001AF4d00001050\nvendor   : Virtio Virtual GPU\nmodel    : Virtio GPU Adapter\ndriver   : xserver-xorg-video-virtio - distro free builtin`
            : `xserver-xorg-video-virtio\nlinux-modules-extra-6.8.0-45-generic`
        ),
      ];
    }

    case 'pro': {
      const sub = args[0] || 'status';
      if (sub === 'security-status') {
        return [
          line(
            'output',
            `${ctx.system.aptPackages.length} packages installed:\n  ${ctx.system.aptPackages.length} packages from Ubuntu Main/Universe\n  0 packages require immediate ESM security updates.`
          ),
        ];
      }
      return [
        line(
          'output',
          `SERVICE          ENTITLED  STATUS    DESCRIPTION
esm-apps         yes       enabled   Expanded Security Maintenance for Applications
esm-infra        yes       enabled   Expanded Security Maintenance for Infrastructure
livepatch        yes       enabled   Canonical Livepatch service

Account: rootrange-lab@nova-corp.local
Subscription: Ubuntu Pro (Lab Attached)`
        ),
      ];
    }

    case 'hostnamectl': {
      if (args[0] === 'set-hostname' && args[1]) {
        ctx.setSystem((prev) => ({ ...prev, hostname: args[1] }));
        return [line('success', `Static hostname set to ${args[1]}`)];
      }
      return [
        line(
          'output',
          ` Static hostname: ${ctx.system.hostname}
       Icon name: computer-vm
         Chassis: vm
      Machine ID: 7f8e9a10c2d445a1b6e3901122334455
         Boot ID: 3c12a8b17e4f44a29d8b21094321fedc
  Virtualization: kvm
Operating System: ${ctx.system.ubuntuVersion}
          Kernel: Linux ${ctx.system.kernelVersion}
    Architecture: x86-64`
        ),
      ];
    }

    case 'localectl': {
      if (args[0] === 'set-locale' && args[1]) {
        const loc = args[1].replace('LANG=', '');
        ctx.setSystem((prev) => ({ ...prev, locale: loc }));
        return [line('success', `System Locale set to ${loc}`)];
      }
      if (args[0] === 'list-locales') {
        return [line('output', 'C.UTF-8\nen_US.UTF-8\nja_JP.UTF-8')];
      }
      return [
        line(
          'output',
          `System Locale: LANG=${ctx.system.locale}
    VC Keymap: jp
   X11 Layout: jp`
        ),
      ];
    }

    case 'loginctl': {
      const sub = args[0] || 'list-sessions';
      if (sub === 'list-users') {
        return [line('output', `  UID USER     LINGER\n 1000 ${ctx.system.username} no\n\n1 users listed.`)];
      }
      return [
        line(
          'output',
          `SESSION  UID USER     SEAT  TTY
      1 1000 ${ctx.system.username} seat0 pts/0

1 sessions listed.`
        ),
      ];
    }

    case 'networkctl': {
      const sub = args[0] || 'list';
      if (sub === 'status') {
        return [
          line(
            'output',
            `●        State: routable
  Online state: online
       Address: ${ctx.system.ipAddress.split('/')[0]} on eth0
       Gateway: ${ctx.system.gateway} on eth0
           DNS: ${ctx.system.dnsServers.join(' ')}`
          ),
        ];
      }
      return [
        line(
          'output',
          `IDX LINK   TYPE     OPERATIONAL SETUP
  1 lo     loopback carrier     unmanaged
  2 eth0   ether    routable    configured

2 links listed.`
        ),
      ];
    }

    case 'nmcli': {
      const sub = args[0] || 'device';
      if (sub === 'connection' || sub === 'c') {
        return [
          line(
            'output',
            `NAME                UUID                                  TYPE      DEVICE
Wired connection 1  a1b2c3d4-e5f6-7890-abcd-ef1234567890  ethernet  eth0`
          ),
        ];
      }
      if (sub === 'general' || sub === 'g') {
        return [
          line(
            'output',
            `STATE      CONNECTIVITY  WIFI-HW  WIFI     WWAN-HW  WWAN
connected  full          missing  enabled  missing  enabled`
          ),
        ];
      }
      return [
        line(
          'output',
          `DEVICE  TYPE      STATE                   CONNECTION
eth0    ethernet  connected               Wired connection 1
lo      loopback  connected (externally)  lo`
        ),
      ];
    }

    case 'resolvconf': {
      if (args.includes('--help') || args.includes('-h')) {
        return [line('output', 'Usage: resolvconf (-d IFACE|-a IFACE|-u|-l)\nUpdates /etc/resolv.conf from systemd-resolved / network interfaces.')];
      }
      if (args.includes('-u')) {
        return [line('success', 'resolvconf: updated /etc/resolv.conf from active interface records.')];
      }
      return [line('output', ctx.fs['/etc/resolv.conf']?.content || 'nameserver 10.10.0.1')];
    }

    // =========================================================================
    // 2. SECURITY & PENTESTING COMMANDS (22 requested commands)
    // =========================================================================
    case 'nmap': {
      const targetArg = args.find((a) => !a.startsWith('-'));
      if (!targetArg) {
        return [line('info', 'Usage: nmap [-sV] [-sC] [-p-] <target-ip-or-hostname>')];
      }
      const target = findTargetByHost(ctx.targets, targetArg);
      if (!target) {
        return [line('error', `Failed to resolve "${targetArg}".`)];
      }
      if (target.status === 'stopped') {
        return [line('warning', `Note: Host seems down (${target.ip} is stopped).`)];
      }
      const portLines = target.ports
        .map((p) => `${`${p.port}/${p.protocol}`.padEnd(10)} ${p.state.padEnd(10)} ${p.service.padEnd(14)} ${p.version}`)
        .join('\n');
      return [
        line(
          'output',
          `Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-11-22 04:12 JST
Nmap scan report for ${target.hostname} (${target.ip})
Host is up (0.0014s latency).
Not shown: ${1000 - target.ports.length} closed tcp ports (reset)
PORT       STATE      SERVICE        VERSION
${portLines}
Service Info: OS: ${target.os}; CPE: cpe:/o:canonical:ubuntu_linux

Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds`
        ),
      ];
    }

    case 'burpsuite':
    case 'burp': {
      const urlArg = args.find((a) => !a.startsWith('-'));
      ctx.onOpenProxyTool('burpsuite', urlArg);
      return [
        line(
          'success',
          `[Burp Suite Community] Proxy listener active on 127.0.0.1:8080.\nWebタブの Burp Suite インターセプター / Repeater ワークベンチを開きました。`
        ),
      ];
    }

    case 'zaproxy':
    case 'owasp-zap':
    case 'zap': {
      const urlArg = args.find((a) => a.startsWith('http') || /^\d+\.\d+/.test(a)) || args[args.indexOf('-quickurl') + 1];
      ctx.onOpenProxyTool('zap', urlArg);
      if (!urlArg) {
        return [
          line(
            'success',
            `[OWASP ZAP 2.15.0] Daemon listening on 127.0.0.1:8080. Webタブの OWASP ZAP ワークベンチを開きました。\nTip: zaproxy -quickurl http://10.10.1.10 でクイックスキャンも可能です。`
          ),
        ];
      }
      const t = findTargetByHost(ctx.targets, urlArg);
      if (!t || t.status === 'stopped') {
        return [line('error', `ZAP Alert: Target ${urlArg} unreachable.`)];
      }
      const alerts = t.vulnerabilities.map((v) => `[HIGH] Detected indicator for vulnerability module: ${v}`).join('\n');
      return [
        line(
          'output',
          `[OWASP ZAP 2.15.0] Running active baseline scan on ${t.hostname} (${t.ip})...\n${alerts}\nScan completed. Detailed request history synced to Web > OWASP ZAP.`
        ),
      ];
    }

    case 'caido': {
      const urlArg = args.find((a) => !a.startsWith('-'));
      ctx.onOpenProxyTool('caido', urlArg);
      return [
        line(
          'success',
          `[Caido 0.41.1] Local HTTP/HTTPS proxy & Replay engine attached at 127.0.0.1:8080.\nWebタブの Caido ワークベンチを開きました。`
        ),
      ];
    }

    case 'gobuster':
    case 'dirb':
    case 'dirbuster':
    case 'ffuf':
    case 'wfuzz': {
      const urlArg =
        args.find((a) => a.startsWith('http')) ||
        args[args.indexOf('-u') + 1] ||
        args.find((a) => a.includes('.local') || /^10\.10\./.test(a));

      if (!urlArg) {
        return [line('info', `Usage: ${lowerCmd} -u http://10.10.1.10[/FUZZ] -w /usr/share/wordlists/common.txt`)];
      }
      const target = findTargetByHost(ctx.targets, urlArg);
      if (!target || target.status === 'stopped') {
        return [line('error', `[${lowerCmd}] Connection failed: target unreachable.`)];
      }

      const paths = getDiscoveredPaths(target);
      const formatted = paths
        .map((p) => {
          if (lowerCmd === 'ffuf') {
            return `${p.path.replace(/^\//, '').padEnd(36)} [Status: ${p.status}, Size: ${p.size}]`;
          }
          if (lowerCmd === 'wfuzz') {
            return `000001:   ${String(p.status).padEnd(5)}   12 L     ${String(p.size).padEnd(6)} Ch   "${p.path}"`;
          }
          if (lowerCmd === 'dirb') {
            return `+ http://${target.ip}${p.path} (CODE:${p.status}|SIZE:${p.size})`;
          }
          return `${p.path.padEnd(42)} (Status: ${p.status}) [Size: ${p.size}]`;
        })
        .join('\n');

      ctx.onLogHttp({
        targetId: target.id,
        toolSource: 'scanner',
        request: { method: 'GET', url: `http://${target.ip}/`, headers: { 'User-Agent': `${lowerCmd}/scanner` }, cookies: {} },
        response: { status: 200, statusText: 'OK', headers: {}, body: formatted, contentType: 'text/plain' },
      });

      return [
        line(
          'output',
          `===============================================================
[${cmd}] Target: http://${target.ip} (${target.hostname})
Wordlist: /usr/share/wordlists/common.txt
===============================================================
${formatted}
===============================================================
Finished scanning ${target.ip}.`
        ),
      ];
    }

    case 'nikto': {
      const hIdx = args.indexOf('-h');
      const targetArg = hIdx !== -1 ? args[hIdx + 1] : args.find((a) => !a.startsWith('-'));
      if (!targetArg) return [line('info', 'Usage: nikto -h http://10.10.1.10')];
      const target = findTargetByHost(ctx.targets, targetArg);
      if (!target || target.status === 'stopped') return [line('error', `ERROR: Cannot connect to ${targetArg}`)];

      const findings: string[] = [
        `+ Server: ${target.webServer}`,
        `+ The anti-clickjacking X-Frame-Options header is not present.`,
      ];
      if (target.vulnerabilities.includes('html_leak')) {
        findings.push(`+ /robots.txt: Entry '/secret-backup/flag.txt' was found.`);
        findings.push(`+ OSVDB-3092: /secret-backup/: Directory indexing or backup exposure found.`);
      }
      if (target.vulnerabilities.includes('weak_auth')) {
        findings.push(`+ /logs/auth.log: Sensitive authentication log file accessible without auth!`);
      }
      if (target.vulnerabilities.includes('sqli')) {
        findings.push(`+ /product?id=1: Potential SQL injection vector detected in 'id' parameter.`);
      }
      if (target.vulnerabilities.includes('lfi_wp')) {
        findings.push(`+ /wp-content/plugins/simple-file-viewer/view.php: Arbitrary File Read (LFI) vulnerability.`);
      }
      if (target.vulnerabilities.includes('cmdi')) {
        findings.push(`+ /api/ping?host=127.0.0.1: OS Command Injection suspected on 'host' parameter.`);
      }
      if (target.vulnerabilities.includes('header_cookie_tamper')) {
        findings.push(`+ /administrator/vault: Trusts client-supplied role cookie / X-Role header.`);
      }
      if (target.vulnerabilities.includes('file_upload_rce')) {
        findings.push(`+ /upload.php: Accepts dangerous extensions (.phtml / .php5) into /uploads/.`);
      }
      if (target.wafEnabled) {
        findings.push(`+ WAF detected: ModSecurity blocking aggressive probes unless X-Forwarded-For: 127.0.0.1 is set.`);
      }

      return [
        line(
          'output',
          `- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          ${target.ip}
+ Target Hostname:    ${target.hostname}
+ Target Port:        ${target.ports[0]?.port || 80}
---------------------------------------------------------------------------
${findings.join('\n')}
+ 1 host(s) tested`
        ),
      ];
    }

    case 'nuclei': {
      const targetArg = args[args.indexOf('-u') + 1] || args.find((a) => !a.startsWith('-'));
      if (!targetArg) return [line('info', 'Usage: nuclei -u http://10.10.1.10')];
      const target = findTargetByHost(ctx.targets, targetArg);
      if (!target || target.status === 'stopped') return [line('error', `[ERR] Could not connect to ${targetArg}`)];

      const matches = target.vulnerabilities.map((v) => {
        switch (v) {
          case 'html_leak':
            return `[exposed-secret-backup] [http] [medium] http://${target.ip}/secret-backup/flag.txt`;
          case 'weak_auth':
            return `[exposed-auth-logs] [http] [high] http://${target.ip}/logs/auth.log`;
          case 'sqli':
            return `[mysql-union-sqli] [http] [critical] http://${target.ip}/product?id=1`;
          case 'lfi_wp':
            return `[CVE-2023-4189-wp-lfi] [http] [critical] http://${target.ip}/wp-content/plugins/simple-file-viewer/view.php?file=../../../../etc/passwd`;
          case 'cmdi':
            return `[os-command-injection] [http] [critical] http://${target.ip}/api/ping?host=127.0.0.1`;
          case 'header_cookie_tamper':
            return `[joomla-role-header-bypass] [http] [high] http://${target.ip}/administrator/vault`;
          case 'stored_xss':
            return `[stored-xss-admin-bot] [http] [high] http://${target.ip}/post`;
          case 'file_upload_rce':
            return `[unrestricted-phtml-upload] [http] [critical] http://${target.ip}/upload.php`;
          case 'ssrf_jwt':
            return `[ssrf-internal-config-leak] [http] [critical] http://${target.ip}/api/fetch?url=http://127.0.0.1:8080/secret-config`;
          case 'waf_chain_ssh':
            return `[waf-xff-bypass-graphql] [http] [critical] http://${target.ip}:8443/api/graphql (requires X-Forwarded-For: 127.0.0.1)`;
        }
      });

      return [
        line(
          'output',
          `                     __     _
   ____  __  _______/ /__  (_)
  / __ \\/ / / / ___/ / _ \\/ /
 / / / / /_/ / /__/ /  __/ /   v3.2.4
/_/ /_/\\__,_/\\___/_/\\___/_/

[INF] Using Nuclei Engine 3.2.4 (latest)
[INF] Targets loaded: 1
${matches.join('\n')}`
        ),
      ];
    }

    case 'whatweb':
    case 'wappalyzer': {
      const targetArg = args.find((a) => !a.startsWith('-'));
      if (!targetArg) return [line('info', `Usage: ${lowerCmd} http://10.10.1.10`)];
      const target = findTargetByHost(ctx.targets, targetArg);
      if (!target || target.status === 'stopped') return [line('error', `ERROR: Cannot reach ${targetArg}`)];

      if (lowerCmd === 'wappalyzer') {
        return [
          line(
            'output',
            JSON.stringify(
              {
                url: `http://${target.ip}`,
                technologies: [
                  { name: target.webServer, categories: ['Web servers'] },
                  ...(target.cms ? [{ name: target.cms, categories: ['CMS / Framework'] }] : []),
                  ...target.techStack.map((t) => ({ name: t, categories: ['Detected Stack'] })),
                  ...(target.wafEnabled ? [{ name: 'ModSecurity WAF', categories: ['Security'] }] : []),
                ],
              },
              null,
              2
            )
          ),
        ];
      }
      return [
        line(
          'output',
          `http://${target.ip} [200 OK] Country[RESERVED][ZZ], HTTPServer[${target.webServer}], IP[${target.ip}], Title[${target.siteTitle}], Stack[${target.techStack.join(', ')}]${
            target.cms ? `, CMS[${target.cms}]` : ''
          }`
        ),
      ];
    }

    case 'sqlmap': {
      const urlArg = args[args.indexOf('-u') + 1] || args.find((a) => a.startsWith('http'));
      if (!urlArg) return [line('info', 'Usage: sqlmap -u "http://10.10.3.10/product?id=1" [--dbs|--dump]')];
      const target = findTargetByHost(ctx.targets, urlArg);
      if (!target || target.status === 'stopped') return [line('error', `[CRITICAL] Unable to connect to ${urlArg}`)];
      if (!target.vulnerabilities.includes('sqli')) {
        return [line('warning', `[WARNING] Target ${target.ip} does not appear to be SQLi injectable on that parameter.`)];
      }

      const dump = args.includes('--dump') || args.includes('-a') || args.includes('--all') || args.includes('--dbs');
      return [
        line(
          dump ? 'success' : 'output',
          `        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.8.3#stable}
|_ -| . [(]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 04:12:18 /2026-11-22/
[INFO] testing connection to the target URL
[INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based' injectable
[INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 3 columns' injectable
back-end DBMS: MySQL >= 8.0
${
  dump
    ? `available databases [2]:
[*] information_schema
[*] shoplite_db

Database: shoplite_db
Table: secrets
[1 entry]
+----+------------------------+------------------------------------------+
| id | key_name               | secret_value                             |
+----+------------------------+------------------------------------------+
| 1  | production_vault_flag  | ${target.flag} |
+----+------------------------+------------------------------------------+`
    : `[INFO] Parameter 'id' is vulnerable. Re-run with --dump to dump table contents.`
}`
        ),
      ];
    }

    case 'wpscan': {
      const urlArg = args[args.indexOf('--url') + 1] || args.find((a) => a.startsWith('http'));
      if (!urlArg) return [line('info', 'Usage: wpscan --url http://10.10.4.10')];
      const target = findTargetByHost(ctx.targets, urlArg);
      if (!target || target.status === 'stopped') return [line('error', `Scan Aborted: ${urlArg} unreachable`)];
      if (target.cms !== 'WordPress' && !target.vulnerabilities.includes('lfi_wp')) {
        return [line('warning', `[!] The remote website (${target.ip}) does not appear to be running WordPress.`)];
      }
      return [
        line(
          'output',
          `_______________________________________________________________
         __          _______   _____
         \\ \\        / /  __ \\ / ____|
          \\ \\  /\\  / /| |__) | (___   ___  __ _ _ __
           \\ \\/  \\/ / |  ___/ \\___ \\ / __|/ _\` | '_ \\
            \\  /\\  /  | |     ____) | (__| (_| | | | |
             \\/  \\/   |_|    |_____/ \\___|\\__,_|_| |_|

[+] URL: http://${target.ip}/
[+] WordPress version 6.1.1 identified (Insecure, released on 2022-11-15).
[+] Enumerating Vulnerable Plugins:
 | [!] simple-file-viewer (v1.0.2)
 |     Title: Simple File Viewer <= 1.0.2 - Unauthenticated Arbitrary File Read (LFI)
 |     Reference: /wp-content/plugins/simple-file-viewer/view.php?file=../../../../etc/flag.txt
[+] Enumerating Users:
 | [i] User Identified: editor`
        ),
      ];
    }

    case 'joomscan': {
      const urlArg = args[args.indexOf('-u') + 1] || args.find((a) => a.startsWith('http'));
      if (!urlArg) return [line('info', 'Usage: joomscan -u http://10.10.6.10')];
      const target = findTargetByHost(ctx.targets, urlArg);
      if (!target || target.status === 'stopped') return [line('error', `[!] Target unreachable: ${urlArg}`)];
      if (target.cms !== 'Joomla' && !target.vulnerabilities.includes('header_cookie_tamper')) {
        return [line('warning', `[!] Target ${target.ip} does not appear to be running Joomla!.`)];
      }
      return [
        line(
          'output',
          `    ____  _____  _____  __  __  ___   ___    __    _  _
   (_  _)(  _  )(  _  )(  \\/  )/ __) / __)  /__\\  ( \\( )
  .-_)(   )(_)(  )(_)(  )    ( \\__ \\( (__  /(__)\\  )  (
  \\____) (_____)(_____)(_/\\/\\_)(___/ \\___)(__)(__)(_)\\_)

[+] Detecting Joomla Version: Joomla! 3.10.11
[+] Admin page found: http://${target.ip}/administrator/
[!] Finding: /administrator/vault trusts client Cookie "role=admin" or Header "X-Role: admin" (Broken Access Control)!`
        ),
      ];
    }

    case 'hydra': {
      const targetArg = args.find((a) => /^10\.10\./.test(a) || a.includes('.local'));
      if (!targetArg) {
        return [line('info', 'Usage: hydra -l admin -P /usr/share/wordlists/rockyou.txt <target-ip> http-post-form|ssh')];
      }
      const target = findTargetByHost(ctx.targets, targetArg);
      if (!target || target.status === 'stopped') return [line('error', `[ERROR] Could not connect to ${targetArg}`)];

      const cred = target.credentials[0] || (target.sshUser ? { username: target.sshUser.username, password: target.sshUser.password } : null);
      if (!cred) {
        return [line('warning', `[STATUS] 0 valid passwords found for ${target.ip}.`)];
      }
      return [
        line(
          'success',
          `Hydra v9.5 starting at 2026-11-22 04:12:30
[DATA] attacking target ${target.ip}
[80][http-post-form] host: ${target.ip}   login: ${cred.username}   password: ${cred.password}
1 of 1 target successfully completed, 1 valid password found`
        ),
      ];
    }

    case 'commix': {
      const urlArg = args[args.indexOf('-u') + 1] || args.find((a) => a.startsWith('http'));
      if (!urlArg) return [line('info', 'Usage: commix -u "http://10.10.5.10/api/ping?host=127.0.0.1" [--os-cmd="cat /var/www/flag.txt"]')];
      const target = findTargetByHost(ctx.targets, urlArg);
      if (!target || target.status === 'stopped') return [line('error', `[CRITICAL] Target unreachable.`)];
      if (!target.vulnerabilities.includes('cmdi')) {
        return [line('warning', `[WARNING] No OS command injection points found on ${target.ip}.`)];
      }
      const osCmdArg = args.find((a) => a.startsWith('--os-cmd='))?.split('=')[1];
      const testRes = executeHttpRequest(ctx.targets, {
        method: 'GET',
        url: `http://${target.ip}/api/ping?host=127.0.0.1 | ${osCmdArg || 'cat /var/www/flag.txt'}`,
        headers: {},
        cookies: {},
      });
      return [
        line(
          'success',
          `                                       __
   ___   ___     ___ ___     ___ ___ /\\_\\   __  _
  /'___\\/ __\`\\ /' __\` __\`\\ /' __\` __\`\\/\\ \\ /\\ \\/'\\
 /\\ \\__/\\ \\L\\ \\/\\ \\/\\ \\/\\ \\/\\ \\/\\ \\/\\ \\ \\ \\\\/>  </
 \\ \\____\\ \\____/\\ \\_\\ \\_\\ \\_\\ \\_\\ \\_\\ \\_\\ \\_\\ /\\_/\\_\\
  \\/____/\\/___/  \\/_/\\/_/\\/_/\\/_/\\/_/\\/_/\\/_/ \\//\\/_/  v3.9-stable

[+] Heuristic test shows that GET parameter 'host' might be injectable (separator: "|", ";" blocked)
[+] Executed payload -> ${osCmdArg || 'cat /var/www/flag.txt'}
[+] Output:\n${testRes.uiState?.cmdOutput || testRes.body}`
        ),
      ];
    }

    case 'xsser': {
      const urlArg = args[args.indexOf('-u') + 1] || args.find((a) => a.startsWith('http'));
      if (!urlArg) return [line('info', 'Usage: xsser -u "http://10.10.7.10/post"')];
      const target = findTargetByHost(ctx.targets, urlArg);
      if (!target || target.status === 'stopped') return [line('error', `[Error] Target unreachable.`)];
      if (!target.vulnerabilities.includes('stored_xss')) {
        return [line('warning', `[Info] No XSS vulnerabilities confirmed on ${target.ip}.`)];
      }
      return [
        line(
          'success',
          `XSSer v1.8.4 — Cross Site "Scripter"
[INFO] Testing target: http://${target.ip}/post
[VULNERABLE] Stored XSS detected on POST parameter 'comment'!
[TIP] Admin Bot polls board automatically. POST "<script>fetch('/api/admin/flag')</script>" to /post and read /api/exfil.`
        ),
      ];
    }

    case 'wapiti':
    case 'skipfish': {
      const targetArg = args.find((a) => a.startsWith('http') || /^10\.10\./.test(a) || a.includes('.local'));
      if (!targetArg) return [line('info', `Usage: ${lowerCmd} ${lowerCmd === 'wapiti' ? '-u ' : '-o out '}http://10.10.7.10`)];
      const target = findTargetByHost(ctx.targets, targetArg);
      if (!target || target.status === 'stopped') return [line('error', `Target unreachable: ${targetArg}`)];
      return [
        line(
          'output',
          `[${cmd}] Active Web Vulnerability Scan on http://${target.ip} (${target.hostname})
------------------------------------------------------------------
Detected Risk Surface: ${target.vulnerabilities.join(', ')}
Recommendations:
- Inspect endpoints via curl / Burp Suite / OWASP ZAP
- Exploitable modules confirmed: ${target.vulnerabilities.length} high-severity findings.`
        ),
      ];
    }

    case 'weevely': {
      if (args[0] === 'generate') {
        const pass = args[1] || 'pass123';
        const fname = args[2] || 'shell.phtml';
        const dest = resolvePath(ctx.system.cwd, fname, '/home/operator');
        const shellCode = `<?php /* Weevely stealth agent (password: ${pass}) */ @eval($_POST['${pass}']); ?>`;
        ctx.setFs((prev) => ({
          ...prev,
          [dest]: {
            type: 'file',
            permissions: '-rw-r--r--',
            owner: ctx.system.username,
            size: shellCode.length,
            modified: '2026-11-22 04:12',
            content: shellCode,
          },
        }));
        return [line('success', `Generated backdoor agent '${dest}' with password '${pass}' (${shellCode.length} bytes).`)];
      }
      const urlArg = args[0];
      const passArg = args[1];
      if (!urlArg || !passArg) {
        return [line('info', 'Usage:\n  weevely generate <password> <filename.phtml>\n  weevely http://10.10.8.10/uploads/shell.phtml <password>')];
      }
      const parsed = parseTargetUrl(urlArg);
      const target = parsed ? findTargetByHost(ctx.targets, parsed.host) : undefined;
      if (!target || target.status === 'stopped') return [line('error', `[!] Could not connect to ${urlArg}`)];
      const fname = parsed!.path.split('/').pop() || '';
      const uploaded = target.uploadedShells[fname];
      if (!uploaded || uploaded.password !== passArg) {
        return [
          line(
            'error',
            `[!] Weevely connection failed: shell "${fname}" not uploaded or invalid password.\nUpload via Web tab (/upload.php) or curl -X POST http://${target.ip}/upload.php -d "filename=${fname}&password=${passArg}"`
          ),
        ];
      }
      ctx.setRemoteSession({
        type: 'weevely',
        targetId: target.id,
        hostname: target.hostname,
        ip: target.ip,
        user: 'www-data',
        cwd: '/var/www/html',
        isRoot: false,
      });
      return [
        line(
          'success',
          `[+] Weevely 4.0.1 shell established on ${target.ip} as www-data!\nType 'ls', 'cat /var/www/html/flag_vault.txt', or 'exit' to disconnect.`
        ),
      ];
    }

    // =========================================================================
    // 3. STANDARD LINUX SHELL UTILITIES & REMOTE ACCESS
    // =========================================================================
    case 'ssh': {
      // Parse ssh user@ip [-p port]
      const targetSpec = args.find((a) => a.includes('@'));
      if (!targetSpec) return [line('info', 'Usage: ssh <user>@<host> [-p <port>]')];
      const [uName, hName] = targetSpec.split('@');
      const target = findTargetByHost(ctx.targets, hName);
      if (!target || target.status === 'stopped') return [line('error', `ssh: connect to host ${hName}: Connection refused`)];
      if (!target.sshUser || target.sshUser.username !== uName) {
        return [line('error', `Permission denied (publickey,password) for ${uName}@${target.ip}.`)];
      }
      ctx.setRemoteSession({
        type: 'ssh',
        targetId: target.id,
        hostname: target.hostname,
        ip: target.ip,
        user: target.sshUser.username,
        cwd: `/home/${target.sshUser.username}`,
        isRoot: false,
      });
      return [
        line(
          'success',
          `Authenticated as ${target.sshUser.username} on ${target.hostname} (${target.ip})!\nWelcome to ${target.os}. Try 'ls', 'sudo -l', or 'exit'.`
        ),
      ];
    }

    case 'curl':
    case 'wget': {
      const methodIdx = args.indexOf('-X');
      const method = (methodIdx !== -1 ? args[methodIdx + 1]?.toUpperCase() : args.includes('-d') || args.includes('--data') ? 'POST' : 'GET') as HttpRequest['method'];
      const headers: Record<string, string> = {};
      const cookies: Record<string, string> = {};
      let body: string | undefined;

      for (let i = 0; i < args.length; i++) {
        if ((args[i] === '-H' || args[i] === '--header') && args[i + 1]) {
          const [hk, ...hv] = args[i + 1].split(':');
          if (hk && hv.length) headers[hk.trim()] = hv.join(':').trim();
        }
        if ((args[i] === '-b' || args[i] === '--cookie') && args[i + 1]) {
          args[i + 1].split(';').forEach((pair) => {
            const [ck, cv] = pair.split('=');
            if (ck && cv !== undefined) cookies[ck.trim()] = cv.trim();
          });
        }
        if ((args[i] === '-d' || args[i] === '--data') && args[i + 1]) {
          body = args[i + 1];
        }
      }

      const urlArg = args.find((a) => a.startsWith('http') || /^10\.10\./.test(a) || a.includes('.local'));
      if (!urlArg) return [line('info', `Usage: ${lowerCmd} [options] http://10.10.1.10/...`)];

      const req: HttpRequest = { method, url: urlArg, headers, cookies, body };
      const res = executeHttpRequest(ctx.targets, req, ctx.mutateTarget);
      const parsed = parseTargetUrl(urlArg);
      const target = parsed ? findTargetByHost(ctx.targets, parsed.host) : undefined;
      if (target) {
        ctx.onLogHttp({ targetId: target.id, toolSource: 'terminal', request: req, response: res });
      }
      const includeHeaders = args.includes('-i') || args.includes('-I');
      const headerStr = includeHeaders
        ? `HTTP/1.1 ${res.status} ${res.statusText}\n${Object.entries(res.headers)
            .map(([k, v]) => `${k}: ${v}`)
            .join('\n')}\n\n`
        : '';
      return [line(res.status >= 400 ? 'warning' : 'output', `${headerStr}${args.includes('-I') ? '' : res.body}`)];
    }

    case 'ping': {
      const host = args.find((a) => !a.startsWith('-'));
      if (!host) return [line('info', 'Usage: ping <host>')];
      const target = findTargetByHost(ctx.targets, host);
      if (host === '127.0.0.1' || host === 'localhost' || (target && target.status === 'running')) {
        const ip = target?.ip || '127.0.0.1';
        return [
          line(
            'output',
            `PING ${host} (${ip}) 56(84) bytes of data.\n64 bytes from ${ip}: icmp_seq=1 ttl=64 time=0.84 ms\n64 bytes from ${ip}: icmp_seq=2 ttl=64 time=0.79 ms\n--- ${host} ping statistics ---\n2 packets transmitted, 2 received, 0% packet loss`
          ),
        ];
      }
      return [line('error', `ping: ${host}: Destination Host Unreachable`)];
    }

    case 'nc': {
      return [line('info', `Listening on 0.0.0.0 4444 (simulated listener ready for callbacks).`)];
    }

    case 'submit': {
      const flag = args[0];
      if (!flag) return [line('info', 'Usage: submit FLAG{...}')];
      const res = ctx.onSubmitFlag(flag);
      return [line(res.ok ? 'success' : 'error', res.message)];
    }

    case 'ls':
    case 'll': {
      const long = lowerCmd === 'll' || args.includes('-la') || args.includes('-l') || args.includes('-al');
      const targetArg = args.find((a) => !a.startsWith('-'));
      const dirPath = targetArg ? resolvePath(ctx.system.cwd, targetArg, '/home/operator') : ctx.system.cwd;
      const node = ctx.fs[dirPath];
      if (!node) return [line('error', `ls: cannot access '${targetArg}': No such file or directory`)];
      if (node.type === 'file') return [line('output', dirPath)];
      const children = getDirChildren(ctx.fs, dirPath);
      if (long) {
        return [
          line(
            'output',
            children
              .map(
                (c) =>
                  `${c.node.permissions} 1 ${c.node.owner.padEnd(8)} ${String(c.node.size).padStart(5)} ${c.node.modified} ${
                    c.node.type === 'dir' ? c.name + '/' : c.name
                  }`
              )
              .join('\n')
          ),
        ];
      }
      return [line('output', children.map((c) => (c.node.type === 'dir' ? c.name + '/' : c.name)).join('  '))];
    }

    case 'cd': {
      const dest = args[0] || '~';
      const resolved = resolvePath(ctx.system.cwd, dest, '/home/operator');
      const node = ctx.fs[resolved];
      if (!node || node.type !== 'dir') {
        return [line('error', `bash: cd: ${dest}: No such directory`)];
      }
      ctx.setSystem((prev) => ({ ...prev, cwd: resolved }));
      return [];
    }

    case 'pwd':
      return [line('output', ctx.system.cwd)];

    case 'cat':
    case 'head':
    case 'tail': {
      const fileArg = args.find((a) => !a.startsWith('-'));
      if (!fileArg) return [line('error', `${lowerCmd}: missing file operand`)];
      const full = resolvePath(ctx.system.cwd, fileArg, '/home/operator');
      const node = ctx.fs[full];
      if (!node || node.type !== 'file') return [line('error', `${lowerCmd}: ${fileArg}: No such file`)];
      const content = node.content || '';
      if (lowerCmd === 'head') return [line('output', content.split('\n').slice(0, 10).join('\n'))];
      if (lowerCmd === 'tail') return [line('output', content.split('\n').slice(-10).join('\n'))];
      return [line('output', content)];
    }

    case 'grep': {
      const pattern = args[0];
      const fileArg = args[1];
      if (!pattern || !fileArg) return [line('info', 'Usage: grep <pattern> <file>')];
      const full = resolvePath(ctx.system.cwd, fileArg, '/home/operator');
      const node = ctx.fs[full];
      if (!node || !node.content) return [line('error', `grep: ${fileArg}: No such file`)];
      const hits = node.content.split('\n').filter((l) => l.toLowerCase().includes(pattern.toLowerCase()));
      return [line('output', hits.join('\n'))];
    }

    case 'find': {
      const base = args[0] && !args[0].startsWith('-') ? resolvePath(ctx.system.cwd, args[0], '/home/operator') : ctx.system.cwd;
      const nameIdx = args.indexOf('-name');
      const namePat = nameIdx !== -1 ? args[nameIdx + 1]?.replace(/\*/g, '') : '';
      const matched = Object.keys(ctx.fs).filter(
        (p) => p.startsWith(base === '/' ? '/' : base + '/') && (!namePat || p.includes(namePat))
      );
      return [line('output', matched.join('\n'))];
    }

    case 'echo':
      return [line('output', args.join(' '))];

    case 'touch': {
      const f = args[0];
      if (!f) return [line('error', 'touch: missing file operand')];
      const full = resolvePath(ctx.system.cwd, f, '/home/operator');
      ctx.setFs((prev) => ({
        ...prev,
        [full]: prev[full] || {
          type: 'file',
          permissions: '-rw-r--r--',
          owner: ctx.system.username,
          size: 0,
          modified: '2026-11-22 04:12',
          content: '',
        },
      }));
      return [];
    }

    case 'mkdir': {
      const d = args.find((a) => !a.startsWith('-'));
      if (!d) return [line('error', 'mkdir: missing operand')];
      const full = resolvePath(ctx.system.cwd, d, '/home/operator');
      ctx.setFs((prev) => ({
        ...prev,
        [full]: { type: 'dir', permissions: 'drwxr-xr-x', owner: ctx.system.username, size: 4096, modified: '2026-11-22 04:12' },
      }));
      return [];
    }

    case 'rm': {
      const target = args.find((a) => !a.startsWith('-'));
      if (!target) return [line('error', 'rm: missing operand')];
      const full = resolvePath(ctx.system.cwd, target, '/home/operator');
      if (!ctx.fs[full]) return [line('error', `rm: cannot remove '${target}': No such file or directory`)];
      ctx.setFs((prev) => {
        const copy = { ...prev };
        delete copy[full];
        return copy;
      });
      return [];
    }

    case 'cp':
    case 'mv': {
      const [src, dst] = args;
      if (!src || !dst) return [line('error', `${lowerCmd}: missing file operand`)];
      const srcPath = resolvePath(ctx.system.cwd, src, '/home/operator');
      const dstPath = resolvePath(ctx.system.cwd, dst, '/home/operator');
      const node = ctx.fs[srcPath];
      if (!node) return [line('error', `${lowerCmd}: cannot stat '${src}': No such file`)];
      ctx.setFs((prev) => {
        const copy = { ...prev, [dstPath]: { ...node } };
        if (lowerCmd === 'mv') delete copy[srcPath];
        return copy;
      });
      return [];
    }

    case 'chmod':
      return [];

    case 'whoami':
      return [line('output', ctx.system.username)];
    case 'id':
      return [line('output', `uid=1000(${ctx.system.username}) gid=1000(${ctx.system.username}) groups=1000(${ctx.system.username}),27(sudo)`)];
    case 'hostname':
      return [line('output', ctx.system.hostname)];
    case 'uname':
      return [line('output', args.includes('-a') ? `Linux ${ctx.system.hostname} ${ctx.system.kernelVersion} #45-Ubuntu SMP x86_64 GNU/Linux` : 'Linux')];
    case 'date':
      return [line('output', 'Sun Nov 22 04:12:00 JST 2026')];
    case 'uptime':
      return [line('output', ' 04:12:00 up 2 days,  4:11,  1 user,  load average: 0.12, 0.08, 0.05')];
    case 'ps':
      return [
        line(
          'output',
          `  PID TTY          TIME CMD\n    1 ?        00:00:03 systemd\n  412 ?        00:00:01 systemd-resolved\n  612 ?        00:00:00 sshd\n  880 ?        00:00:04 burp-proxy\n 1024 pts/0    00:00:00 bash`
        ),
      ];
    case 'df':
      return [
        line(
          'output',
          `Filesystem      Size  Used Avail Use% Mounted on\n/dev/vda1        40G   14G   24G  37% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm`
        ),
      ];
    case 'free':
      return [
        line(
          'output',
          `               total        used        free      shared  buff/cache   available\nMem:           4.0Gi       1.1Gi       2.1Gi        32Mi       840Mi       2.7Gi`
        ),
      ];
    case 'env':
      return [line('output', Object.entries(ctx.system.env).map(([k, v]) => `${k}=${v}`).join('\n'))];
    case 'export': {
      const [k, v] = (args[0] || '').split('=');
      if (k && v !== undefined) {
        ctx.setSystem((prev) => ({ ...prev, env: { ...prev.env, [k]: v } }));
      }
      return [];
    }
    case 'which': {
      const targetBin = args[0];
      if (!targetBin) return [];
      return ALL_COMMANDS.includes(targetBin.toLowerCase())
        ? [line('output', `/usr/bin/${targetBin.toLowerCase()}`)]
        : [line('error', `${targetBin} not found`)];
    }
    case 'base64': {
      if (args.includes('-d') && args[1]) {
        try {
          return [line('output', atob(args[1]))];
        } catch {
          return [line('error', 'base64: invalid input')];
        }
      }
      if (args[0]) return [line('output', btoa(args[0]))];
      return [line('info', 'Usage: base64 [-d] <string>')];
    }
    case 'python3':
      return [line('output', 'Python 3.12.3 (main, Ubuntu 24.04) — Interactive lab sandbox')];
    case 'history':
      return [
        line(
          'output',
          ctx.system.commandHistory.map((c, idx) => `${String(idx + 1).padStart(4)}  ${c}`).join('\n')
        ),
      ];
    case 'clear':
      ctx.onClearTerminal();
      return [];
    case 'man':
    case 'help':
      return [
        line(
          'info',
          `=== Ubuntu System & Network Commands ===
ip, ss, dig, resolvectl, systemctl, journalctl, apt, timedatectl, chronyc,
snap, netplan, ufw, do-release-upgrade, ubuntu-drivers, pro, hostnamectl,
localectl, loginctl, networkctl, nmcli, resolvconf

=== Pentesting & Web Attack Tools ===
nmap, Burp Suite (burpsuite), OWASP ZAP (zaproxy), Caido (caido),
Nikto, ffuf, Gobuster, Nuclei, Wappalyzer, sqlmap, WPScan, Hydra,
Dirb, DirBuster, Wfuzz, WhatWeb, Wapiti, Skipfish, Commix, XSSer,
JoomScan, Weevely

=== Shell & Lab Commands ===
ls, cd, pwd, cat, grep, find, curl, wget, ssh, ping, submit FLAG{...}, clear
Tip: Tabキーで自動補完、左側のコマンドパレットからワンクリックで挿入できます。`
        ),
      ];

    default:
      return [line('error', `${cmd}: command not found (type 'help' to see all 43+ supported commands)`)];
  }
}

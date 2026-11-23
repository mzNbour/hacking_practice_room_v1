import { SystemState, VirtualFile } from '../types/lab';

export function createInitialSystemState(): SystemState {
  return {
    hostname: 'kali-ubuntu-lab',
    username: 'operator',
    cwd: '/home/operator',
    timezone: 'Asia/Tokyo (JST, +0900)',
    locale: 'ja_JP.UTF-8',
    ubuntuVersion: 'Ubuntu 24.04.1 LTS (Noble Numbat)',
    kernelVersion: '6.8.0-45-generic',
    ipAddress: '10.10.0.5/24',
    gateway: '10.10.0.1',
    dnsServers: ['10.10.0.1', '1.1.1.1'],
    ufwActive: true,
    ufwRules: [
      { id: 1, to: '22/tcp', action: 'ALLOW IN', from: '10.10.0.0/24' },
      { id: 2, to: '8080/tcp (Proxy)', action: 'ALLOW IN', from: '127.0.0.1' },
      { id: 3, to: '4444/tcp (Listener)', action: 'ALLOW IN', from: 'Anywhere' },
    ],
    proAttached: true,
    netplanConfig: `network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: no
      addresses:
        - 10.10.0.5/24
      routes:
        - to: default
          via: 10.10.0.1
      nameservers:
        addresses: [10.10.0.1, 1.1.1.1]`,
    units: [
      {
        name: 'systemd-resolved.service',
        load: 'loaded',
        active: 'active',
        sub: 'running',
        description: 'Network Name Resolution',
        logs: [
          'systemd-resolved[412]: Positive Trust Anchors:',
          'systemd-resolved[412]: Using system hostname kali-ubuntu-lab.',
          'systemd-resolved[412]: Bound DNS server 10.10.0.1 on interface eth0.',
        ],
      },
      {
        name: 'systemd-networkd.service',
        load: 'loaded',
        active: 'active',
        sub: 'running',
        description: 'Network Configuration',
        logs: [
          'systemd-networkd[389]: eth0: Link UP',
          'systemd-networkd[389]: eth0: Gained carrier',
          'systemd-networkd[389]: eth0: Configured static IPv4 10.10.0.5/24',
        ],
      },
      {
        name: 'NetworkManager.service',
        load: 'loaded',
        active: 'active',
        sub: 'running',
        description: 'Network Manager',
        logs: [
          'NetworkManager[501]: <info>  manager: startup complete',
          'NetworkManager[501]: <info>  device (eth0): state change: config -> activated',
        ],
      },
      {
        name: 'ssh.service',
        load: 'loaded',
        active: 'active',
        sub: 'running',
        description: 'OpenBSD Secure Shell server',
        logs: [
          'sshd[612]: Server listening on 0.0.0.0 port 22.',
          'sshd[612]: Server listening on :: port 22.',
        ],
      },
      {
        name: 'chrony.service',
        load: 'loaded',
        active: 'active',
        sub: 'running',
        description: 'chrony, an NTP client/server',
        logs: [
          'chronyd[540]: chronyd version 4.5 starting',
          'chronyd[540]: Selected source 10.10.0.1 (ntp.nova-corp.local)',
        ],
      },
      {
        name: 'ufw.service',
        load: 'loaded',
        active: 'active',
        sub: 'exited',
        description: 'Uncomplicated Firewall',
        logs: ['ufw[310]: Firewall loaded ruleset (3 active rules).'],
      },
      {
        name: 'burp-proxy.service',
        load: 'loaded',
        active: 'active',
        sub: 'listening',
        description: 'Local HTTP Intercepting Proxy (127.0.0.1:8080)',
        logs: [
          'proxy[880]: Listening on 127.0.0.1:8080 (HTTP/1.1 & TLS intercept)',
          'proxy[880]: Ready to inspect traffic to 10.10.1.0/24 - 10.10.20.0/24',
        ],
      },
      {
        name: 'nginx.service',
        load: 'loaded',
        active: 'inactive',
        sub: 'dead',
        description: 'A high performance web server and reverse proxy',
        logs: ['systemd[1]: nginx.service: Stopped cleanly.'],
      },
    ],
    aptPackages: [
      { name: 'nmap', version: '7.94SVN-1ubuntu1', arch: 'amd64', description: 'The Network Mapper' },
      { name: 'sqlmap', version: '1.8.3-1', arch: 'all', description: 'automatic SQL injection tool' },
      { name: 'gobuster', version: '3.6-1', arch: 'amd64', description: 'Directory/File, DNS and VHost busting tool' },
      { name: 'ffuf', version: '2.1.0-1', arch: 'amd64', description: 'Fast web fuzzer written in Go' },
      { name: 'nikto', version: '2.5.0-1', arch: 'all', description: 'web server security scanner' },
      { name: 'hydra', version: '9.5-1', arch: 'amd64', description: 'very fast network logon cracker' },
      { name: 'nuclei', version: '3.2.4-1', arch: 'amd64', description: 'fast and customizable vulnerability scanner' },
      { name: 'commix', version: '3.9-1', arch: 'all', description: 'Automated OS Command Injection and Exploitation Tool' },
      { name: 'wpscan', version: '3.8.25-1', arch: 'amd64', description: 'WordPress vulnerability scanner' },
      { name: 'whatweb', version: '0.5.5-2', arch: 'all', description: 'Next generation web scanner' },
      { name: 'curl', version: '8.5.0-2ubuntu10', arch: 'amd64', description: 'command line tool for transferring data' },
      { name: 'openssh-client', version: '1:9.6p1-3ubuntu13', arch: 'amd64', description: 'secure shell (SSH) client' },
      { name: 'ufw', version: '0.36.2-6', arch: 'all', description: 'program for managing a Netfilter firewall' },
      { name: 'chrony', version: '4.5-1ubuntu4', arch: 'amd64', description: 'Versatile implementation of the Network Time Protocol' },
    ],
    snapPackages: [
      { name: 'core24', version: '20240920', rev: '490', tracking: 'latest/stable', publisher: 'canonical✓', notes: 'base' },
      { name: 'burpsuite-community', version: '2024.8.2', rev: '142', tracking: 'latest/stable', publisher: 'portswigger', notes: '-' },
      { name: 'zaproxy', version: '2.15.0', rev: '89', tracking: 'latest/stable', publisher: 'owasp', notes: '-' },
      { name: 'caido-cli', version: '0.41.1', rev: '34', tracking: 'latest/stable', publisher: 'caido-labs', notes: '-' },
      { name: 'snapd', version: '2.65.3', rev: '22710', tracking: 'latest/stable', publisher: 'canonical✓', notes: 'snapd' },
    ],
    env: {
      USER: 'operator',
      HOME: '/home/operator',
      SHELL: '/bin/bash',
      PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin',
      LANG: 'ja_JP.UTF-8',
      TERM: 'xterm-256color',
      HTTP_PROXY: 'http://127.0.0.1:8080',
    },
    commandHistory: [],
  };
}

export function createInitialFS(): Record<string, VirtualFile> {
  const now = '2026-11-22 04:00';
  return {
    '/': { type: 'dir', permissions: 'drwxr-xr-x', owner: 'root', size: 4096, modified: now },
    '/home': { type: 'dir', permissions: 'drwxr-xr-x', owner: 'root', size: 4096, modified: now },
    '/home/operator': { type: 'dir', permissions: 'drwxr-xr-x', owner: 'operator', size: 4096, modified: now },
    '/home/operator/readme.txt': {
      type: 'file',
      permissions: '-rw-r--r--',
      owner: 'operator',
      size: 420,
      modified: now,
      content: `RootRange Security Lab へようこそ！
このターミナルは Ubuntu 24.04 LTS 環境を再現しています。

1. targets.txt に 10段階の攻略対象IPリストが保存されています。
2. nmap / dig / gobuster / ffuf / nikto / nuclei / sqlmap / wpscan /
   joomscan / commix / xsser / hydra / weevely 等でターゲットを調査・攻撃できます。
3. Webタブでブラウザ操作や Burp Suite / OWASP ZAP / Caido プロキシ改ざんが可能です。
4. フラグ (FLAG{...}) を入手したら "submit FLAG{...}" または画面上部の「フラグ提出」で提出してください。`,
    },
    '/home/operator/targets.txt': {
      type: 'file',
      permissions: '-rw-r--r--',
      owner: 'operator',
      size: 512,
      modified: now,
      content: `# Target Network: 10.10.0.0/16
LVL 1  | 10.10.1.10  | portal.nova-corp.local    | 強度 1/10 (超初級)
LVL 2  | 10.10.2.10  | devnotes.nova-corp.local  | 強度 2/10 (初級)
LVL 3  | 10.10.3.10  | shoplite.nova-corp.local  | 強度 3/10 (初級+)
LVL 4  | 10.10.4.10  | blog.nova-corp.local      | 強度 4/10 (中級-)
LVL 5  | 10.10.5.10  | netdiag.nova-corp.local   | 強度 5/10 (中級)
LVL 6  | 10.10.6.10  | intranet.nova-corp.local  | 強度 6/10 (中級+)
LVL 7  | 10.10.7.10  | feedback.nova-corp.local  | 強度 7/10 (上級-)
LVL 8  | 10.10.8.10  | upload.nova-corp.local    | 強度 8/10 (上級)
LVL 9  | 10.10.9.10  | authgate.nova-corp.local  | 強度 9/10 (熟練)
LVL 10 | 10.10.10.10 | aegis.nova-corp.local     | 強度 10/10 (極限)`,
    },
    '/etc': { type: 'dir', permissions: 'drwxr-xr-x', owner: 'root', size: 4096, modified: now },
    '/etc/hosts': {
      type: 'file',
      permissions: '-rw-r--r--',
      owner: 'root',
      size: 380,
      modified: now,
      content: `127.0.0.1 localhost
10.10.0.5 kali-ubuntu-lab
10.10.1.10 portal.nova-corp.local
10.10.2.10 devnotes.nova-corp.local
10.10.3.10 shoplite.nova-corp.local
10.10.4.10 blog.nova-corp.local
10.10.5.10 netdiag.nova-corp.local
10.10.6.10 intranet.nova-corp.local
10.10.7.10 feedback.nova-corp.local
10.10.8.10 upload.nova-corp.local
10.10.9.10 authgate.nova-corp.local
10.10.10.10 aegis.nova-corp.local`,
    },
    '/etc/resolv.conf': {
      type: 'file',
      permissions: '-rw-r--r--',
      owner: 'root',
      size: 120,
      modified: now,
      content: `# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
nameserver 10.10.0.1
nameserver 1.1.1.1
search nova-corp.local`,
    },
    '/etc/netplan': { type: 'dir', permissions: 'drwxr-xr-x', owner: 'root', size: 4096, modified: now },
    '/etc/netplan/01-netcfg.yaml': {
      type: 'file',
      permissions: '-rw-------',
      owner: 'root',
      size: 240,
      modified: now,
      content: `network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: no
      addresses:
        - 10.10.0.5/24
      routes:
        - to: default
          via: 10.10.0.1
      nameservers:
        addresses: [10.10.0.1, 1.1.1.1]`,
    },
    '/usr': { type: 'dir', permissions: 'drwxr-xr-x', owner: 'root', size: 4096, modified: now },
    '/usr/share': { type: 'dir', permissions: 'drwxr-xr-x', owner: 'root', size: 4096, modified: now },
    '/usr/share/wordlists': { type: 'dir', permissions: 'drwxr-xr-x', owner: 'root', size: 4096, modified: now },
    '/usr/share/wordlists/common.txt': {
      type: 'file',
      permissions: '-rw-r--r--',
      owner: 'root',
      size: 1280,
      modified: now,
      content: `admin
administrator
api
api/fetch
api/ping
api/graphql
api/v2/admin/vault
backup
config
dashboard
debug
dev
logs
logs/auth.log
login
post
product
robots.txt
secret-backup
secret-backup/flag.txt
upload.php
uploads
wp-admin
wp-content
wp-login.php`,
    },
    '/usr/share/wordlists/rockyou.txt': {
      type: 'file',
      permissions: '-rw-r--r--',
      owner: 'root',
      size: 2048,
      modified: now,
      content: `123456
password
admin
qwerty
letmein
shadow123
summer2024
Password123!
Aegis#Root2026!
iloveyou
dragon`,
    },
    '/var': { type: 'dir', permissions: 'drwxr-xr-x', owner: 'root', size: 4096, modified: now },
    '/var/log': { type: 'dir', permissions: 'drwxr-xr-x', owner: 'root', size: 4096, modified: now },
    '/var/log/syslog': {
      type: 'file',
      permissions: '-rw-r-----',
      owner: 'syslog',
      size: 540,
      modified: now,
      content: `2026-11-22T04:01:12+09:00 kali-ubuntu-lab systemd[1]: Started OpenBSD Secure Shell server.
2026-11-22T04:01:14+09:00 kali-ubuntu-lab systemd-resolved[412]: Positive Trust Anchors configured.
2026-11-22T04:01:16+09:00 kali-ubuntu-lab kernel: [UFW AUDIT] Interface eth0 UP 10.10.0.5/24`,
    },
  };
}

export function resolvePath(cwd: string, targetPath: string, home = '/home/operator'): string {
  let p = targetPath.trim();
  if (!p || p === '~') return home;
  if (p.startsWith('~/')) p = home + p.slice(1);
  if (!p.startsWith('/')) {
    p = (cwd === '/' ? '' : cwd) + '/' + p;
  }
  const parts = p.split('/');
  const resolved: string[] = [];
  for (const part of parts) {
    if (!part || part === '.') continue;
    if (part === '..') {
      resolved.pop();
    } else {
      resolved.push(part);
    }
  }
  return '/' + resolved.join('/');
}

export function getDirChildren(fs: Record<string, VirtualFile>, dirPath: string): Array<{ name: string; node: VirtualFile }> {
  const prefix = dirPath === '/' ? '/' : dirPath + '/';
  const results: Array<{ name: string; node: VirtualFile }> = [];
  for (const [path, node] of Object.entries(fs)) {
    if (path === dirPath) continue;
    if (path.startsWith(prefix)) {
      const rest = path.slice(prefix.length);
      if (!rest.includes('/')) {
        results.push({ name: rest, node });
      }
    }
  }
  return results.sort((a, b) => a.name.localeCompare(b.name));
}

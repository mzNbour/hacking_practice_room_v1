import { useEffect, useState } from 'react';
import {
  CheckCircle2,
  Code2,
  ExternalLink,
  Flag,
  Globe,
  HelpCircle,
  RefreshCw,
  Send,
  ShieldAlert,
} from 'lucide-react';
import { executeHttpRequest, findTargetByHost, parseTargetUrl } from '../engine/httpEngine';
import { HttpLogEntry, HttpRequest, HttpResponse, ProxyToolMode, TargetServer } from '../types/lab';

interface WebBrowserViewProps {
  targets: TargetServer[];
  selectedTargetId: string;
  onSelectTarget: (targetId: string) => void;
  capturedFlags: string[];
  httpLogs: HttpLogEntry[];
  onLogHttp: (entry: Omit<HttpLogEntry, 'id' | 'timestamp'>) => void;
  mutateTarget: (targetId: string, updater: (prev: TargetServer) => TargetServer) => void;
  proxyOpen: boolean;
  onToggleProxy: (open: boolean) => void;
  proxyTool: ProxyToolMode;
  onSelectProxyTool: (tool: ProxyToolMode) => void;
  onSubmitFlag: (flag: string) => { ok: boolean; message: string };
}

export function WebBrowserView({
  targets,
  selectedTargetId,
  onSelectTarget,
  capturedFlags,
  httpLogs,
  onLogHttp,
  mutateTarget,
  proxyOpen,
  onToggleProxy,
  proxyTool,
  onSelectProxyTool,
  onSubmitFlag,
}: WebBrowserViewProps) {
  const activeTarget = targets.find((t) => t.id === selectedTargetId) || targets[0];

  const [urlInput, setUrlInput] = useState(`http://${activeTarget.ip}/`);
  const [showSource, setShowSource] = useState(false);
  const [showHint, setShowHint] = useState(false);
  const [cookies, setCookies] = useState<Record<string, string>>({ role: 'user' });
  const [lastResponse, setLastResponse] = useState<HttpResponse | null>(null);

  // Interactive form states for target web apps
  const [loginUser, setLoginUser] = useState('admin');
  const [loginPass, setLoginPass] = useState('');
  const [sqliInput, setSqliInput] = useState('1');
  const [lfiFile, setLfiFile] = useState('readme.txt');
  const [pingHost, setPingHost] = useState('127.0.0.1');
  const [xssComment, setXssComment] = useState('');
  const [uploadFilename, setUploadFilename] = useState('shell.phtml');
  const [uploadPassword, setUploadPassword] = useState('pass123');
  const [ssrfUrl, setSsrfUrl] = useState('https://example.com/status');
  const [graphqlQuery, setGraphqlQuery] = useState('{ __schema { types } }');

  // Proxy Repeater states
  const [repMethod, setRepMethod] = useState<HttpRequest['method']>('GET');
  const [repUrl, setRepUrl] = useState(`http://${activeTarget.ip}/`);
  const [repHeaders, setRepHeaders] = useState('User-Agent: Mozilla/5.0\nX-Role: user');
  const [repCookies, setRepCookies] = useState('role=user');
  const [repBody, setRepBody] = useState('');
  const [repResponse, setRepResponse] = useState<HttpResponse | null>(null);

  const navigateTo = (
    targetUrl: string,
    method: HttpRequest['method'] = 'GET',
    body?: string,
    extraHeaders: Record<string, string> = {}
  ) => {
    setUrlInput(targetUrl);
    const req: HttpRequest = {
      method,
      url: targetUrl,
      headers: { 'User-Agent': 'RootRange-Browser/1.0', ...extraHeaders },
      cookies,
      body,
    };
    const res = executeHttpRequest(targets, req, mutateTarget);
    if (res.setCookies) {
      setCookies((prev) => ({ ...prev, ...res.setCookies }));
    }
    setLastResponse(res);

    const parsed = parseTargetUrl(targetUrl);
    const matchedTarget = parsed ? findTargetByHost(targets, parsed.host) : activeTarget;
    if (matchedTarget) {
      onLogHttp({
        targetId: matchedTarget.id,
        toolSource: 'browser',
        request: req,
        response: res,
      });
    }
  };

  useEffect(() => {
    const initialUrl = `http://${activeTarget.ip}/`;
    setUrlInput(initialUrl);
    setRepUrl(initialUrl);
    setShowHint(false);
    setShowSource(false);
    setCookies({ role: 'user' });
    const res = executeHttpRequest(targets, { method: 'GET', url: initialUrl, headers: {}, cookies: { role: 'user' } });
    setLastResponse(res);
  }, [activeTarget.id]);

  const handleSendRepeater = () => {
    const hdrObj: Record<string, string> = {};
    repHeaders.split('\n').forEach((line) => {
      const idx = line.indexOf(':');
      if (idx > 0) {
        hdrObj[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      }
    });
    const cookieObj: Record<string, string> = {};
    repCookies.split(';').forEach((pair) => {
      const [k, v] = pair.split('=');
      if (k && v !== undefined) cookieObj[k.trim()] = v.trim();
    });

    const req: HttpRequest = {
      method: repMethod,
      url: repUrl,
      headers: hdrObj,
      cookies: cookieObj,
      body: repBody || undefined,
    };
    const res = executeHttpRequest(targets, req, mutateTarget);
    setRepResponse(res);
    const parsed = parseTargetUrl(repUrl);
    const t = parsed ? findTargetByHost(targets, parsed.host) : activeTarget;
    if (t) {
      onLogHttp({ targetId: t.id, toolSource: 'repeater', request: req, response: res });
    }
  };

  const loadHistoryToRepeater = (entry: HttpLogEntry) => {
    setRepMethod(entry.request.method);
    setRepUrl(entry.request.url);
    setRepHeaders(
      Object.entries(entry.request.headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n')
    );
    setRepCookies(
      Object.entries(entry.request.cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join('; ')
    );
    setRepBody(entry.request.body || '');
    setRepResponse(entry.response);
  };

  const discoveredFlag = lastResponse?.uiState?.capturedFlag || repResponse?.uiState?.capturedFlag;
  const isTargetCaptured = capturedFlags.includes(activeTarget.flag);

  return (
    <div className="flex-1 min-h-0 flex bg-[#0B0F17]">
      {/* Left Sidebar: 1-10 Targets & Briefing */}
      <aside className="w-80 shrink-0 border-r border-[#232D3F] bg-[#0F1520] flex flex-col min-h-0">
        <div className="px-4 py-3 border-b border-[#232D3F] flex items-center justify-between">
          <h2 className="font-display text-sm font-semibold text-slate-100">ターゲット一覧 (強度 1〜10)</h2>
          <span className="text-xs font-mono text-slate-400 tabular-nums">{targets.length}台</span>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-[#1B2434]">
          {targets.map((t) => {
            const isSelected = t.id === activeTarget.id;
            const captured = capturedFlags.includes(t.flag);
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => onSelectTarget(t.id)}
                className={`w-full text-left px-4 py-3 transition-colors ${
                  isSelected ? 'bg-[#192234]' : 'hover:bg-[#141C2B]'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className={`text-sm font-medium truncate ${isSelected ? 'text-emerald-400' : 'text-slate-100'}`}>
                    {t.isCustom ? t.name : `Lv.${t.level} ${t.name}`}
                  </span>
                  {captured ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : (
                    <span className="text-[11px] font-mono text-slate-500 shrink-0 tabular-nums">{t.level}/10</span>
                  )}
                </div>
                <div className="mt-1 text-xs text-slate-400 flex items-center gap-1.5">
                  <span className="tabular-nums">強度 {t.level}/10</span>
                  <span aria-hidden="true">·</span>
                  <span>{t.difficultyLabel}</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono">{t.ip}</span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Selected Target Mission Briefing */}
        <div className="p-4 border-t border-[#232D3F] bg-[#0B0F17] space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200">
              ミッション概要 {activeTarget.isCustom ? '(カスタム)' : `(強度 ${activeTarget.level}/10)`}
            </span>
            <button
              type="button"
              onClick={() => setShowHint((v) => !v)}
              className="inline-flex items-center gap-1 text-xs text-sky-400 hover:text-sky-300"
            >
              <HelpCircle className="w-3.5 h-3.5" />
              <span>{showHint ? 'ヒント隠す' : 'ヒント'}</span>
            </button>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">{activeTarget.briefing}</p>
          {showHint && (
            <ul className="space-y-1.5 pt-1 text-xs text-amber-300/90 font-mono">
              {activeTarget.hints.map((h, i) => (
                <li key={i} className="leading-relaxed">
                  {i + 1}. {h}
                </li>
              ))}
            </ul>
          )}
        </div>
      </aside>

      {/* Main Browser + Proxy Workbench */}
      <div className="flex-1 min-w-0 flex flex-col min-h-0">
        {/* Browser Address Bar */}
        <div className="h-12 shrink-0 border-b border-[#232D3F] bg-[#121824] px-4 flex items-center gap-3">
          <Globe className="w-4 h-4 text-slate-400 shrink-0" />
          <form
            onSubmit={(e) => {
              e.preventDefault();
              navigateTo(urlInput);
            }}
            className="flex-1 flex items-center gap-2 min-w-0"
          >
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              aria-label="ターゲットURL"
              className="flex-1 px-3 py-1.5 bg-[#0B0F17] border border-[#232D3F] rounded-md font-mono text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
            />
            <button
              type="submit"
              className="px-3 py-1.5 text-xs font-medium bg-[#1E293B] hover:bg-[#2B3A52] text-slate-100 rounded-md transition-colors whitespace-nowrap"
            >
              移動
            </button>
          </form>

          <button
            type="button"
            onClick={() => navigateTo(urlInput)}
            title="再読み込み"
            className="p-1.5 text-slate-400 hover:text-slate-100 rounded hover:bg-[#1E293B] transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={() => setShowSource((v) => !v)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap ${
              showSource
                ? 'bg-[#1E293B] border-sky-500/60 text-sky-300'
                : 'bg-[#0B0F17] border-[#232D3F] text-slate-300 hover:text-slate-100'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>ソース表示</span>
          </button>

          <button
            type="button"
            onClick={() => onToggleProxy(!proxyOpen)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap ${
              proxyOpen
                ? 'bg-amber-500/15 border-amber-500/60 text-amber-300'
                : 'bg-[#0B0F17] border-[#232D3F] text-slate-300 hover:text-slate-100'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>プロキシ (Burp / ZAP / Caido)</span>
          </button>
        </div>

        {/* Flag Captured Inline Banner */}
        {discoveredFlag && !isTargetCaptured && (
          <div className="px-4 py-2.5 bg-emerald-500/10 border-b border-emerald-500/30 flex items-center justify-between gap-4">
            <div className="flex items-center gap-2 text-xs text-emerald-300 font-mono">
              <Flag className="w-3.5 h-3.5 shrink-0" />
              <span>フラグ検出: {discoveredFlag}</span>
            </div>
            <button
              type="button"
              onClick={() => onSubmitFlag(discoveredFlag)}
              className="px-3 py-1 text-xs font-semibold bg-emerald-400 hover:bg-emerald-300 text-slate-950 rounded transition-colors whitespace-nowrap"
            >
              ワンクリック提出
            </button>
          </div>
        )}

        {/* Viewport Split: Web Page + Optional Proxy Workbench */}
        <div className="flex-1 min-h-0 flex flex-col">
          {/* Web Page Content */}
          <div className="flex-1 min-h-0 overflow-y-auto p-6 bg-[#0B0F17]">
            {activeTarget.status === 'stopped' ? (
              <div className="max-w-xl mx-auto mt-12 p-6 border border-[#232D3F] bg-[#121824] rounded-xl text-center space-y-2">
                <h3 className="font-display text-lg font-semibold text-slate-200">503 Service Unavailable</h3>
                <p className="text-sm text-slate-400">
                  対象サーバー ({activeTarget.ip}) は現在停止中です。「サーバー作成」タブから起動してください。
                </p>
              </div>
            ) : showSource ? (
              <div className="max-w-4xl mx-auto border border-[#232D3F] bg-[#090D14] rounded-xl overflow-hidden">
                <div className="px-4 py-2.5 border-b border-[#232D3F] bg-[#121824] flex items-center justify-between text-xs text-slate-400 font-mono">
                  <span>HTTP {lastResponse?.status || 200} {lastResponse?.statusText || 'OK'} — {urlInput}</span>
                  <span>Raw Source</span>
                </div>
                <pre className="p-5 font-mono text-xs text-emerald-300 whitespace-pre-wrap break-words leading-relaxed">
                  {lastResponse?.body || ''}
                </pre>
              </div>
            ) : (
              <div className="max-w-4xl mx-auto space-y-6">
                {/* Simulated Website Header */}
                <div className="border border-[#232D3F] bg-[#121824] rounded-xl p-6 space-y-2">
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <h1 className="font-display text-2xl font-bold text-slate-100">{activeTarget.siteTitle}</h1>
                      <p className="text-sm text-slate-400 mt-1">{activeTarget.siteSubtitle}</p>
                    </div>
                    <div className="text-right text-xs text-slate-400 font-mono">
                      <div>{activeTarget.hostname}</div>
                      <div className="text-slate-500">{activeTarget.webServer}</div>
                    </div>
                  </div>
                  <div className="pt-3 border-t border-[#1E2636] flex flex-wrap items-center gap-4 text-xs text-slate-400">
                    <button type="button" onClick={() => navigateTo(`http://${activeTarget.ip}/`)} className="hover:text-emerald-400">
                      ホーム
                    </button>
                    <button type="button" onClick={() => navigateTo(`http://${activeTarget.ip}/robots.txt`)} className="hover:text-emerald-400">
                      robots.txt
                    </button>
                    {activeTarget.vulnerabilities.includes('weak_auth') && (
                      <button type="button" onClick={() => navigateTo(`http://${activeTarget.ip}/logs/auth.log`)} className="hover:text-emerald-400">
                        /logs/auth.log
                      </button>
                    )}
                    {activeTarget.vulnerabilities.includes('stored_xss') && (
                      <button type="button" onClick={() => navigateTo(`http://${activeTarget.ip}/api/exfil`)} className="hover:text-emerald-400">
                        /api/exfil
                      </button>
                    )}
                  </div>
                </div>

                {/* Alert from last HTTP action */}
                {lastResponse?.uiState?.alert && (
                  <div
                    className={`p-4 rounded-lg border text-xs font-mono ${
                      lastResponse.uiState.alert.type === 'success'
                        ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300'
                        : lastResponse.uiState.alert.type === 'error'
                        ? 'bg-rose-500/10 border-rose-500/40 text-rose-300'
                        : 'bg-sky-500/10 border-sky-500/40 text-sky-300'
                    }`}
                  >
                    {lastResponse.uiState.alert.message}
                  </div>
                )}

                {/* Raw response display when inspecting non-root text/json paths */}
                {parseTargetUrl(urlInput)?.path !== '/' && lastResponse && (
                  <div className="border border-[#232D3F] bg-[#0D121C] rounded-xl p-5">
                    <div className="text-xs font-mono text-slate-400 mb-2">
                      Response ({lastResponse.status} {lastResponse.statusText})
                    </div>
                    <pre className="font-mono text-xs text-slate-200 whitespace-pre-wrap break-words">
                      {lastResponse.body}
                    </pre>
                  </div>
                )}

                {/* Interactive Modules per Vulnerability */}
                {activeTarget.vulnerabilities.includes('html_leak') && (
                  <div className="border border-[#232D3F] bg-[#121824] rounded-xl p-6 space-y-3">
                    <h2 className="font-display text-base font-semibold text-slate-100">公開ポータル案内</h2>
                    <p className="text-sm text-slate-400 leading-relaxed">
                      NovaCorpの公開Webサイトへようこそ。開発チームはデプロイ前の確認作業中であり、HTMLソースコード内のコメントまたは検索エンジン制御ファイルを確認することで隠しバックアップパスが判明する可能性があります。
                    </p>
                    <button
                      type="button"
                      onClick={() => setShowSource(true)}
                      className="px-4 py-2 text-xs font-medium bg-[#1E293B] hover:bg-[#2A3950] text-sky-300 rounded-lg transition-colors"
                    >
                      ページのHTMLソースを表示
                    </button>
                  </div>
                )}

                {activeTarget.vulnerabilities.includes('weak_auth') && (
                  <div className="border border-[#232D3F] bg-[#121824] rounded-xl p-6 space-y-4">
                    <h2 className="font-display text-base font-semibold text-slate-100">管理者ログイン (/login)</h2>
                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        navigateTo(
                          `http://${activeTarget.ip}/login`,
                          'POST',
                          JSON.stringify({ username: loginUser, password: loginPass })
                        );
                      }}
                      className="grid grid-cols-1 sm:grid-cols-3 gap-3"
                    >
                      <input
                        type="text"
                        value={loginUser}
                        onChange={(e) => setLoginUser(e.target.value)}
                        placeholder="ユーザー名"
                        className="px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg text-sm text-slate-100"
                      />
                      <input
                        type="password"
                        value={loginPass}
                        onChange={(e) => setLoginPass(e.target.value)}
                        placeholder="パスワード"
                        className="px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg text-sm text-slate-100"
                      />
                      <button
                        type="submit"
                        className="px-4 py-2 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold text-sm rounded-lg transition-colors"
                      >
                        ログイン
                      </button>
                    </form>
                  </div>
                )}

                {activeTarget.vulnerabilities.includes('sqli') && (
                  <div className="border border-[#232D3F] bg-[#121824] rounded-xl p-6 space-y-4">
                    <h2 className="font-display text-base font-semibold text-slate-100">商品カタログ検索 (/product?id=)</h2>
                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        navigateTo(`http://${activeTarget.ip}/product?id=${encodeURIComponent(sqliInput)}`);
                      }}
                      className="flex gap-3"
                    >
                      <input
                        type="text"
                        value={sqliInput}
                        onChange={(e) => setSqliInput(e.target.value)}
                        placeholder="商品ID (例: 1 または ' OR 1=1--)"
                        className="flex-1 px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg font-mono text-sm text-slate-100"
                      />
                      <button
                        type="submit"
                        className="px-4 py-2 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold text-sm rounded-lg transition-colors whitespace-nowrap"
                      >
                        検索実行
                      </button>
                    </form>
                    {lastResponse?.uiState?.dataRows && (
                      <div className="border border-[#232D3F] rounded-lg overflow-hidden">
                        <table className="w-full text-left text-xs">
                          <thead className="bg-[#0B0F17] text-slate-400 border-b border-[#232D3F]">
                            <tr>
                              <th className="px-3 py-2">ID</th>
                              <th className="px-3 py-2">商品名</th>
                              <th className="px-3 py-2">価格</th>
                              <th className="px-3 py-2">備考 / Secret</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-[#1E2636]">
                            {lastResponse.uiState.dataRows.map((row, idx) => (
                              <tr key={idx} className="bg-[#0E131D]">
                                <td className="px-3 py-2 font-mono">{row.id}</td>
                                <td className="px-3 py-2">{row.name}</td>
                                <td className="px-3 py-2 font-mono">{row.price}</td>
                                <td className="px-3 py-2 font-mono text-emerald-400">{row.secret || '-'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}

                {activeTarget.vulnerabilities.includes('lfi_wp') && (
                  <div className="border border-[#232D3F] bg-[#121824] rounded-xl p-6 space-y-4">
                    <h2 className="font-display text-base font-semibold text-slate-100">
                      WordPress プラグイン: Simple File Viewer
                    </h2>
                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        navigateTo(
                          `http://${activeTarget.ip}/wp-content/plugins/simple-file-viewer/view.php?file=${encodeURIComponent(lfiFile)}`
                        );
                      }}
                      className="flex gap-3"
                    >
                      <input
                        type="text"
                        value={lfiFile}
                        onChange={(e) => setLfiFile(e.target.value)}
                        placeholder="ファイルパス (例: ../../../../etc/flag.txt)"
                        className="flex-1 px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg font-mono text-sm text-slate-100"
                      />
                      <button
                        type="submit"
                        className="px-4 py-2 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold text-sm rounded-lg transition-colors whitespace-nowrap"
                      >
                        ファイル閲覧
                      </button>
                    </form>
                  </div>
                )}

                {activeTarget.vulnerabilities.includes('cmdi') && (
                  <div className="border border-[#232D3F] bg-[#121824] rounded-xl p-6 space-y-4">
                    <h2 className="font-display text-base font-semibold text-slate-100">ICMP Ping 診断 (/api/ping)</h2>
                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        navigateTo(`http://${activeTarget.ip}/api/ping?host=${encodeURIComponent(pingHost)}`);
                      }}
                      className="flex gap-3"
                    >
                      <input
                        type="text"
                        value={pingHost}
                        onChange={(e) => setPingHost(e.target.value)}
                        placeholder="例: 127.0.0.1 | cat /var/www/flag.txt"
                        className="flex-1 px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg font-mono text-sm text-slate-100"
                      />
                      <button
                        type="submit"
                        className="px-4 py-2 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold text-sm rounded-lg transition-colors whitespace-nowrap"
                      >
                        Ping実行
                      </button>
                    </form>
                    {lastResponse?.uiState?.cmdOutput && (
                      <pre className="p-4 bg-[#080B11] border border-[#232D3F] rounded-lg font-mono text-xs text-emerald-300 whitespace-pre-wrap">
                        {lastResponse.uiState.cmdOutput}
                      </pre>
                    )}
                  </div>
                )}

                {activeTarget.vulnerabilities.includes('header_cookie_tamper') && (
                  <div className="border border-[#232D3F] bg-[#121824] rounded-xl p-6 space-y-4">
                    <h2 className="font-display text-base font-semibold text-slate-100">Joomla 社内イントラネット承認</h2>
                    <p className="text-sm text-slate-400">
                      現在のセッションCookie: <code className="font-mono text-sky-300">role={cookies.role || 'user'}</code>
                    </p>
                    <div className="flex flex-wrap gap-3">
                      <button
                        type="button"
                        onClick={() => navigateTo(`http://${activeTarget.ip}/administrator/vault`)}
                        className="px-4 py-2 bg-[#1E293B] hover:bg-[#2B3A52] text-slate-100 text-sm font-medium rounded-lg transition-colors"
                      >
                        /administrator/vault にアクセス
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setRepMethod('GET');
                          setRepUrl(`http://${activeTarget.ip}/administrator/vault`);
                          setRepHeaders('User-Agent: Mozilla/5.0\nX-Role: user');
                          setRepCookies('role=user');
                          onToggleProxy(true);
                        }}
                        className="inline-flex items-center gap-1.5 px-4 py-2 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-300 text-sm font-medium rounded-lg transition-colors"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                        <span>プロキシで改ざんテスト</span>
                      </button>
                    </div>
                  </div>
                )}

                {activeTarget.vulnerabilities.includes('stored_xss') && (
                  <div className="border border-[#232D3F] bg-[#121824] rounded-xl p-6 space-y-4">
                    <h2 className="font-display text-base font-semibold text-slate-100">フィードバック投稿 (/post)</h2>
                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        navigateTo(`http://${activeTarget.ip}/post`, 'POST', JSON.stringify({ comment: xssComment }));
                        setXssComment('');
                      }}
                      className="flex gap-3"
                    >
                      <input
                        type="text"
                        value={xssComment}
                        onChange={(e) => setXssComment(e.target.value)}
                        placeholder="コメント入力 (例: <script>fetch('/api/admin/flag')</script>)"
                        className="flex-1 px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg font-mono text-sm text-slate-100"
                      />
                      <button
                        type="submit"
                        className="px-4 py-2 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold text-sm rounded-lg transition-colors whitespace-nowrap"
                      >
                        投稿
                      </button>
                    </form>
                    <div className="flex items-center justify-between pt-2">
                      <span className="text-xs text-slate-400">Admin Bot 収集ログ (/api/exfil):</span>
                      <button
                        type="button"
                        onClick={() => navigateTo(`http://${activeTarget.ip}/api/exfil`)}
                        className="text-xs text-sky-400 hover:underline"
                      >
                        ログを更新して表示
                      </button>
                    </div>
                    <div className="p-3 bg-[#080B11] border border-[#232D3F] rounded-lg font-mono text-xs text-slate-300 space-y-1">
                      {activeTarget.exfilLogs.map((log, i) => (
                        <div key={i} className={log.includes('FLAG{') ? 'text-emerald-400' : ''}>
                          {log}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {activeTarget.vulnerabilities.includes('file_upload_rce') && (
                  <div className="border border-[#232D3F] bg-[#121824] rounded-xl p-6 space-y-4">
                    <h2 className="font-display text-base font-semibold text-slate-100">ファイルアップロード (/upload.php)</h2>
                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        navigateTo(
                          `http://${activeTarget.ip}/upload.php`,
                          'POST',
                          JSON.stringify({ filename: uploadFilename, password: uploadPassword })
                        );
                      }}
                      className="grid grid-cols-1 sm:grid-cols-3 gap-3"
                    >
                      <input
                        type="text"
                        value={uploadFilename}
                        onChange={(e) => setUploadFilename(e.target.value)}
                        placeholder="ファイル名 (例: shell.phtml)"
                        className="px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg font-mono text-sm text-slate-100"
                      />
                      <input
                        type="text"
                        value={uploadPassword}
                        onChange={(e) => setUploadPassword(e.target.value)}
                        placeholder="Weevelyパスワード"
                        className="px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg font-mono text-sm text-slate-100"
                      />
                      <button
                        type="submit"
                        className="px-4 py-2 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold text-sm rounded-lg transition-colors"
                      >
                        アップロード
                      </button>
                    </form>
                  </div>
                )}

                {activeTarget.vulnerabilities.includes('ssrf_jwt') && (
                  <div className="border border-[#232D3F] bg-[#121824] rounded-xl p-6 space-y-4">
                    <h2 className="font-display text-base font-semibold text-slate-100">URLプレビュー / SSRF (/api/fetch)</h2>
                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        navigateTo(`http://${activeTarget.ip}/api/fetch?url=${encodeURIComponent(ssrfUrl)}`);
                      }}
                      className="flex gap-3"
                    >
                      <input
                        type="text"
                        value={ssrfUrl}
                        onChange={(e) => setSsrfUrl(e.target.value)}
                        placeholder="取得先URL (例: http://127.0.0.1:8080/secret-config)"
                        className="flex-1 px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg font-mono text-sm text-slate-100"
                      />
                      <button
                        type="submit"
                        className="px-4 py-2 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold text-sm rounded-lg transition-colors whitespace-nowrap"
                      >
                        プレビュー取得
                      </button>
                    </form>
                    <button
                      type="button"
                      onClick={() => navigateTo(`http://${activeTarget.ip}/api/v2/admin/vault`)}
                      className="px-4 py-2 bg-[#1E293B] hover:bg-[#2B3A52] text-slate-200 text-xs font-medium rounded-lg transition-colors"
                    >
                      /api/v2/admin/vault へアクセス
                    </button>
                  </div>
                )}

                {activeTarget.vulnerabilities.includes('waf_chain_ssh') && (
                  <div className="border border-[#232D3F] bg-[#121824] rounded-xl p-6 space-y-4">
                    <h2 className="font-display text-base font-semibold text-slate-100">
                      GraphQL Core API (/api/graphql)
                    </h2>
                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        navigateTo(`https://${activeTarget.ip}:8443/api/graphql`, 'POST', graphqlQuery);
                      }}
                      className="flex gap-3"
                    >
                      <input
                        type="text"
                        value={graphqlQuery}
                        onChange={(e) => setGraphqlQuery(e.target.value)}
                        className="flex-1 px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg font-mono text-sm text-slate-100"
                      />
                      <button
                        type="submit"
                        className="px-4 py-2 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold text-sm rounded-lg transition-colors whitespace-nowrap"
                      >
                        クエリ送信
                      </button>
                    </form>
                    <button
                      type="button"
                      onClick={() => {
                        setRepMethod('POST');
                        setRepUrl(`https://${activeTarget.ip}:8443/api/graphql`);
                        setRepHeaders('User-Agent: Mozilla/5.0\nX-Forwarded-For: 127.0.0.1');
                        setRepBody('{ admin_secrets { ssh_user ssh_password } }');
                        onToggleProxy(true);
                      }}
                      className="px-4 py-2 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-300 text-xs font-medium rounded-lg transition-colors"
                    >
                      プロキシ (Repeater) で X-Forwarded-For バイパス送信準備
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Integrated Proxy Workbench (Burp Suite / OWASP ZAP / Caido) */}
          {proxyOpen && (
            <div className="h-80 shrink-0 border-t border-[#232D3F] bg-[#0F1520] flex flex-col">
              <div className="px-4 py-2 border-b border-[#232D3F] flex items-center justify-between gap-4">
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-1 p-0.5 bg-[#0B0F17] border border-[#232D3F] rounded-md">
                    {(
                      [
                        { id: 'burpsuite', label: 'Burp Suite' },
                        { id: 'zap', label: 'OWASP ZAP' },
                        { id: 'caido', label: 'Caido' },
                      ] as const
                    ).map((tool) => (
                      <button
                        key={tool.id}
                        type="button"
                        onClick={() => onSelectProxyTool(tool.id)}
                        className={`px-3 py-1 text-xs font-medium rounded transition-colors ${
                          proxyTool === tool.id
                            ? 'bg-[#1E293B] text-amber-300'
                            : 'text-slate-400 hover:text-slate-100'
                        }`}
                      >
                        {tool.label}
                      </button>
                    ))}
                  </div>
                  <span className="text-xs font-mono text-slate-400">127.0.0.1:8080 · HTTP Repeater &amp; History</span>
                </div>
                <button
                  type="button"
                  onClick={() => onToggleProxy(false)}
                  className="text-xs text-slate-400 hover:text-slate-100"
                >
                  閉じる
                </button>
              </div>

              <div className="flex-1 min-h-0 grid grid-cols-12 divide-x divide-[#232D3F]">
                {/* HTTP History */}
                <div className="col-span-4 overflow-y-auto bg-[#0B0F17]">
                  <div className="px-3 py-1.5 text-[11px] font-semibold text-slate-400 border-b border-[#1E2636]">
                    HTTP Proxy History ({httpLogs.length})
                  </div>
                  {httpLogs.length === 0 ? (
                    <div className="p-4 text-xs text-slate-500">まだ通信履歴がありません。</div>
                  ) : (
                    <div className="divide-y divide-[#182030]">
                      {httpLogs.slice(0, 30).map((entry) => (
                        <button
                          key={entry.id}
                          type="button"
                          onClick={() => loadHistoryToRepeater(entry)}
                          className="w-full text-left px-3 py-2 hover:bg-[#141C2B] transition-colors flex items-center justify-between gap-2 text-xs font-mono"
                        >
                          <span className="truncate text-slate-200">
                            <span className="text-sky-400 mr-1.5">{entry.request.method}</span>
                            {entry.request.url.replace(/^https?:\/\//, '')}
                          </span>
                          <span
                            className={`shrink-0 tabular-nums ${
                              entry.response.status >= 400 ? 'text-rose-400' : 'text-emerald-400'
                            }`}
                          >
                            {entry.response.status}
                          </span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                {/* Request Editor */}
                <div className="col-span-4 p-3 flex flex-col gap-2 overflow-y-auto">
                  <div className="flex items-center gap-2">
                    <select
                      value={repMethod}
                      onChange={(e) => setRepMethod(e.target.value as HttpRequest['method'])}
                      className="px-2 py-1 bg-[#0B0F17] border border-[#232D3F] rounded text-xs font-mono text-slate-100"
                    >
                      <option value="GET">GET</option>
                      <option value="POST">POST</option>
                      <option value="PUT">PUT</option>
                    </select>
                    <input
                      type="text"
                      value={repUrl}
                      onChange={(e) => setRepUrl(e.target.value)}
                      className="flex-1 px-2.5 py-1 bg-[#0B0F17] border border-[#232D3F] rounded text-xs font-mono text-slate-100"
                    />
                    <button
                      type="button"
                      onClick={handleSendRepeater}
                      className="inline-flex items-center gap-1 px-3 py-1 bg-amber-400 hover:bg-amber-300 text-slate-950 font-semibold text-xs rounded transition-colors whitespace-nowrap"
                    >
                      <Send className="w-3 h-3" />
                      <span>送信</span>
                    </button>
                  </div>

                  <div className="grid grid-cols-2 gap-2 flex-1 min-h-0">
                    <div className="flex flex-col">
                      <label className="text-[11px] text-slate-400 mb-1">Headers (1行1ヘッダ)</label>
                      <textarea
                        value={repHeaders}
                        onChange={(e) => setRepHeaders(e.target.value)}
                        className="flex-1 p-2 bg-[#0B0F17] border border-[#232D3F] rounded font-mono text-[11px] text-slate-200 resize-none focus:outline-none focus:border-amber-400"
                      />
                    </div>
                    <div className="flex flex-col gap-2">
                      <div className="flex flex-col">
                        <label className="text-[11px] text-slate-400 mb-1">Cookies</label>
                        <input
                          type="text"
                          value={repCookies}
                          onChange={(e) => setRepCookies(e.target.value)}
                          className="px-2 py-1 bg-[#0B0F17] border border-[#232D3F] rounded font-mono text-[11px] text-slate-200"
                        />
                      </div>
                      <div className="flex-1 flex flex-col">
                        <label className="text-[11px] text-slate-400 mb-1">Body</label>
                        <textarea
                          value={repBody}
                          onChange={(e) => setRepBody(e.target.value)}
                          className="flex-1 p-2 bg-[#0B0F17] border border-[#232D3F] rounded font-mono text-[11px] text-slate-200 resize-none focus:outline-none focus:border-amber-400"
                        />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Repeater Response */}
                <div className="col-span-4 p-3 overflow-y-auto bg-[#080B11] font-mono text-xs">
                  <div className="text-[11px] text-slate-400 mb-2">
                    Response:{' '}
                    {repResponse ? (
                      <span className={repResponse.status >= 400 ? 'text-rose-400' : 'text-emerald-400'}>
                        HTTP {repResponse.status} {repResponse.statusText}
                      </span>
                    ) : (
                      '送信ボタンを押してレスポンスを確認'
                    )}
                  </div>
                  {repResponse && (
                    <pre className="text-slate-200 whitespace-pre-wrap break-words text-[11px] leading-relaxed">
                      {Object.entries(repResponse.headers)
                        .map(([k, v]) => `${k}: ${v}`)
                        .join('\n')}
                      {'\n\n'}
                      {repResponse.body}
                    </pre>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

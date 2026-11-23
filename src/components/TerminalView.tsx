import { useEffect, useRef, useState } from 'react';
import { PanelLeftClose, PanelLeftOpen, RotateCcw, Terminal as TerminalIcon } from 'lucide-react';
import { ALL_COMMANDS } from '../engine/commandProcessor';
import { RemoteSession, SystemState, TargetServer, TerminalLine } from '../types/lab';

interface TerminalViewProps {
  lines: TerminalLine[];
  system: SystemState;
  remoteSession: RemoteSession | null;
  targets: TargetServer[];
  capturedFlags: string[];
  onExecute: (cmd: string) => void;
  onClear: () => void;
  onResetLab: () => void;
  onSelectTargetInWeb: (targetId: string) => void;
}

const PENTEST_CHEATSHEET = [
  { name: 'nmap', example: 'nmap -sV 10.10.1.10', desc: 'ポート＆サービススキャン' },
  { name: 'Burp Suite', example: 'Burp Suite', desc: 'HTTPプロキシ＆改ざんツール起動' },
  { name: 'OWASP ZAP', example: 'OWASP ZAP -quickurl http://10.10.1.10', desc: '脆弱性プロキシ＆スキャナ' },
  { name: 'Caido', example: 'Caido', desc: 'モダンWebプロキシ＆Replay' },
  { name: 'Gobuster', example: 'gobuster dir -u http://10.10.1.10 -w /usr/share/wordlists/common.txt', desc: 'ディレクトリ探索' },
  { name: 'ffuf', example: 'ffuf -u http://10.10.8.10/FUZZ -w /usr/share/wordlists/common.txt', desc: '高速Webファザー' },
  { name: 'Nikto', example: 'nikto -h http://10.10.2.10', desc: 'Webサーバー脆弱性診断' },
  { name: 'Nuclei', example: 'nuclei -u http://10.10.4.10', desc: 'テンプレート脆弱性スキャン' },
  { name: 'WhatWeb', example: 'whatweb http://10.10.4.10', desc: 'Web技術フィンガープリント' },
  { name: 'Wappalyzer', example: 'wappalyzer http://10.10.6.10', desc: '使用技術JSON解析' },
  { name: 'sqlmap', example: 'sqlmap -u "http://10.10.3.10/product?id=1" --dump', desc: '自動SQLインジェクション' },
  { name: 'WPScan', example: 'wpscan --url http://10.10.4.10', desc: 'WordPress脆弱性検査' },
  { name: 'JoomScan', example: 'joomscan -u http://10.10.6.10', desc: 'Joomla脆弱性検査' },
  { name: 'Hydra', example: 'hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.2.10 http-post-form', desc: 'ログインブルートフォース' },
  { name: 'Dirb', example: 'dirb http://10.10.1.10', desc: 'Webコンテンツ探索' },
  { name: 'DirBuster', example: 'dirbuster -u http://10.10.2.10', desc: 'ディレクトリ総当たり' },
  { name: 'Wfuzz', example: 'wfuzz -u http://10.10.8.10/FUZZ', desc: 'Webパラメータファジング' },
  { name: 'Wapiti', example: 'wapiti -u http://10.10.7.10', desc: 'Web脆弱性監査' },
  { name: 'Skipfish', example: 'skipfish -o out http://10.10.7.10', desc: '能動Web偵察スキャン' },
  { name: 'Commix', example: 'commix -u "http://10.10.5.10/api/ping?host=127.0.0.1" --os-cmd="cat /var/www/flag.txt"', desc: 'OSコマンドインジェクション' },
  { name: 'XSSer', example: 'xsser -u "http://10.10.7.10/post"', desc: 'XSS自動検出' },
  { name: 'Weevely', example: 'weevely generate pass123 shell.phtml', desc: 'ステルスPHP Webシェル' },
];

const LINUX_CHEATSHEET = [
  { name: 'ip', example: 'ip a', desc: 'IPアドレス・ルート確認' },
  { name: 'ss', example: 'ss -tulnp', desc: 'リッスン中のソケット確認' },
  { name: 'dig', example: 'dig portal.nova-corp.local', desc: 'DNS名前解決照会' },
  { name: 'resolvectl', example: 'resolvectl status', desc: 'systemd-resolved状態確認' },
  { name: 'systemctl', example: 'systemctl list-units', desc: 'systemdサービス管理' },
  { name: 'journalctl', example: 'journalctl -u ssh -n 10', desc: 'systemdジャーナルログ参照' },
  { name: 'apt', example: 'apt list --installed', desc: 'APTパッケージ管理' },
  { name: 'timedatectl', example: 'timedatectl status', desc: '時刻・タイムゾーン確認' },
  { name: 'chronyc', example: 'chronyc tracking', desc: 'NTP時刻同期ステータス' },
  { name: 'snap', example: 'snap list', desc: 'Snapパッケージ一覧' },
  { name: 'netplan', example: 'netplan status', desc: 'Netplanネットワーク設定' },
  { name: 'ufw', example: 'ufw status verbose', desc: 'ファイアウォール設定' },
  { name: 'do-release-upgrade', example: 'do-release-upgrade -c', desc: 'Ubuntuリリース確認' },
  { name: 'ubuntu-drivers', example: 'ubuntu-drivers list', desc: 'ハードウェアドライバ一覧' },
  { name: 'pro', example: 'pro status', desc: 'Ubuntu Pro状態確認' },
  { name: 'hostnamectl', example: 'hostnamectl', desc: 'ホスト名・OS詳細確認' },
  { name: 'localectl', example: 'localectl status', desc: 'ロケール・キーマップ確認' },
  { name: 'loginctl', example: 'loginctl list-sessions', desc: 'ログインセッション管理' },
  { name: 'networkctl', example: 'networkctl list', desc: 'networkdリンク状態' },
  { name: 'nmcli', example: 'nmcli device status', desc: 'NetworkManager CLI' },
  { name: 'resolvconf', example: 'resolvconf -l', desc: 'resolv.conf生成管理' },
];

export function TerminalView({
  lines,
  system,
  remoteSession,
  targets,
  capturedFlags,
  onExecute,
  onClear,
  onResetLab,
  onSelectTargetInWeb,
}: TerminalViewProps) {
  const [input, setInput] = useState('');
  const [historyCursor, setHistoryCursor] = useState<number>(-1);
  const [showSidebar, setShowSidebar] = useState(true);
  const [refTab, setRefTab] = useState<'targets' | 'pentest' | 'linux'>('targets');
  const [searchQuery, setSearchQuery] = useState('');

  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [lines]);

  const promptText = remoteSession
    ? `${remoteSession.user}@${remoteSession.hostname}:${remoteSession.cwd}${remoteSession.isRoot ? '#' : '$'} `
    : `${system.username}@${system.hostname}:${system.cwd === '/home/operator' ? '~' : system.cwd}$ `;

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      const cmd = input;
      setInput('');
      setHistoryCursor(-1);
      onExecute(cmd);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      const hist = system.commandHistory;
      if (hist.length === 0) return;
      const nextIdx = historyCursor === -1 ? hist.length - 1 : Math.max(0, historyCursor - 1);
      setHistoryCursor(nextIdx);
      setInput(hist[nextIdx]);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      const hist = system.commandHistory;
      if (historyCursor === -1) return;
      if (historyCursor >= hist.length - 1) {
        setHistoryCursor(-1);
        setInput('');
      } else {
        const nextIdx = historyCursor + 1;
        setHistoryCursor(nextIdx);
        setInput(hist[nextIdx]);
      }
    } else if (e.key === 'Tab') {
      e.preventDefault();
      const parts = input.split(/\s+/);
      const last = parts[parts.length - 1] || '';
      if (!last) return;
      if (parts.length === 1) {
        const match = ALL_COMMANDS.find((c) => c.startsWith(last.toLowerCase()));
        if (match) setInput(match + ' ');
      } else {
        const hostCandidates = targets.flatMap((t) => [t.ip, t.hostname]);
        const match = hostCandidates.find((h) => h.startsWith(last));
        if (match) {
          parts[parts.length - 1] = match;
          setInput(parts.join(' '));
        }
      }
    } else if (e.ctrlKey && e.key.toLowerCase() === 'l') {
      e.preventDefault();
      onClear();
    } else if (e.ctrlKey && e.key.toLowerCase() === 'c') {
      e.preventDefault();
      setInput('');
    }
  };

  const insertCommand = (cmd: string) => {
    setInput(cmd);
    inputRef.current?.focus();
  };

  const filteredPentest = PENTEST_CHEATSHEET.filter(
    (c) =>
      c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.desc.toLowerCase().includes(searchQuery.toLowerCase())
  );
  const filteredLinux = LINUX_CHEATSHEET.filter(
    (c) =>
      c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.desc.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="flex-1 min-h-0 flex bg-[#0B0F17]">
      {/* Collapsible Reference Sidebar */}
      {showSidebar && (
        <aside className="w-80 shrink-0 border-r border-[#232D3F] bg-[#0F1520] flex flex-col min-h-0">
          <div className="p-3 border-b border-[#232D3F] space-y-2.5">
            <div className="flex items-center gap-1 p-1 bg-[#0B0F17] border border-[#232D3F] rounded-lg">
              {(
                [
                  { id: 'targets', label: 'ターゲット' },
                  { id: 'pentest', label: '攻撃ツール' },
                  { id: 'linux', label: 'Linux管理' },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setRefTab(tab.id)}
                  className={`flex-1 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                    refTab === tab.id ? 'bg-[#1E293B] text-emerald-400' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
            {refTab !== 'targets' && (
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="コマンド検索..."
                className="w-full px-3 py-1.5 bg-[#0B0F17] border border-[#232D3F] rounded-md text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
              />
            )}
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-[#1B2434]">
            {refTab === 'targets' &&
              targets.map((t) => {
                const captured = capturedFlags.includes(t.flag);
                return (
                  <div key={t.id} className="p-3 hover:bg-[#141C2B] transition-colors space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-semibold text-slate-100 truncate">
                        {t.isCustom ? `Custom · ${t.name}` : `Lv.${t.level} ${t.name}`}
                      </span>
                      <span
                        className={`text-[11px] font-medium shrink-0 ${
                          t.status === 'stopped'
                            ? 'text-slate-500'
                            : captured
                            ? 'text-emerald-400'
                            : 'text-amber-400'
                        }`}
                      >
                        {t.status === 'stopped' ? '停止中' : captured ? '攻略済' : '未攻略'}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono flex items-center gap-1.5">
                      <span className="tabular-nums">強度 {t.level}/10</span>
                      <span aria-hidden="true">·</span>
                      <span>{t.ip}</span>
                    </div>
                    <div className="flex items-center gap-2 pt-1">
                      <button
                        type="button"
                        onClick={() => insertCommand(`nmap -sV ${t.ip}`)}
                        className="px-2.5 py-1 text-[11px] font-mono bg-[#0B0F17] hover:bg-[#1E293B] border border-[#232D3F] text-slate-300 rounded transition-colors"
                      >
                        nmap挿入
                      </button>
                      <button
                        type="button"
                        onClick={() => onSelectTargetInWeb(t.id)}
                        className="px-2.5 py-1 text-[11px] bg-[#0B0F17] hover:bg-[#1E293B] border border-[#232D3F] text-sky-400 rounded transition-colors"
                      >
                        Webで開く
                      </button>
                    </div>
                  </div>
                );
              })}

            {refTab === 'pentest' &&
              filteredPentest.map((item) => (
                <button
                  key={item.name}
                  type="button"
                  onClick={() => insertCommand(item.example)}
                  className="w-full text-left p-3 hover:bg-[#141C2B] transition-colors block"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-semibold text-emerald-400">{item.name}</span>
                    <span className="text-[11px] text-slate-500">クリックで挿入</span>
                  </div>
                  <div className="text-xs text-slate-300 mt-0.5">{item.desc}</div>
                  <div className="text-[11px] font-mono text-slate-500 mt-1 truncate">{item.example}</div>
                </button>
              ))}

            {refTab === 'linux' &&
              filteredLinux.map((item) => (
                <button
                  key={item.name}
                  type="button"
                  onClick={() => insertCommand(item.example)}
                  className="w-full text-left p-3 hover:bg-[#141C2B] transition-colors block"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-semibold text-sky-400">{item.name}</span>
                    <span className="text-[11px] text-slate-500">クリックで挿入</span>
                  </div>
                  <div className="text-xs text-slate-300 mt-0.5">{item.desc}</div>
                  <div className="text-[11px] font-mono text-slate-500 mt-1 truncate">{item.example}</div>
                </button>
              ))}
          </div>
        </aside>
      )}

      {/* Main Terminal Canvas */}
      <section className="flex-1 min-w-0 flex flex-col bg-[#080B11]">
        {/* Terminal Sub-toolbar */}
        <div className="h-10 shrink-0 border-b border-[#1E2636] bg-[#0D121C] px-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setShowSidebar((v) => !v)}
              className="p-1.5 text-slate-400 hover:text-slate-100 rounded hover:bg-[#182131] transition-colors"
              title={showSidebar ? 'サイドバーを閉じる' : 'サイドバーを開く'}
            >
              {showSidebar ? <PanelLeftClose className="w-4 h-4" /> : <PanelLeftOpen className="w-4 h-4" />}
            </button>
            <div className="flex items-center gap-2 text-xs font-mono text-slate-300 truncate">
              <TerminalIcon className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span className="truncate">
                {remoteSession
                  ? `${remoteSession.type.toUpperCase()} — ${remoteSession.user}@${remoteSession.ip}`
                  : `${system.username}@${system.hostname} (${system.ipAddress})`}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={onClear}
              className="px-2.5 py-1 text-xs text-slate-300 hover:text-slate-100 bg-[#141C2B] hover:bg-[#1E293B] border border-[#232D3F] rounded transition-colors"
            >
              クリア
            </button>
            <button
              type="button"
              onClick={onResetLab}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs text-slate-300 hover:text-slate-100 bg-[#141C2B] hover:bg-[#1E293B] border border-[#232D3F] rounded transition-colors"
            >
              <RotateCcw className="w-3 h-3" />
              <span>初期化</span>
            </button>
          </div>
        </div>

        {/* Terminal Scrollable Buffer */}
        <div
          onClick={() => inputRef.current?.focus()}
          className="flex-1 overflow-y-auto p-5 font-mono text-[13px] leading-relaxed cursor-text select-text space-y-1.5"
        >
          {lines.map((ln) => {
            if (ln.kind === 'prompt') {
              return (
                <div key={ln.id} className="break-all">
                  <span className="text-emerald-400 font-semibold">{ln.promptText}</span>
                  <span className="text-slate-100">{ln.text}</span>
                </div>
              );
            }
            const colorClass =
              ln.kind === 'error'
                ? 'text-rose-400'
                : ln.kind === 'success'
                ? 'text-emerald-300'
                : ln.kind === 'warning'
                ? 'text-amber-300'
                : ln.kind === 'info'
                ? 'text-sky-300'
                : 'text-slate-300';
            return (
              <pre key={ln.id} className={`${colorClass} whitespace-pre-wrap break-words font-mono`}>
                {ln.text}
              </pre>
            );
          })}

          {/* Active Prompt Input */}
          <div className="flex items-center gap-0 pt-1">
            <span className="text-emerald-400 font-semibold whitespace-pre shrink-0">{promptText}</span>
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              autoFocus
              spellCheck={false}
              autoCapitalize="off"
              autoComplete="off"
              aria-label="Linuxターミナル入力"
              className="flex-1 bg-transparent text-slate-100 font-mono text-[13px] focus:outline-none caret-emerald-400"
            />
          </div>
          <div ref={bottomRef} />
        </div>
      </section>
    </div>
  );
}

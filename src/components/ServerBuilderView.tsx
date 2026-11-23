import { useState } from 'react';
import { Globe, Play, Plus, Server, Square, Trash2 } from 'lucide-react';
import { CustomServerInput, createCustomTargetServer } from '../data/targets';
import { TargetServer, VulnerabilityType } from '../types/lab';

interface ServerBuilderViewProps {
  targets: TargetServer[];
  onAddServer: (server: TargetServer) => void;
  onToggleServerStatus: (targetId: string) => void;
  onDeleteServer: (targetId: string) => void;
  onOpenInWeb: (targetId: string) => void;
}

const VULN_OPTIONS: Array<{ id: VulnerabilityType; label: string; toolHint: string }> = [
  { id: 'html_leak', label: 'HTMLコメント / robots.txt 情報漏洩', toolHint: 'curl / gobuster / nikto' },
  { id: 'weak_auth', label: '脆弱パスワード & auth.log 露出', toolHint: 'hydra / dirb' },
  { id: 'sqli', label: 'SQLインジェクション (UNION / Error)', toolHint: 'sqlmap' },
  { id: 'lfi_wp', label: 'WordPress プラグイン LFI', toolHint: 'wpscan / nuclei' },
  { id: 'cmdi', label: 'OSコマンドインジェクション', toolHint: 'commix' },
  { id: 'header_cookie_tamper', label: 'Cookie / Header 権限改ざん', toolHint: 'Burp Suite / Caido / joomscan' },
  { id: 'stored_xss', label: '蓄積型 XSS (管理ボット巡回)', toolHint: 'xsser / wapiti' },
  { id: 'file_upload_rce', label: 'Webシェルアップロード RCE', toolHint: 'weevely / ffuf' },
  { id: 'ssrf_jwt', label: 'SSRF 内部メタデータ & JWT偽造', toolHint: 'ffuf / Repeater' },
  { id: 'waf_chain_ssh', label: 'WAFバイパス + GraphQL + SSH', toolHint: 'nmap / ssh' },
];

export function ServerBuilderView({
  targets,
  onAddServer,
  onToggleServerStatus,
  onDeleteServer,
  onOpenInWeb,
}: ServerBuilderViewProps) {
  const nextCustomNum = targets.filter((t) => t.isCustom).length + 1;

  const [name, setName] = useState(`Custom Lab #${nextCustomNum}`);
  const [hostname, setHostname] = useState(`custom-${nextCustomNum}.nova-corp.local`);
  const [ip, setIp] = useState(`10.10.20.${10 + nextCustomNum}`);
  const [level, setLevel] = useState<number>(4);
  const [webServer, setWebServer] = useState('nginx/1.26.0');
  const [cms, setCms] = useState<CustomServerInput['cms']>('Custom');
  const [ufwEnabled, setUfwEnabled] = useState(true);
  const [wafEnabled, setWafEnabled] = useState(false);
  const [sshEnabled, setSshEnabled] = useState(true);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityType[]>(['sqli', 'weak_auth']);
  const [siteTitle, setSiteTitle] = useState(`Custom Target Node #${nextCustomNum}`);
  const [siteSubtitle, setSiteSubtitle] = useState('ユーザー構築セキュリティ検証環境');
  const [flag, setFlag] = useState(`FLAG{custom_server_${nextCustomNum}_pwned}`);
  const [adminPassword, setAdminPassword] = useState('letmein');
  const [createdBanner, setCreatedBanner] = useState<string | null>(null);

  const toggleVuln = (id: VulnerabilityType) => {
    setVulnerabilities((prev) => (prev.includes(id) ? prev.filter((v) => v !== id) : [...prev, id]));
  };

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    const newServer = createCustomTargetServer({
      name,
      hostname,
      ip,
      level,
      webServer,
      cms,
      ufwEnabled,
      wafEnabled,
      sshEnabled,
      vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : ['html_leak'],
      siteTitle,
      siteSubtitle,
      flag,
      adminPassword,
    });
    onAddServer(newServer);
    setCreatedBanner(
      `サーバー "${newServer.name}" (${newServer.ip} / ${newServer.hostname}) をデプロイしました！ターミナルの nmap / dig / sqlmap や Webタブからすぐ攻撃できます。`
    );

    const n = nextCustomNum + 1;
    setName(`Custom Lab #${n}`);
    setHostname(`custom-${n}.nova-corp.local`);
    setIp(`10.10.20.${10 + n}`);
    setSiteTitle(`Custom Target Node #${n}`);
    setFlag(`FLAG{custom_server_${n}_pwned}`);
  };

  return (
    <div className="flex-1 min-h-0 overflow-y-auto bg-[#0B0F17] p-6">
      <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Create Server Form */}
        <section className="lg:col-span-7 border border-[#232D3F] bg-[#121824] rounded-xl p-6 space-y-6">
          <div>
            <h1 className="font-display text-xl font-bold text-slate-100">カスタムターゲットサーバー作成</h1>
            <p className="text-sm text-slate-400 mt-1">
              独自のWebアプリ・脆弱性・防御設定を組み合わせた攻撃演習サーバーを作成し、ネットワークへ即時デプロイします。
            </p>
          </div>

          {createdBanner && (
            <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/40 text-xs text-emerald-300">
              {createdBanner}
            </div>
          )}

          <form onSubmit={handleCreate} className="space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">サーバー名</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">ホスト名 (DNS)</label>
                <input
                  type="text"
                  required
                  value={hostname}
                  onChange={(e) => setHostname(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg font-mono text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">IPアドレス</label>
                <input
                  type="text"
                  required
                  value={ip}
                  onChange={(e) => setIp(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg font-mono text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>

            {/* Strength Slider 1-10 */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label htmlFor="strength-slider" className="text-xs font-medium text-slate-300">
                  サーバー強度レベル (1〜10)
                </label>
                <span className="font-mono text-sm font-semibold text-emerald-400 tabular-nums">
                  強度 {level} / 10
                </span>
              </div>
              <input
                id="strength-slider"
                type="range"
                min={1}
                max={10}
                value={level}
                onChange={(e) => setLevel(Number(e.target.value))}
                className="w-full accent-emerald-400 cursor-pointer"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Webサーバー</label>
                <select
                  value={webServer}
                  onChange={(e) => setWebServer(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg text-sm text-slate-100"
                >
                  <option value="nginx/1.26.0">nginx/1.26.0 (Ubuntu)</option>
                  <option value="Apache/2.4.58">Apache/2.4.58 (Ubuntu)</option>
                  <option value="Express/4.19.2 (Node.js)">Express/4.19.2 (Node.js)</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">CMS / フレームワーク</label>
                <select
                  value={cms}
                  onChange={(e) => setCms(e.target.value as CustomServerInput['cms'])}
                  className="w-full px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg text-sm text-slate-100"
                >
                  <option value="Custom">Custom Web App</option>
                  <option value="WordPress">WordPress 6.1.1</option>
                  <option value="Joomla">Joomla! 3.10.11</option>
                  <option value="Node.js">Node.js API</option>
                  <option value="GraphQL">GraphQL Core</option>
                </select>
              </div>
            </div>

            {/* Defense Options */}
            <div className="flex flex-wrap gap-6 pt-1">
              <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={ufwEnabled}
                  onChange={(e) => setUfwEnabled(e.target.checked)}
                  className="accent-emerald-400 w-4 h-4"
                />
                <span>ufw ファイアウォール有効</span>
              </label>
              <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={wafEnabled}
                  onChange={(e) => setWafEnabled(e.target.checked)}
                  className="accent-emerald-400 w-4 h-4"
                />
                <span>ModSecurity WAF 有効</span>
              </label>
              <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={sshEnabled}
                  onChange={(e) => setSshEnabled(e.target.checked)}
                  className="accent-emerald-400 w-4 h-4"
                />
                <span>OpenSSH (Port 22) 開放</span>
              </label>
            </div>

            {/* Vulnerability Modules */}
            <div className="space-y-2.5">
              <div className="text-xs font-medium text-slate-300">組み込む脆弱性モジュール</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {VULN_OPTIONS.map((v) => {
                  const checked = vulnerabilities.includes(v.id);
                  return (
                    <label
                      key={v.id}
                      className={`p-3 rounded-lg border cursor-pointer transition-colors flex items-start gap-2.5 ${
                        checked
                          ? 'bg-[#192334] border-emerald-500/50 text-slate-100'
                          : 'bg-[#0B0F17] border-[#232D3F] text-slate-400 hover:border-slate-600'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggleVuln(v.id)}
                        className="mt-0.5 accent-emerald-400"
                      />
                      <div className="min-w-0">
                        <div className="text-xs font-medium leading-snug">{v.label}</div>
                        <div className="text-[11px] font-mono text-slate-500 mt-0.5">{v.toolHint}</div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>

            {/* Flag & Site Appearance */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">埋め込むフラグ</label>
                <input
                  type="text"
                  required
                  value={flag}
                  onChange={(e) => setFlag(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg font-mono text-sm text-emerald-300 focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Adminパスワード</label>
                <input
                  type="text"
                  value={adminPassword}
                  onChange={(e) => setAdminPassword(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg font-mono text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Webページタイトル</label>
                <input
                  type="text"
                  value={siteTitle}
                  onChange={(e) => setSiteTitle(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg text-sm text-slate-100"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">サブタイトル</label>
                <input
                  type="text"
                  value={siteSubtitle}
                  onChange={(e) => setSiteSubtitle(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0B0F17] border border-[#232D3F] rounded-lg text-sm text-slate-100"
                />
              </div>
            </div>

            <button
              type="submit"
              className="w-full py-2.5 px-5 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold text-sm rounded-lg transition-colors inline-flex items-center justify-center gap-2"
            >
              <Plus className="w-4 h-4" />
              <span>サーバーを作成してネットワークへ起動</span>
            </button>
          </form>
        </section>

        {/* Right: Active Server Fleet Control */}
        <section className="lg:col-span-5 border border-[#232D3F] bg-[#121824] rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-[#232D3F] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-sky-400" />
              <h2 className="font-display text-base font-semibold text-slate-100">稼働中サーバー管理</h2>
            </div>
            <span className="text-xs font-mono text-slate-400 tabular-nums">{targets.length}台</span>
          </div>

          <div className="divide-y divide-[#1E2636] max-h-[760px] overflow-y-auto">
            {targets.map((t) => (
              <div key={t.id} className="p-4 hover:bg-[#161E2E] transition-colors space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-slate-100 truncate">
                      {t.isCustom ? t.name : `Lv.${t.level} ${t.name}`}
                    </div>
                    <div className="text-xs text-slate-400 font-mono flex items-center gap-1.5 mt-0.5">
                      <span className="tabular-nums">強度 {t.level}/10</span>
                      <span aria-hidden="true">·</span>
                      <span>{t.ip}</span>
                      <span aria-hidden="true">·</span>
                      <span className={t.status === 'running' ? 'text-emerald-400' : 'text-slate-500'}>
                        {t.status === 'running' ? '稼働中' : '停止'}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    <button
                      type="button"
                      onClick={() => onToggleServerStatus(t.id)}
                      title={t.status === 'running' ? '停止' : '起動'}
                      className="p-1.5 rounded bg-[#0B0F17] hover:bg-[#1E293B] border border-[#232D3F] text-slate-300 transition-colors"
                    >
                      {t.status === 'running' ? (
                        <Square className="w-3.5 h-3.5 text-amber-400" />
                      ) : (
                        <Play className="w-3.5 h-3.5 text-emerald-400" />
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={() => onOpenInWeb(t.id)}
                      title="Webタブで開く"
                      className="p-1.5 rounded bg-[#0B0F17] hover:bg-[#1E293B] border border-[#232D3F] text-sky-400 transition-colors"
                    >
                      <Globe className="w-3.5 h-3.5" />
                    </button>
                    {t.isCustom && (
                      <button
                        type="button"
                        onClick={() => onDeleteServer(t.id)}
                        title="削除"
                        className="p-1.5 rounded bg-[#0B0F17] hover:bg-[#1E293B] border border-[#232D3F] text-rose-400 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>
                <div className="text-[11px] font-mono text-slate-500 truncate">
                  {t.hostname} · {t.vulnerabilities.join(', ')}
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}

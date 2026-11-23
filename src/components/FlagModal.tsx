import { useState } from 'react';
import { CheckCircle2, Flag, X } from 'lucide-react';
import { TargetServer } from '../types/lab';

interface FlagModalProps {
  isOpen: boolean;
  onClose: () => void;
  targets: TargetServer[];
  capturedFlags: string[];
  onSubmitFlag: (flag: string) => { ok: boolean; message: string };
  onJumpToTarget: (targetId: string) => void;
}

export function FlagModal({
  isOpen,
  onClose,
  targets,
  capturedFlags,
  onSubmitFlag,
  onJumpToTarget,
}: FlagModalProps) {
  const [inputFlag, setInputFlag] = useState('');
  const [feedback, setFeedback] = useState<{ ok: boolean; message: string } | null>(null);

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputFlag.trim()) return;
    const res = onSubmitFlag(inputFlag.trim());
    setFeedback(res);
    if (res.ok) setInputFlag('');
  };

  const officialTargets = targets.filter((t) => !t.isCustom);
  const customTargets = targets.filter((t) => t.isCustom);

  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4" role="dialog" aria-modal="true">
      <div className="w-full max-w-2xl bg-[#121824] border border-[#232D3F] rounded-xl overflow-hidden shadow-2xl">
        <div className="px-6 py-4 border-b border-[#232D3F] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Flag className="w-4 h-4 text-emerald-400" />
            <h2 className="font-display text-base font-semibold text-slate-100">フラグ提出 &amp; 攻略状況</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="閉じる"
            className="p-1.5 text-slate-400 hover:text-slate-100 rounded-md hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 space-y-6 max-h-[80vh] overflow-y-auto">
          <form onSubmit={handleSubmit} className="space-y-3">
            <label htmlFor="flag-input" className="block text-xs font-medium text-slate-300">
              取得したフラグを入力 (例: FLAG&#123;...&#125;)
            </label>
            <div className="flex gap-2">
              <input
                id="flag-input"
                type="text"
                value={inputFlag}
                onChange={(e) => setInputFlag(e.target.value)}
                placeholder="FLAG{...}"
                className="flex-1 px-3.5 py-2.5 bg-[#0B0F17] border border-[#232D3F] rounded-lg text-sm font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
              />
              <button
                type="submit"
                className="px-5 py-2.5 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold text-sm rounded-lg transition-colors whitespace-nowrap shrink-0"
              >
                検証して提出
              </button>
            </div>
            {feedback && (
              <p className={`text-xs font-medium ${feedback.ok ? 'text-emerald-400' : 'text-rose-400'}`}>
                {feedback.message}
              </p>
            )}
          </form>

          <div>
            <h3 className="text-xs font-semibold text-slate-400 mb-3">
              公式チャレンジ (強度 1〜10)
            </h3>
            <div className="divide-y divide-[#232D3F] border border-[#232D3F] rounded-lg overflow-hidden">
              {officialTargets.map((t) => {
                const captured = capturedFlags.includes(t.flag);
                return (
                  <div
                    key={t.id}
                    className="px-4 py-2.5 bg-[#0E131D] flex items-center justify-between gap-4 hover:bg-[#151C2A] transition-colors"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 text-sm font-medium text-slate-100">
                        <span className="font-mono text-xs text-slate-400 tabular-nums">
                          Lv.{String(t.level).padStart(2, '0')}
                        </span>
                        <span className="truncate">{t.name}</span>
                      </div>
                      <div className="text-xs text-slate-400 mt-0.5 flex items-center gap-2">
                        <span className="tabular-nums">強度 {t.level}/10</span>
                        <span aria-hidden="true">·</span>
                        <span>{t.difficultyLabel}</span>
                        <span aria-hidden="true">·</span>
                        <span className="font-mono">{t.ip}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      {captured ? (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          攻略済み
                        </span>
                      ) : (
                        <span className="text-xs text-slate-500">未攻略</span>
                      )}
                      <button
                        type="button"
                        onClick={() => {
                          onJumpToTarget(t.id);
                          onClose();
                        }}
                        className="px-3 py-1 text-xs font-medium text-slate-200 bg-[#1B2434] hover:bg-[#253147] rounded-md transition-colors whitespace-nowrap"
                      >
                        Webで開く
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {customTargets.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-slate-400 mb-3">カスタムサーバー</h3>
              <div className="divide-y divide-[#232D3F] border border-[#232D3F] rounded-lg overflow-hidden">
                {customTargets.map((t) => {
                  const captured = capturedFlags.includes(t.flag);
                  return (
                    <div key={t.id} className="px-4 py-2.5 bg-[#0E131D] flex items-center justify-between gap-4">
                      <div>
                        <div className="text-sm font-medium text-slate-100">{t.name}</div>
                        <div className="text-xs text-slate-400 flex items-center gap-2">
                          <span className="tabular-nums">強度 {t.level}/10</span>
                          <span aria-hidden="true">·</span>
                          <span className="font-mono">{t.ip}</span>
                        </div>
                      </div>
                      <span className={`text-xs font-medium ${captured ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {captured ? '攻略済み' : '未攻略'}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

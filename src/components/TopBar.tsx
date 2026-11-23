import { Flag } from 'lucide-react';
import { AppTab } from '../types/lab';

interface TopBarProps {
  activeTab: AppTab;
  onSelectTab: (tab: AppTab) => void;
  capturedCount: number;
  totalOfficialCount: number;
  onOpenFlagModal: () => void;
}

export function TopBar({
  activeTab,
  onSelectTab,
  capturedCount,
  totalOfficialCount,
  onOpenFlagModal,
}: TopBarProps) {
  const tabs: Array<{ id: AppTab; label: string }> = [
    { id: 'terminal', label: 'ターミナル' },
    { id: 'web', label: 'Web' },
    { id: 'builder', label: 'サーバー作成' },
  ];

  return (
    <header className="h-14 shrink-0 border-b border-[#232D3F] bg-[#0F1520] px-6 flex items-center justify-between gap-8">
      {/* Zone 1: Single-line Brand Wordmark */}
      <div className="font-display text-lg font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0">
        RootRange
      </div>

      {/* Zone 2: Primary Navigation Tabs */}
      <nav aria-label="メインナビゲーション" className="flex items-center gap-1 p-1 bg-[#0B0F17] border border-[#232D3F] rounded-lg">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => onSelectTab(tab.id)}
              className={`px-4 py-1.5 text-sm font-medium rounded-md transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 ${
                isActive
                  ? 'bg-[#1E293B] text-emerald-400'
                  : 'text-slate-400 hover:text-slate-100'
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </nav>

      {/* Zone 3: Single Primary Action */}
      <div className="flex items-center shrink-0">
        <button
          type="button"
          onClick={onOpenFlagModal}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 rounded-lg transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
        >
          <Flag className="w-3.5 h-3.5" />
          <span className="tabular-nums">
            フラグ提出 ({capturedCount}/{totalOfficialCount})
          </span>
        </button>
      </div>
    </header>
  );
}

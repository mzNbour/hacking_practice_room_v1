import { useEffect, useState } from 'react';
import { FlagModal } from './components/FlagModal';
import { ServerBuilderView } from './components/ServerBuilderView';
import { TerminalView } from './components/TerminalView';
import { TopBar } from './components/TopBar';
import { WebBrowserView } from './components/WebBrowserView';
import { INITIAL_TARGETS } from './data/targets';
import { executeTerminalCommand } from './engine/commandProcessor';
import { createInitialFS, createInitialSystemState } from './engine/vfs';
import {
  AppTab,
  HttpLogEntry,
  ProxyToolMode,
  RemoteSession,
  SystemState,
  TargetServer,
  TerminalLine,
  VirtualFile,
} from './types/lab';

const STORAGE_FLAGS_KEY = 'rootrange_captured_flags_v1';
const STORAGE_CUSTOM_SERVERS_KEY = 'rootrange_custom_servers_v1';

const WELCOME_LINES: TerminalLine[] = [
  {
    id: 'welcome-1',
    kind: 'info',
    text: `Ubuntu 24.04.1 LTS (RootRange Security Lab) — 10-Stage Web CTF Environment
ネットワーク 10.10.0.0/16 上に 強度 1〜10 段階のターゲットが稼働中です。`,
  },
  {
    id: 'welcome-2',
    kind: 'output',
    text: `まずは 'cat targets.txt' でターゲット一覧を確認するか、'nmap -sV 10.10.1.10' でスキャンを開始してください。
全コマンド一覧は 'help' または左側のコマンドリファレンスで確認できます。`,
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<AppTab>('terminal');
  const [system, setSystem] = useState<SystemState>(() => createInitialSystemState());
  const [fs, setFs] = useState<Record<string, VirtualFile>>(() => createInitialFS());

  const [targets, setTargets] = useState<TargetServer[]>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_CUSTOM_SERVERS_KEY);
      if (saved) {
        const custom: TargetServer[] = JSON.parse(saved);
        return [...INITIAL_TARGETS, ...custom];
      }
    } catch {
      // ignore storage errors
    }
    return INITIAL_TARGETS;
  });

  const [capturedFlags, setCapturedFlags] = useState<string[]>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_FLAGS_KEY);
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  const [selectedTargetId, setSelectedTargetId] = useState<string>(INITIAL_TARGETS[0].id);
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>(WELCOME_LINES);
  const [remoteSession, setRemoteSession] = useState<RemoteSession | null>(null);
  const [httpLogs, setHttpLogs] = useState<HttpLogEntry[]>([]);
  const [proxyOpen, setProxyOpen] = useState(false);
  const [proxyTool, setProxyTool] = useState<ProxyToolMode>('burpsuite');
  const [flagModalOpen, setFlagModalOpen] = useState(false);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_FLAGS_KEY, JSON.stringify(capturedFlags));
    } catch {
      // ignore
    }
  }, [capturedFlags]);

  useEffect(() => {
    try {
      const customOnly = targets.filter((t) => t.isCustom);
      localStorage.setItem(STORAGE_CUSTOM_SERVERS_KEY, JSON.stringify(customOnly));
    } catch {
      // ignore
    }
  }, [targets]);

  const mutateTarget = (targetId: string, updater: (prev: TargetServer) => TargetServer) => {
    setTargets((prev) => prev.map((t) => (t.id === targetId ? updater(t) : t)));
  };

  const handleLogHttp = (entry: Omit<HttpLogEntry, 'id' | 'timestamp'>) => {
    const newEntry: HttpLogEntry = {
      ...entry,
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: new Date().toLocaleTimeString('ja-JP', { hour12: false }),
    };
    setHttpLogs((prev) => [newEntry, ...prev].slice(0, 80));
  };

  const handleSubmitFlag = (rawFlag: string): { ok: boolean; message: string } => {
    const clean = rawFlag.trim();
    const matched = targets.find((t) => t.flag === clean);
    if (!matched) {
      return { ok: false, message: `不正なフラグです: "${clean}"` };
    }
    if (capturedFlags.includes(clean)) {
      return { ok: true, message: `すでに取得済みのフラグです (${matched.name})` };
    }
    setCapturedFlags((prev) => [...prev, clean]);
    return {
      ok: true,
      message: `フラグ認証成功！ [${matched.isCustom ? matched.name : `Lv.${matched.level} ${matched.name}`}] を攻略しました！`,
    };
  };

  const handleExecuteCommand = (cmd: string) => {
    const promptText = remoteSession
      ? `${remoteSession.user}@${remoteSession.hostname}:${remoteSession.cwd}${remoteSession.isRoot ? '#' : '$'} `
      : `${system.username}@${system.hostname}:${system.cwd === '/home/operator' ? '~' : system.cwd}$ `;

    const promptLine: TerminalLine = {
      id: `p-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      kind: 'prompt',
      promptText,
      text: cmd,
    };

    if (cmd.trim().toLowerCase() === 'clear') {
      setTerminalLines([]);
      return;
    }

    const out = executeTerminalCommand(cmd, {
      system,
      setSystem,
      fs,
      setFs,
      targets,
      mutateTarget,
      remoteSession,
      setRemoteSession,
      onOpenProxyTool: (tool, url) => {
        setProxyTool(tool);
        setProxyOpen(true);
        if (url) {
          const found = targets.find((t) => url.includes(t.ip) || url.includes(t.hostname));
          if (found) setSelectedTargetId(found.id);
        }
        setActiveTab('web');
      },
      onLogHttp: handleLogHttp,
      onSubmitFlag: handleSubmitFlag,
      onClearTerminal: () => setTerminalLines([]),
    });

    setTerminalLines((prev) => [...prev, promptLine, ...out]);
  };

  const handleResetLab = () => {
    setSystem(createInitialSystemState());
    setFs(createInitialFS());
    setRemoteSession(null);
    setTerminalLines(WELCOME_LINES);
  };

  const handleAddServer = (server: TargetServer) => {
    setTargets((prev) => [...prev, server]);
    setFs((prev) => {
      const hosts = prev['/etc/hosts'];
      if (!hosts) return prev;
      return {
        ...prev,
        '/etc/hosts': {
          ...hosts,
          content: `${hosts.content}\n${server.ip} ${server.hostname}`,
        },
      };
    });
  };

  const handleToggleServerStatus = (targetId: string) => {
    mutateTarget(targetId, (prev) => ({
      ...prev,
      status: prev.status === 'running' ? 'stopped' : 'running',
    }));
  };

  const handleDeleteServer = (targetId: string) => {
    setTargets((prev) => prev.filter((t) => t.id !== targetId));
    if (selectedTargetId === targetId) {
      setSelectedTargetId(INITIAL_TARGETS[0].id);
    }
  };

  const openTargetInWeb = (targetId: string) => {
    setSelectedTargetId(targetId);
    setActiveTab('web');
  };

  const officialTargets = targets.filter((t) => !t.isCustom);
  const officialCapturedCount = officialTargets.filter((t) => capturedFlags.includes(t.flag)).length;

  return (
    <div className="h-screen w-screen flex flex-col overflow-hidden bg-[#0B0F17] text-slate-100">
      <TopBar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        capturedCount={officialCapturedCount}
        totalOfficialCount={officialTargets.length}
        onOpenFlagModal={() => setFlagModalOpen(true)}
      />

      <main className="flex-1 min-h-0 flex flex-col">
        {activeTab === 'terminal' && (
          <TerminalView
            lines={terminalLines}
            system={system}
            remoteSession={remoteSession}
            targets={targets}
            capturedFlags={capturedFlags}
            onExecute={handleExecuteCommand}
            onClear={() => setTerminalLines([])}
            onResetLab={handleResetLab}
            onSelectTargetInWeb={openTargetInWeb}
          />
        )}

        {activeTab === 'web' && (
          <WebBrowserView
            targets={targets}
            selectedTargetId={selectedTargetId}
            onSelectTarget={setSelectedTargetId}
            capturedFlags={capturedFlags}
            httpLogs={httpLogs}
            onLogHttp={handleLogHttp}
            mutateTarget={mutateTarget}
            proxyOpen={proxyOpen}
            onToggleProxy={setProxyOpen}
            proxyTool={proxyTool}
            onSelectProxyTool={setProxyTool}
            onSubmitFlag={handleSubmitFlag}
          />
        )}

        {activeTab === 'builder' && (
          <ServerBuilderView
            targets={targets}
            onAddServer={handleAddServer}
            onToggleServerStatus={handleToggleServerStatus}
            onDeleteServer={handleDeleteServer}
            onOpenInWeb={openTargetInWeb}
          />
        )}
      </main>

      <FlagModal
        isOpen={flagModalOpen}
        onClose={() => setFlagModalOpen(false)}
        targets={targets}
        capturedFlags={capturedFlags}
        onSubmitFlag={handleSubmitFlag}
        onJumpToTarget={openTargetInWeb}
      />
    </div>
  );
}

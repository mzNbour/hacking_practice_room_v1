export type AppTab = 'terminal' | 'web' | 'builder';

export type VulnerabilityType =
  | 'html_leak'
  | 'weak_auth'
  | 'sqli'
  | 'lfi_wp'
  | 'cmdi'
  | 'header_cookie_tamper'
  | 'stored_xss'
  | 'file_upload_rce'
  | 'ssrf_jwt'
  | 'waf_chain_ssh';

export interface TargetPort {
  port: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'filtered' | 'closed';
  service: string;
  version: string;
}

export interface TargetCredentials {
  username: string;
  password: string;
  role?: string;
}

export interface TargetFile {
  path: string;
  content: string;
  owner: string;
  permissions: string;
}

export interface TargetServer {
  id: string;
  level: number; // 1-10 for official levels, or custom difficulty 1-10
  isCustom: boolean;
  name: string;
  hostname: string;
  ip: string;
  os: string;
  webServer: string;
  cms?: 'WordPress' | 'Joomla' | 'Custom' | 'Node.js' | 'GraphQL';
  techStack: string[];
  difficultyLabel: string;
  briefing: string;
  hints: string[];
  flag: string;
  status: 'running' | 'stopped';
  ufwEnabled: boolean;
  wafEnabled: boolean;
  ports: TargetPort[];
  vulnerabilities: VulnerabilityType[];
  credentials: TargetCredentials[];
  themeAccent: string;
  siteTitle: string;
  siteSubtitle: string;
  uploadedShells: Record<string, { password: string; filename: string }>;
  xssPayloads: string[];
  exfilLogs: string[];
  remoteFiles: TargetFile[];
  sshUser?: {
    username: string;
    password: string;
    sudoRule?: string;
  };
}

export interface HttpRequest {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD';
  url: string;
  headers: Record<string, string>;
  cookies: Record<string, string>;
  body?: string;
}

export interface HttpResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  setCookies?: Record<string, string>;
  body: string;
  contentType: 'text/html' | 'application/json' | 'text/plain';
  uiState?: {
    pageTitle: string;
    loggedInUser?: string;
    role?: string;
    alert?: { type: 'success' | 'error' | 'info'; message: string };
    dataRows?: Array<Record<string, string>>;
    cmdOutput?: string;
    capturedFlag?: string;
  };
}

export interface HttpLogEntry {
  id: string;
  timestamp: string;
  targetId: string;
  request: HttpRequest;
  response: HttpResponse;
  toolSource: 'browser' | 'terminal' | 'repeater' | 'scanner';
}

export type ProxyToolMode = 'burpsuite' | 'zap' | 'caido';

export interface VirtualFile {
  type: 'file' | 'dir';
  content?: string;
  permissions: string;
  owner: string;
  size: number;
  modified: string;
}

export interface SystemUnit {
  name: string;
  load: 'loaded' | 'masked';
  active: 'active' | 'inactive' | 'failed';
  sub: 'running' | 'dead' | 'exited' | 'listening';
  description: string;
  logs: string[];
}

export interface UfwRule {
  id: number;
  to: string;
  action: 'ALLOW IN' | 'DENY IN' | 'LIMIT IN' | 'ALLOW OUT';
  from: string;
}

export interface AptPackage {
  name: string;
  version: string;
  arch: string;
  description: string;
}

export interface SnapPackage {
  name: string;
  version: string;
  rev: string;
  tracking: string;
  publisher: string;
  notes: string;
}

export interface SystemState {
  hostname: string;
  username: string;
  cwd: string;
  timezone: string;
  locale: string;
  ubuntuVersion: string;
  kernelVersion: string;
  ipAddress: string;
  gateway: string;
  dnsServers: string[];
  ufwActive: boolean;
  ufwRules: UfwRule[];
  units: SystemUnit[];
  aptPackages: AptPackage[];
  snapPackages: SnapPackage[];
  netplanConfig: string;
  proAttached: boolean;
  env: Record<string, string>;
  commandHistory: string[];
}

export interface RemoteSession {
  type: 'ssh' | 'weevely';
  targetId: string;
  hostname: string;
  ip: string;
  user: string;
  cwd: string;
  isRoot: boolean;
}

export interface TerminalLine {
  id: string;
  kind: 'prompt' | 'output' | 'error' | 'success' | 'info' | 'warning';
  promptText?: string;
  text: string;
}

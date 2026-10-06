/**
 * The shape of hive/policy/guardrail.json and of what the Rules screen gets back,
 * shared by main, the preload bridge and the renderer. Logic lives in
 * src/main/guardrail.ts and src/main/guardrailEditor.ts.
 */

export type BackstopDoes = 'block' | 'ask' | 'log';

/** What a backstop fires on. Every present key must match (AND). */
export interface BackstopMatch {
  tool?: string | string[];
  path_glob?: string;
  path_not_glob?: string;
  command_matches?: string;
  command_not_matches?: string;
  path_in_other_agent_workspace?: boolean;
}

export interface Backstop {
  on: boolean;
  /** block = deny the call; ask = the operator answers (or approves on a card);
   *  log = record what it would have done and let the call run. */
  does: BackstopDoes;
  /** Action classes the operator may approve one at a time on a card. `ask` only. */
  approve_on_card?: string[];
  match: BackstopMatch;
  /** What the agent is told when the backstop stops it. Defaults to the principle. */
  message?: string;
  /** If the backstop cannot be evaluated: let the call run (allow) or stop it (deny). */
  on_error?: 'allow' | 'deny';
}

export interface GuardrailRule {
  id: string;
  /** The sentence the agents are given. */
  principle: string;
  /** 'all', or the agent ids the principle (and its backstop) apply to. */
  agents: 'all' | string[];
  why?: string;
  /** Notes carried over from the old engine.json (`_…_why` fields). Not shown to agents. */
  notes?: Record<string, string>;
  backstop?: Backstop;
}

export interface GuardrailFile {
  version: 1;
  /** Bumped on every save, so agents' rendered instructions know they are stale. */
  rev: number;
  defaults?: { on_error?: 'allow' | 'deny' };
  report_check?: { mode?: 'dry_run' | 'live' };
  rules: GuardrailRule[];
}

/** The engine's load status, as the screen shows it. */
export interface GuardrailStatus {
  configured: boolean;
  file: string | null;
  rulesLoaded: number;
  ruleIds: string[];
  error: string | null;
  loadedAt: string | null;
}

export interface CapEntry { count: number; tokens: number; max: number; maxTokens: number; over: boolean }
export interface CapReport { global: CapEntry; perAgent: Record<string, CapEntry>; over: string[] }

export interface GuardrailView {
  exists: boolean;
  file: GuardrailFile | null;
  /** The file's modification time when read; a save sends it back. */
  stamp: number | null;
  /** Why the file cannot be used, when it exists but is broken. */
  error: string | null;
  status: GuardrailStatus | null;
  caps: CapReport | null;
}

export type GuardrailSaveResult =
  | { ok: true; rev: number; stamp: number | null; status: GuardrailStatus | null; warning?: string }
  | { ok: false; reason: 'invalid' | 'changed-on-disk' | 'broken-file' | 'no-hive' | 'write-failed'; errors: string[] };

export interface GuardrailTestResult { fires: boolean; does?: string; on?: string; error?: string }

/**
 * The Rules screen's path to guardrail.json (finish plan item 2).
 *
 * Main only: the renderer sends a whole file, main decides. A save is refused when the
 * file changed on disk since the screen read it (no silent overwrite), when the shape
 * or the engine's own check fails, or when the principles are over the cap. Otherwise
 * it backs the file up, writes it atomically, reloads the engine and re-renders the
 * agents' instructions, so a change takes effect with no restart. Agents cannot reach
 * this (no IPC from a terminal; the policy folder is self-protected).
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  GUARDRAIL_FILE, atomicWriteJson, backupGuardrail, guardrailVersionStamp, readGuardrail, toEngineRules,
  toPrinciples, validateGuardrail, type GuardrailFile, type GuardrailRule,
} from './guardrail';
import type { PolicyPayload, PolicyRule, PolicyStatus } from './policy';
import type { RulesManager } from './rules';
import { STARTER_RULES } from './guardrailStarter';
import type { GuardrailSaveResult, GuardrailTestResult, GuardrailView } from '../shared/guardrail';

export interface GuardrailEditorDeps {
  policyDir: () => string | null;
  /** The live engine (HookServer): its check, its tester, and a reload. */
  engine: {
    reloadPolicy(): PolicyStatus | null;
    policyStatus(): PolicyStatus | null;
    checkEngineRules(rules: PolicyRule[]): string[];
    wouldMatch(rule: PolicyRule, p: PolicyPayload): { fires: boolean; on?: string; error?: string };
  };
  principles: Pick<RulesManager, 'capReportFor'>;
  agentIds: () => string[];
  /** Re-render every agent's instructions after a save. */
  afterSave: () => Promise<void>;
  log: (row: Record<string, unknown>) => void;
}

type CapReport = ReturnType<RulesManager['capReportFor']>;

export class GuardrailEditor {
  constructor(private d: GuardrailEditorDeps) {}

  private path(): string | null {
    const dir = this.d.policyDir();
    return dir ? join(dir, GUARDRAIL_FILE) : null;
  }

  read(): GuardrailView {
    const p = this.path();
    const status = this.d.engine.policyStatus();
    if (!p || !existsSync(p)) return { exists: false, file: null, stamp: null, error: null, status, caps: null };
    const stamp = guardrailVersionStamp(p);
    const r = readGuardrail(p);
    if (!r.ok) return { exists: true, file: null, stamp, error: r.error, status, caps: null };
    return { exists: true, file: r.file, stamp, error: null, status, caps: this.caps(r.file) };
  }

  private caps(file: GuardrailFile): CapReport {
    return this.d.principles.capReportFor(toPrinciples(file), this.d.agentIds());
  }

  /** `capCheck: false` (the install only): the cap becomes a warning, not a refusal. */
  async save(next: GuardrailFile, expectedStamp: number | null, actor: string, opts: { capCheck?: boolean } = {}): Promise<GuardrailSaveResult> {
    const p = this.path();
    if (!p) return { ok: false, reason: 'no-hive', errors: ['no hive is open'] };
    const nowStamp = existsSync(p) ? guardrailVersionStamp(p) : null;
    if (nowStamp !== expectedStamp) {
      return { ok: false, reason: 'changed-on-disk', errors: ['the rules file changed since this screen loaded it; reload and make the change again'] };
    }
    const current = existsSync(p) ? readGuardrail(p) : null;
    if (current && !current.ok) {
      // Dwight M1: never replace a file this screen could not read; it holds rules
      // (and settings) the screen never saw. Repair it or restore a backup.
      return { ok: false, reason: 'broken-file', errors: [`the rules file is broken (${current.error}); fix it or restore a backup before saving`] };
    }
    const rev = (current?.ok ? current.file.rev : 0) + 1;
    const file: GuardrailFile = { ...next, version: 1, rev };
    const errors = validateGuardrail(file);
    let capWarning: string | null = null;
    // The engine's own check (regexes, matcher values) on every rule whose shape is
    // fine, so one save shows every problem rather than one layer at a time.
    const shapeBad = new Set(errors.map((e) => e.split(': ')[0]));
    if (Array.isArray(file.rules)) {
      try {
        // Off backstops too, so switching one on later cannot break the file.
        const okRules = file.rules.filter((r) => r && !shapeBad.has(r.id))
          .map((r) => (r.backstop ? { ...r, backstop: { ...r.backstop, on: true } } : r));
        errors.push(...this.d.engine.checkEngineRules(toEngineRules({ ...file, rules: okRules })));
      } catch (e) { errors.push(`the rules could not be checked: ${e instanceof Error ? e.message : String(e)}`); }
    }
    if (!errors.length) {
      const cap = this.caps(file);
      // Dwight M2: refuse only a save that makes the cap worse, so a hive that is
      // already over (e.g. after migration) can still delete, edit and switch.
      const before = current?.ok ? this.caps(current.file) : null;
      const worse = (now: { count: number; tokens: number; over: boolean }, was?: { count: number; tokens: number }) =>
        now.over && (!was || now.count > was.count || now.tokens > was.tokens);
      cap.over = cap.over.filter((k) => (k === 'global'
        ? worse(cap.global, before?.global)
        : worse(cap.perAgent[k], before?.perAgent[k])));
      if (cap.over.length) {
        const msg = cap.over.includes('global')
          ? `over the cap: ${cap.global.count} principles for all agents (max ${cap.global.max}, about ${cap.global.maxTokens} tokens)`
          : `over the cap for ${cap.over.join(', ')} (max ${Object.values(cap.perAgent)[0]?.max ?? ''} principles each)`;
        if (opts.capCheck === false) capWarning = `${msg}; consider removing or shortening a principle`;
        else errors.push(msg);
      }
    }
    if (errors.length) return { ok: false, reason: 'invalid', errors };
    try {
      backupGuardrail(p);
      atomicWriteJson(p, file);
    } catch (e) {
      return { ok: false, reason: 'write-failed', errors: [e instanceof Error ? e.message : String(e)] };
    }
    const status = this.d.engine.reloadPolicy();
    this.d.log({
      kind: 'guardrail-saved', rev, actor, rules: file.rules.length,
      backstops_on: file.rules.filter((r) => r.backstop?.on).length,
      report_check_changed: JSON.stringify(current?.ok ? current.file.report_check ?? null : null) !== JSON.stringify(file.report_check ?? null),
      defaults_changed: JSON.stringify(current?.ok ? current.file.defaults ?? null : null) !== JSON.stringify(file.defaults ?? null),
      rules_loaded: status?.rulesLoaded ?? null, error: status?.error ?? null,
    });
    try { await this.d.afterSave(); } catch { /* the agents catch up at the next reconcile */ }
    return { ok: true, rev, stamp: guardrailVersionStamp(p), status, ...(capWarning ? { warning: capWarning } : {}) };
  }

  /**
   * "Turn on guardrail" (finish plan item 9): add the starter rules that are missing,
   * by id, blocks before the existing rules and asks after them (the first matching
   * backstop wins). A rule already there is left as the operator set it. Nothing
   * missing: nothing written. A broken file is never overwritten.
   */
  async install(actor: string): Promise<(GuardrailSaveResult & { added: string[] }) | { ok: false; reason: 'invalid'; errors: string[]; added: string[] }> {
    const cur = this.read();
    if (cur.exists && !cur.file) {
      return { ok: false, reason: 'invalid', added: [], errors: [`the rules file is broken (${cur.error}); fix it or restore a backup first`] };
    }
    const have = new Set((cur.file?.rules ?? []).map((r) => r.id));
    const missing = STARTER_RULES.filter((r) => !have.has(r.id)).map((r) => JSON.parse(JSON.stringify(r)) as GuardrailRule);
    if (!missing.length) {
      return { ok: true, added: [], rev: cur.file?.rev ?? 0, stamp: cur.stamp, status: cur.status };
    }
    const blocks = missing.filter((r) => r.backstop?.does === 'block');
    const rest = missing.filter((r) => r.backstop?.does !== 'block');
    const base: GuardrailFile = cur.file ?? { version: 1, rev: 0, rules: [] };
    // First match wins. Order: new blocks, existing blocks, new asks, existing
    // non-blocks, each in its own order. An existing Ask or Log rule cannot shadow a
    // new ask (Dwight L11) and no existing block ends up behind it (M6); moving a block
    // ahead of a non-block only makes a call stricter.
    const isBlock = (r: GuardrailRule) => r.backstop?.does === 'block';
    const rules = [...blocks, ...base.rules.filter(isBlock), ...rest, ...base.rules.filter((r) => !isBlock(r))];
    // The starter rules are safety, not prose: the principles cap warns, never refuses
    // them (Dwight M2b).
    const out = await this.save({ ...base, rules }, cur.stamp, actor, { capCheck: false });
    return { ...out, added: out.ok ? missing.map((r) => r.id) : [] };
  }

  /** Would this rule's backstop stop `command` (a Bash call) for `agentId`? */
  test(rule: GuardrailRule, command: string, agentId = 'agent'): GuardrailTestResult {
    if (!rule?.backstop) return { fires: false, error: 'this rule has no backstop' };
    const [engineRule] = toEngineRules({ version: 1, rev: 0, rules: [{ ...rule, backstop: { ...rule.backstop, on: true } }] });
    const r = this.d.engine.wouldMatch(engineRule, {
      hook_event_name: 'PreToolUse', agent_id: agentId, tool_name: 'Bash', tool_input: { command }, cwd: undefined,
    });
    if (r.error) return { fires: false, error: r.error };
    return r.fires ? { fires: true, does: rule.backstop.does, on: r.on } : { fires: false };
  }
}

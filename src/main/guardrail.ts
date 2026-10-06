/**
 * guardrail.json — the one rules file (finish plan item 1, spec v3).
 *
 * A rule is a guiding principle: a sentence every targeted agent is given. It may
 * have a BACKSTOP: the check the hook runs on every tool call, so an agent that loses
 * track of the principle is still caught. The engine reads the backstops
 * (`toEngineRules`), the agents' instructions are built from the principles
 * (`toPrinciples`). There is no second file and no link between files to drift.
 *
 * The day job's engine.json (backstops) and rules.json (principles) are migrated into
 * it once (`migrateLegacyPolicy`) and renamed `*.migrated-<date>`; no older build has
 * to keep working (Gary, 2026-10-06), so nothing here reads the old files afterwards.
 */
import { existsSync, readFileSync, readdirSync, renameSync, writeFileSync, openSync, fsyncSync, closeSync, copyFileSync, unlinkSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { GRANT_CLASSES } from './grants';
import type { PolicyRule, PolicyMode } from './policy';

export const GUARDRAIL_FILE = 'guardrail.json';
export const LEGACY_ENGINE_FILE = 'engine.json';
export const LEGACY_PROSE_FILE = 'rules.json';
/** Timestamped backups kept beside the file; older ones are deleted on each save. */
export const GUARDRAIL_BACKUPS_KEPT = 20;

/** The keys a backstop may match on. Every present key must match (AND). */
export const MATCHERS = [
  'tool',
  'path_glob',
  'path_not_glob',
  'command_matches',
  'command_not_matches',
  'path_in_other_agent_workspace',
] as const;

export type { BackstopDoes, Backstop, GuardrailRule, GuardrailFile } from '../shared/guardrail';
import type { Backstop, BackstopDoes, GuardrailRule, GuardrailFile } from '../shared/guardrail';

const DOES: readonly BackstopDoes[] = ['block', 'ask', 'log'];

/** Every problem with the file's shape, as "<rule id>: <what>". Empty when valid.
 *  The engine's own checks (regexes, matcher values) still run when it loads. */
export function validateGuardrail(g: unknown): string[] {
  if (!g || typeof g !== 'object' || Array.isArray(g)) return ['the file must be a JSON object with a "rules" array'];
  const f = g as Partial<GuardrailFile>;
  const out: string[] = [];
  if (f.version !== 1) out.push(`version must be 1, got ${JSON.stringify(f.version)}`);
  if (typeof f.rev !== 'number' || !Number.isInteger(f.rev) || f.rev < 0) out.push('rev must be a whole number');
  if (f.defaults !== undefined) {
    const oe = (f.defaults as { on_error?: unknown })?.on_error;
    if (oe !== undefined && oe !== 'allow' && oe !== 'deny') out.push('defaults.on_error must be allow or deny');
  }
  if (!Array.isArray(f.rules)) return [...out, '"rules" must be an array'];
  const seen = new Set<string>();
  for (const r of f.rules as unknown[]) {
    const rule = (r ?? {}) as Partial<GuardrailRule>;
    const id = typeof rule.id === 'string' && rule.id.trim() ? rule.id : '(no id)';
    const bad = (what: string) => out.push(`${id}: ${what}`);
    if (id === '(no id)') bad('id must be a non-empty string');
    else if (seen.has(id)) bad('duplicate id');
    seen.add(id);
    if (typeof rule.principle !== 'string' || !rule.principle.trim()) bad('principle must be a non-empty sentence');
    const a = rule.agents;
    if (a !== 'all' && !(Array.isArray(a) && a.every((x) => typeof x === 'string' && x))) bad('agents must be "all" or a list of agent ids');
    if (rule.backstop === undefined) continue;
    const b = rule.backstop as Partial<Backstop>;
    if (!b || typeof b !== 'object') { bad('backstop must be an object'); continue; }
    if (typeof b.on !== 'boolean') bad('backstop.on must be true or false');
    if (!DOES.includes(b.does as BackstopDoes)) bad(`backstop.does must be block, ask or log, got ${JSON.stringify(b.does)}`);
    if (b.approve_on_card !== undefined) {
      if (b.does !== 'ask') bad('approve_on_card is only for a backstop that does ask');
      else if (!Array.isArray(b.approve_on_card) || !b.approve_on_card.length) bad('approve_on_card must be a non-empty list, e.g. ["git-push"]');
      else {
        const u = b.approve_on_card.find((c) => !(GRANT_CLASSES as readonly string[]).includes(c));
        if (u !== undefined) bad(`approve_on_card: unknown action ${JSON.stringify(u)} (known: ${GRANT_CLASSES.join(', ')})`);
      }
    }
    if (b.on_error !== undefined && b.on_error !== 'allow' && b.on_error !== 'deny') bad('backstop.on_error must be allow or deny');
    if (b.message !== undefined && typeof b.message !== 'string') bad('backstop.message must be text');
    if (!b.match || typeof b.match !== 'object' || Array.isArray(b.match)) { bad('backstop.match must be an object'); continue; }
    const keys = Object.keys(b.match);
    if (!keys.length) bad('backstop.match is empty: it would fire on every tool call');
    const unknown = keys.find((k) => !(MATCHERS as readonly string[]).includes(k));
    if (unknown) bad(`unknown matcher "${unknown}" (known: ${MATCHERS.join(', ')})`);
  }
  return out;
}

/** The backstops that are on, as the engine's rules, in file order. */
export function toEngineRules(g: GuardrailFile): PolicyRule[] {
  const out: PolicyRule[] = [];
  for (const r of g.rules) {
    const b = r.backstop;
    if (!b || !b.on) continue;
    out.push({
      id: r.id,
      decision: b.does === 'ask' ? 'ask' : 'deny',
      mode: b.does === 'log' ? 'dry_run' : 'live',
      reason: b.message?.trim() ? b.message : r.principle,
      match: b.match,
      ...(b.on_error ? { on_error: b.on_error } : {}),
      ...(b.does === 'ask' && b.approve_on_card?.length ? { grantable: [...b.approve_on_card] } : {}),
      ...(r.agents !== 'all' ? { agents: [...r.agents] } : {}),
    });
  }
  return out;
}

/** The principles in the shape the agents' rules renderer reads. */
export function toPrinciples(g: GuardrailFile): Array<{ id: string; text: string; scope: { kind: 'global' } | { kind: 'agents'; ids: string[] }; why?: string }> {
  return g.rules.map((r) => ({
    id: r.id,
    text: r.principle,
    scope: r.agents === 'all' ? { kind: 'global' as const } : { kind: 'agents' as const, ids: [...r.agents] },
    ...(r.why ? { why: r.why } : {}),
  }));
}

/** Read guardrail.json: the file, or why it cannot be used. Never throws. */
export function readGuardrail(path: string): { ok: true; file: GuardrailFile } | { ok: false; error: string } {
  let parsed: unknown;
  try { parsed = JSON.parse(readFileSync(path, 'utf8')); } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
  const problems = validateGuardrail(parsed);
  return problems.length ? { ok: false, error: problems.join('; ') } : { ok: true, file: parsed as GuardrailFile };
}

/** temp sibling, fsync, rename: a reader sees the old file or the new one, never half. */
export function atomicWriteJson(path: string, value: unknown): void {
  const tmp = `${path}.tmp-${Math.random().toString(36).slice(2, 10)}`;
  writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', 'utf8');
  try {
    const fd = openSync(tmp, 'r+');
    try { fsyncSync(fd); } finally { closeSync(fd); }
  } catch { /* fsync best effort */ }
  renameSync(tmp, path);
}

const stamp = (d = new Date()) => d.toISOString().replace(/[:.]/g, '-');

/** Copy the current file to `<file>.bak-<time>` and keep only the newest backups. */
export function backupGuardrail(path: string, keep = GUARDRAIL_BACKUPS_KEPT): string | null {
  if (!existsSync(path)) return null;
  const bak = `${path}.bak-${stamp()}`;
  copyFileSync(path, bak);
  const dir = join(path, '..');
  const base = path.split(/[\\/]/).pop()!;
  const baks = readdirSync(dir).filter((f) => f.startsWith(`${base}.bak-`)).sort();
  for (const old of baks.slice(0, Math.max(0, baks.length - keep))) {
    try { unlinkSync(join(dir, old)); } catch { /* best effort */ }
  }
  return bak;
}

/** The file's modification time, for "it changed on disk since you loaded it". */
export function guardrailVersionStamp(path: string): number | null {
  try { return statSync(path).mtimeMs; } catch { return null; }
}

type LegacyEngine = { defaults?: { mode?: PolicyMode; on_error?: 'allow' | 'deny' }; report_check?: { mode?: PolicyMode }; rules?: Array<Partial<PolicyRule>> };
type LegacyProse = { rev?: number; rules?: Array<{ id?: string; text?: string; scope?: unknown; why?: string; status?: string }> };

const readJson = <T>(p: string): T | null => { try { return JSON.parse(readFileSync(p, 'utf8')) as T; } catch { return null; } };

/**
 * One-time move of engine.json (backstops) and rules.json (principles) into
 * guardrail.json. Runs only when guardrail.json does not exist and at least one old
 * file does. Returns true when it wrote guardrail.json.
 *
 * An old file that does not parse is NOT migrated and NOT renamed: the caller then
 * finds no guardrail.json and reports the old file's error, so a broken policy is
 * never silently replaced by an empty one.
 */
export function migrateLegacyPolicy(
  policyDir: string,
  log: (row: Record<string, unknown>) => void,
  /** The engine's own rule check: a legacy rule it would have refused is not migrated. */
  validateEngineRule: (r: unknown) => string | null = () => null,
): { migrated: boolean; error?: string } {
  const target = join(policyDir, GUARDRAIL_FILE);
  if (existsSync(target)) return { migrated: false };
  const enginePath = join(policyDir, LEGACY_ENGINE_FILE);
  const prosePath = join(policyDir, LEGACY_PROSE_FILE);
  const hasEngine = existsSync(enginePath);
  const hasProse = existsSync(prosePath);
  if (!hasEngine && !hasProse) return { migrated: false };
  const refuse = (error: string) => {
    log({ kind: 'guardrail-migration-failed', error });
    return { migrated: false, error };
  };
  let eng: LegacyEngine | null = {};
  if (hasEngine) {
    try { eng = JSON.parse(readFileSync(enginePath, 'utf8')) as LegacyEngine; } catch (e) {
      return refuse(`${LEGACY_ENGINE_FILE} does not parse, so nothing was moved: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (!eng || typeof eng !== 'object' || Array.isArray(eng) || (eng.rules !== undefined && !Array.isArray(eng.rules))) {
      return refuse(`${LEGACY_ENGINE_FILE} must be a JSON object with a "rules" array, so nothing was moved`);
    }
    const why = (eng.rules ?? []).map((r) => {
      const w = validateEngineRule(r);
      return w ? `${(r as { id?: string })?.id ?? '(no id)'}: ${w}` : null;
    }).filter(Boolean);
    if (why.length) return refuse(`${LEGACY_ENGINE_FILE} has rules the engine refuses, so nothing was moved: ${why.join('; ')}`);
    // An engine.json with no rules is a truncated write or a bad edit, as it always was.
    if (!(eng.rules ?? []).length) return refuse(`${LEGACY_ENGINE_FILE} has no rules, so nothing was moved: nothing is enforced`);
  }
  const prose = hasProse ? readJson<LegacyProse>(prosePath) : {};
  if (!prose) return refuse(`${LEGACY_PROSE_FILE} does not parse, so nothing was moved`);
  eng = eng ?? {};
  // Dwight L4: nothing is dropped silently. What cannot be carried stops the move,
  // with the reason, and both old files stay as they are.
  const problems: string[] = [];
  const seenEngine = new Set<string>();
  for (const r of eng.rules ?? []) {
    if (r && typeof r.id === 'string') {
      if (seenEngine.has(r.id)) problems.push(`${r.id}: duplicate id in ${LEGACY_ENGINE_FILE}`);
      seenEngine.add(r.id);
    }
  }
  const seenProse = new Set<string>();
  for (const p of prose?.rules ?? []) {
    if (!p || typeof p.id !== 'string' || p.status === 'retired') continue;
    if (seenProse.has(p.id)) problems.push(`${p.id}: duplicate id in ${LEGACY_PROSE_FILE}`);
    seenProse.add(p.id);
    const s = p.scope as { kind?: string; ids?: unknown } | string | undefined;
    const carried = s === undefined || s === null || s === 'all' || s === 'global'
      || (typeof s === 'object' && (s.kind === 'global' || (s.kind === 'agents' && Array.isArray(s.ids))));
    if (!carried) problems.push(`${p.id}: scope ${JSON.stringify(s)} cannot be carried (use all agents or a list of agents)`);
  }
  if (problems.length) return refuse(`nothing was moved: ${problems.join('; ')}`);
  const defaultMode: PolicyMode = eng.defaults?.mode ?? 'dry_run';
  const rules: GuardrailRule[] = [];
  const ids = new Set<string>();
  for (const r of eng.rules ?? []) {
    if (!r || typeof r.id !== 'string') continue;
    const notes = Object.fromEntries(Object.entries(r).filter(([k, v]) => k.startsWith('_') && typeof v === 'string')) as Record<string, string>;
    const mode = r.mode ?? defaultMode;
    const does: BackstopDoes = mode === 'dry_run' ? 'log' : r.decision === 'ask' ? 'ask' : 'block';
    const reason = typeof r.reason === 'string' ? r.reason : '';
    rules.push({
      id: r.id,
      principle: reason || r.id,
      agents: 'all',
      ...(typeof r.description === 'string' && r.description ? { why: r.description } : {}),
      ...(Object.keys(notes).length ? { notes } : {}),
      backstop: {
        on: true, does,
        ...(does === 'ask' && Array.isArray(r.grantable) && r.grantable.length ? { approve_on_card: [...r.grantable] } : {}),
        match: r.match as PolicyRule['match'],
        message: reason,
        ...(r.on_error ? { on_error: r.on_error } : {}),
      },
    });
    ids.add(r.id);
  }
  let skippedRetired = 0;
  for (const p of prose.rules ?? []) {
    if (!p || typeof p.id !== 'string' || typeof p.text !== 'string') continue;
    if (p.status === 'retired') { skippedRetired++; continue; }
    const s = p.scope as { kind?: string; ids?: unknown } | string | undefined;
    const agents: 'all' | string[] =
      s === undefined || s === null || s === 'all' || s === 'global' || (typeof s === 'object' && s.kind === 'global') ? 'all'
        : (((s as { ids?: unknown[] }).ids ?? []) as unknown[]).filter((x): x is string => typeof x === 'string');
    let id = p.id;
    if (ids.has(id)) id = `${id}-principle`;
    ids.add(id);
    rules.push({ id, principle: p.text, agents, ...(p.why ? { why: p.why } : {}) });
  }
  const file: GuardrailFile = {
    version: 1,
    rev: (typeof prose.rev === 'number' ? prose.rev : 0) + 1,
    ...(eng.defaults?.on_error ? { defaults: { on_error: eng.defaults.on_error } } : {}),
    ...(eng.report_check !== undefined ? { report_check: eng.report_check } : {}),
    rules,
  };
  atomicWriteJson(target, file);
  const when = stamp();
  if (hasEngine) renameSync(enginePath, `${enginePath}.migrated-${when}`);
  if (hasProse) renameSync(prosePath, `${prosePath}.migrated-${when}`);
  log({
    kind: 'guardrail-migrated', path: target,
    backstops: rules.filter((r) => r.backstop).length,
    principles_only: rules.filter((r) => !r.backstop).length,
    skipped_retired: skippedRetired,
    from: [hasEngine && LEGACY_ENGINE_FILE, hasProse && LEGACY_PROSE_FILE].filter(Boolean),
  });
  return { migrated: true };
}

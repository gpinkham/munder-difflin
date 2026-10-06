/**
 * The Rules screen's pure parts (finish plan item 2): the status line, the one-line
 * summary of a backstop, and the edit form's draft <-> rule conversion. Kept out of
 * RulesPanel.tsx so they are tested without a renderer.
 */
import type { Backstop, BackstopDoes, GuardrailRule, GuardrailView } from '../../../shared/guardrail';

const slug = (s: string): string =>
  s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);

export const DOES: Array<{ v: BackstopDoes; label: string }> = [
  { v: 'block', label: 'Block' },
  { v: 'ask', label: 'Ask me' },
  { v: 'log', label: 'Log only' },
];

/** One line a person can read: what this rule's backstop does, or that it has none. */
export function describeBackstop(r: GuardrailRule): string {
  const b = r.backstop;
  if (!b) return 'Principle only, not enforced';
  const what = b.does === 'block' ? 'Block' : b.does === 'ask' ? 'Ask me' : 'Log only';
  const card = b.does === 'ask' && b.approve_on_card?.length ? ' · approve on a card' : '';
  const m = b.match;
  const on = m.command_matches ? `command ${m.command_matches}` : m.path_glob ? `path ${m.path_glob}`
    : m.path_in_other_agent_workspace ? "another agent's workspace" : `tool ${[m.tool].flat().join(', ')}`;
  return `Backstop: ${what}${card} · matches ${on}${b.on ? '' : ' · OFF'}`;
}

/** Draft state of the edit form, kept flat so every field is a plain input. */
export interface Draft {
  id: string; isNew: boolean; principle: string; why: string;
  allAgents: boolean; picked: string[];
  hasBackstop: boolean; on: boolean; does: BackstopDoes; approveOnCard: boolean;
  tool: string; commandMatches: string; pathGlob: string; otherWorkspace: boolean; message: string;
}

export const emptyDraft = (): Draft => ({
  id: '', isNew: true, principle: '', why: '', allAgents: true, picked: [],
  hasBackstop: false, on: true, does: 'ask', approveOnCard: false,
  tool: 'Bash', commandMatches: '', pathGlob: '', otherWorkspace: false, message: '',
});

export function toDraft(r: GuardrailRule): Draft {
  const b = r.backstop;
  return {
    id: r.id, isNew: false, principle: r.principle, why: r.why ?? '',
    allAgents: r.agents === 'all', picked: r.agents === 'all' ? [] : [...r.agents],
    hasBackstop: !!b, on: b?.on ?? true, does: b?.does ?? 'ask', approveOnCard: !!b?.approve_on_card?.length,
    tool: b ? [b.match.tool ?? ''].flat().join(',') : 'Bash',
    commandMatches: b?.match.command_matches ?? '', pathGlob: b?.match.path_glob ?? '',
    otherWorkspace: !!b?.match.path_in_other_agent_workspace, message: b?.message ?? '',
  };
}

/** The draft as a rule. `prev` keeps fields the form does not show (on_error, other matchers). */
export function fromDraft(d: Draft, prev?: GuardrailRule): GuardrailRule {
  const out: GuardrailRule = {
    id: d.id || slug(d.principle) || 'rule',
    principle: d.principle.trim(),
    agents: d.allAgents ? 'all' : [...d.picked],
    ...(d.why.trim() ? { why: d.why.trim() } : {}),
  };
  if (!d.hasBackstop) return out;
  const tools = d.tool.split(',').map((t) => t.trim()).filter(Boolean);
  const match: Backstop['match'] = { ...(prev?.backstop?.match ?? {}) };
  for (const k of ['tool', 'command_matches', 'path_glob', 'path_in_other_agent_workspace'] as const) delete match[k];
  if (tools.length) match.tool = tools.length === 1 ? tools[0] : tools;
  if (d.commandMatches.trim()) match.command_matches = d.commandMatches.trim();
  if (d.pathGlob.trim()) match.path_glob = d.pathGlob.trim();
  if (d.otherWorkspace) match.path_in_other_agent_workspace = true;
  out.backstop = {
    on: d.on, does: d.does, match,
    ...(d.does === 'ask' && d.approveOnCard ? { approve_on_card: ['git-push'] } : {}),
    ...(d.message.trim() ? { message: d.message.trim() } : {}),
    ...(prev?.backstop?.on_error ? { on_error: prev.backstop.on_error } : {}),
  };
  return out;
}

/** The status line: what is enforced now, or, in red, why nothing is. */
export function statusLine(v: GuardrailView | null): { text: string; bad: boolean } {
  if (!v) return { text: 'Loading rules…', bad: false };
  if (v.error) return { text: `The rules file is broken, so nothing is enforced: ${v.error}`, bad: true };
  const st = v.status;
  if (st?.error) return { text: `The rules did not load, so nothing is enforced: ${st.error}`, bad: true };
  if (!v.exists) return { text: 'Guardrail is not set up: no rules yet. Add a rule to start.', bad: false };
  const n = st?.rulesLoaded ?? 0;
  const at = st?.loadedAt ? ` (loaded ${new Date(st.loadedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })})` : '';
  return {
    text: n ? `Guardrail active: ${n} rule${n === 1 ? '' : 's'} enforced${at}` : `Guardrail on, but no backstop is on: nothing is enforced${at}`,
    bad: false,
  };
}


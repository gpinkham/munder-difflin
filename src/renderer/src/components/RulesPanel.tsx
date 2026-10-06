/**
 * RulesPanel: the one place rules live and change (finish plan item 2, spec v3).
 *
 * A rule is a guiding principle (the sentence every targeted agent is given) and may
 * have a BACKSTOP (what the hook enforces on every tool call). Both live in one file,
 * hive/policy/guardrail.json, which main reads, validates, writes and reloads; this
 * screen only edits a draft and sends the whole file back with the stamp it read, so a
 * file changed elsewhere is never overwritten silently.
 *
 * Top-level on purpose, not a tab inside the per-agent modal: a rule is usually about
 * the floor, and the per-agent modal is the surface god is excluded from (md-140). The
 * per-agent modal gets the read-only RulesInEffect view instead.
 */
import { useCallback, useEffect, useMemo, useState, type CSSProperties } from 'react';
import { useStore } from '@/store/store';
import { PixelButton } from './PixelButton';
import type { BackstopDoes, GuardrailFile, GuardrailRule, GuardrailTestResult, GuardrailView } from '../../../shared/guardrail';
import { DOES, describeBackstop, emptyDraft, fromDraft, statusLine, toDraft, type Draft } from './rulesView';

const row: CSSProperties = { display: 'flex', gap: 8, alignItems: 'center' };
const label: CSSProperties = { fontSize: 11, opacity: 0.75, textTransform: 'uppercase', letterSpacing: 0.4 };
const box: CSSProperties = { border: '1px solid rgba(128,128,128,0.35)', borderRadius: 4, padding: 10 };
const input: CSSProperties = { width: '100%', padding: '6px 8px', fontFamily: 'inherit', fontSize: 12 };
const red: CSSProperties = { color: 'var(--cth-coral, #c0392b)', fontWeight: 600 };

export function RulesPanel() {
  const agents = useStore((s) => s.agents);
  const [view, setView] = useState<GuardrailView | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [errors, setErrors] = useState<string[]>([]);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [tryCmd, setTryCmd] = useState('');
  const [tried, setTried] = useState<GuardrailTestResult | null>(null);

  /** Every agent on the roster, god INCLUDED (md-140: the agent that most needs rules
   *  was the one with no surface to carry them). */
  const targetable = useMemo(
    () => agents.filter((a) => !a.archived).map((a) => ({ id: a.id, name: a.name })),
    [agents]
  );

  /** A read that produces neither a view nor an error would leave the screen on
   *  "Loading rules…" for ever, so an absent reply is a failure in its own right. */
  const load = useCallback(async () => {
    try {
      const v = await window.cth.guardrailRead();
      if (!v) { setView(null); setLoadErr('Could not read the rules: the main process returned nothing'); return; }
      setView(v);
      setLoadErr(null);
    } catch (e) { setView(null); setLoadErr(`Could not read the rules: ${e instanceof Error ? e.message : String(e)}`); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const rules = view?.file?.rules ?? [];
  const status = statusLine(view);

  const save = useCallback(async (nextRules: GuardrailRule[], done: string) => {
    if (!view) return;
    setBusy(true); setErrors([]); setNote(null);
    const base: GuardrailFile = view.file ?? { version: 1, rev: 0, rules: [] };
    try {
      const out = await window.cth.guardrailSave({ ...base, rules: nextRules }, view.stamp);
      if (out.ok) { setDraft(null); setNote(`${done} (rev ${out.rev}). In effect now.`); }
      else setErrors(out.errors.length ? out.errors : [out.reason]);
    } catch (e) { setErrors([e instanceof Error ? e.message : String(e)]); }
    setBusy(false);
    await load();
  }, [view, load]);

  const saveDraft = () => {
    if (!draft) return;
    const prev = rules.find((r) => r.id === draft.id);
    const rule = fromDraft(draft, prev);
    if (!draft.allAgents && !draft.picked.length) { setErrors(['Pick at least one agent, or choose all agents.']); return; }
    if (draft.isNew && rules.some((r) => r.id === rule.id)) { setErrors([`A rule with the id "${rule.id}" already exists.`]); return; }
    const next = draft.isNew ? [...rules, rule] : rules.map((r) => (r.id === draft.id ? rule : r));
    void save(next, draft.isNew ? 'Rule added' : 'Rule saved');
  };

  const toggle = (r: GuardrailRule) => {
    const b = r.backstop;
    if (!b) return;
    void save(rules.map((x) => (x.id === r.id ? { ...x, backstop: { ...b, on: !b.on } } : x)),
      b.on ? 'Backstop turned off' : 'Backstop turned on');
  };

  const remove = (r: GuardrailRule) => {
    if (!window.confirm(`Delete the rule "${r.principle}"? A backup of the file is kept.`)) return;
    void save(rules.filter((x) => x.id !== r.id), 'Rule deleted');
  };

  const tryIt = async () => {
    if (!draft || !tryCmd.trim()) return;
    try {
      setTried(await window.cth.guardrailTest(fromDraft({ ...draft, hasBackstop: true }), tryCmd.trim(),
        draft.allAgents ? undefined : draft.picked[0]));
    } catch (e) { setTried({ fires: false, error: e instanceof Error ? e.message : String(e) }); }
  };

  const set = (patch: Partial<Draft>) => setDraft((d) => (d ? { ...d, ...patch } : d));
  const nameOf = (id: string) => targetable.find((a) => a.id === id)?.name ?? id;
  const startEdit = (d: Draft) => { setDraft(d); setErrors([]); setTried(null); setTryCmd(''); setNote(null); };
  const caps = view?.caps;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ ...row, justifyContent: 'space-between' }}>
        <div style={{ fontSize: 12, ...(status.bad || loadErr ? red : {}) }}>{loadErr ?? status.text}</div>
        <PixelButton variant="primary" size="sm" disabled={busy || !!draft || !view} onClick={() => startEdit(emptyDraft())}>
          + Add rule
        </PixelButton>
      </div>
      {caps && (
        <div style={{ fontSize: 11, opacity: 0.75, ...(caps.over.length ? red : {}) }}>
          Principles for all agents: {caps.global.count} of {caps.global.max} used
          {caps.over.length ? ` · over the cap for ${caps.over.join(', ')}` : ''}
        </div>
      )}
      {note && <div style={{ fontSize: 12 }}>{note}</div>}
      {errors.length > 0 && !draft && (
        <div style={{ ...box, ...red, fontSize: 12 }}>{errors.map((e) => <div key={e}>{e}</div>)}</div>
      )}

      {rules.length === 0 && view && !view.error && (
        <div style={{ ...box, fontSize: 12 }}>
          No rules yet. A rule is a sentence your agents are given, for example &quot;Do not push without my
          approval&quot;. Add a backstop to have the hook enforce it.
        </div>
      )}

      {rules.map((r) => (
        <div key={r.id} style={{ ...box, display: 'flex', flexDirection: 'column', gap: 4 }}>
          <div style={{ ...row, justifyContent: 'space-between' }}>
            <div style={{ fontSize: 13 }}>{r.principle}</div>
            <div style={{ fontSize: 11, opacity: 0.75, whiteSpace: 'nowrap' }}>
              {r.agents === 'all' ? 'all agents' : r.agents.map(nameOf).join(', ')}
            </div>
          </div>
          <div style={{ ...row, justifyContent: 'space-between' }}>
            <div style={{ fontSize: 11, opacity: r.backstop?.on === false ? 0.55 : 0.85 }}>{describeBackstop(r)}</div>
            <div style={row}>
              {r.backstop && (
                <PixelButton variant="secondary" size="sm" disabled={busy || !!draft} onClick={() => toggle(r)}>
                  {r.backstop.on ? 'Turn off' : 'Turn on'}
                </PixelButton>
              )}
              <PixelButton variant="secondary" size="sm" disabled={busy || !!draft} onClick={() => startEdit(toDraft(r))}>Edit</PixelButton>
              <PixelButton variant="destructive" size="sm" disabled={busy || !!draft} onClick={() => remove(r)}>Delete</PixelButton>
            </div>
          </div>
          {r.agents !== 'all' && r.backstop && <div style={{ fontSize: 10, opacity: 0.6 }}>The backstop applies to these agents only.</div>}
        </div>
      ))}

      {draft && (
        <div style={{ ...box, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={label}>{draft.isNew ? 'New rule' : `Edit rule ${draft.id}`}</div>
          <div style={label}>Principle: what your agents are told</div>
          <textarea style={{ ...input, minHeight: 48 }} value={draft.principle}
            onChange={(e) => set({ principle: e.target.value })} placeholder="Do not push without my approval." />
          <div style={label}>Applies to</div>
          <div style={{ ...row, flexWrap: 'wrap' }}>
            <label style={{ fontSize: 12 }}>
              <input type="checkbox" checked={draft.allAgents} onChange={(e) => set({ allAgents: e.target.checked })} /> All agents
            </label>
            {!draft.allAgents && targetable.map((a) => (
              <label key={a.id} style={{ fontSize: 12 }}>
                <input type="checkbox" checked={draft.picked.includes(a.id)}
                  onChange={(e) => set({ picked: e.target.checked ? [...draft.picked, a.id] : draft.picked.filter((x) => x !== a.id) })} /> {a.name}
              </label>
            ))}
          </div>
          <label style={{ fontSize: 12 }}>
            <input type="checkbox" checked={draft.hasBackstop} onChange={(e) => set({ hasBackstop: e.target.checked })} />{' '}
            Add a backstop: the hook checks every tool call
          </label>
          {draft.hasBackstop && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, paddingLeft: 12 }}>
              <div style={row}>
                <span style={{ fontSize: 12 }}>What it does</span>
                <select value={draft.does} onChange={(e) => set({ does: e.target.value as BackstopDoes })}>
                  {DOES.map((d) => <option key={d.v} value={d.v}>{d.label}</option>)}
                </select>
                <label style={{ fontSize: 12 }}><input type="checkbox" checked={draft.on} onChange={(e) => set({ on: e.target.checked })} /> On</label>
              </div>
              {draft.does === 'ask' && (
                <label style={{ fontSize: 12 }}>
                  <input type="checkbox" checked={draft.approveOnCard} onChange={(e) => set({ approveOnCard: e.target.checked })} />{' '}
                  Let me approve one exact git push on a card
                </label>
              )}
              {draft.does === 'log' && (
                <div style={{ fontSize: 11, opacity: 0.7 }}>Log only records what it would have done and lets the call run.</div>
              )}
              <div style={label}>Tool (comma separated)</div>
              <input style={input} value={draft.tool} onChange={(e) => set({ tool: e.target.value })} placeholder="Bash" />
              <div style={label}>Command pattern (regular expression)</div>
              <input style={input} value={draft.commandMatches} onChange={(e) => set({ commandMatches: e.target.value })} placeholder="^git\s+push\b" />
              <div style={label}>Or a path pattern</div>
              <input style={input} value={draft.pathGlob} onChange={(e) => set({ pathGlob: e.target.value })} placeholder="**/secrets/**" />
              <label style={{ fontSize: 12 }}>
                <input type="checkbox" checked={draft.otherWorkspace} onChange={(e) => set({ otherWorkspace: e.target.checked })} />{' '}
                Fires when a call writes inside another agent&apos;s workspace
              </label>
              <div style={label}>Message to the agent when stopped (optional)</div>
              <input style={input} value={draft.message} onChange={(e) => set({ message: e.target.value })} placeholder="Defaults to the principle" />
              <div style={label}>Try it: would this stop a command?</div>
              <div style={row}>
                <input style={input} value={tryCmd} onChange={(e) => { setTryCmd(e.target.value); setTried(null); }} placeholder="git push origin main" />
                <PixelButton variant="secondary" size="sm" disabled={!tryCmd.trim()} onClick={() => void tryIt()}>Try</PixelButton>
              </div>
              {tried && (
                <div style={{ fontSize: 12, ...(tried.error ? red : {}) }}>
                  {tried.error ? `Cannot test: ${tried.error}`
                    : tried.fires ? `Yes: it would ${tried.does === 'block' ? 'block' : tried.does === 'ask' ? 'ask' : 'log'} this (${tried.on}).`
                      : 'No: this command would run.'}
                </div>
              )}
            </div>
          )}
          {errors.length > 0 && <div style={{ ...red, fontSize: 12 }}>{errors.map((e) => <div key={e}>{e}</div>)}</div>}
          <div style={row}>
            <PixelButton variant="primary" size="sm" disabled={busy || !draft.principle.trim()} onClick={saveDraft}>{busy ? 'Saving…' : 'Save'}</PixelButton>
            <PixelButton variant="secondary" size="sm" disabled={busy} onClick={() => { setDraft(null); setErrors([]); }}>Cancel</PixelButton>
          </div>
        </div>
      )}
      <div style={{ fontSize: 10, opacity: 0.6 }}>
        Saved to {view?.status?.file ?? 'hive/policy/guardrail.json'}. Each save keeps a backup and takes effect at once.
      </div>
    </div>
  );
}

/** Read-only per-agent view, for the agent modal: the principles this agent is given. */
export function RulesInEffect({ agentId }: { agentId: string }) {
  const [data, setData] = useState<{ rev: number; rules: Array<{ id: string; text: string }>; deliveredRev: number | null } | null>(null);
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const d = (await window.cth.rulesInEffect(agentId)) as typeof data;
        if (!cancelled) setData(d ?? null);
      } catch { /* absent bridge = feature off */ }
    })();
    return () => { cancelled = true; };
  }, [agentId]);

  if (!data || !data.rules.length) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={label}>Rules in effect (rev {data.rev}) · read-only</div>
      {data.rules.map((r, i) => (
        <div key={r.id} style={{ fontSize: 11, opacity: 0.85, lineHeight: 1.5 }}>({i + 1}) {r.text}</div>
      ))}
      <div style={{ fontSize: 10, opacity: 0.6 }}>
        Edited in Settings → Rules. Rendered into this agent&apos;s pinned memory automatically.
      </div>
    </div>
  );
}

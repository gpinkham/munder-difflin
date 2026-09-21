/**
 * RulesPanel — authoring surface for agent authority rules (md-146 Phase 3).
 *
 * Top-level on purpose, not a tab inside the per-agent modal. A rule is usually
 * about the floor rather than about one agent, and the per-agent modal is the
 * wrong home for something global: it also happens to be the surface god is
 * excluded from, which is how the orchestrator ended up unable to hold the rules
 * it most needed. The per-agent modal gets a READ-ONLY view instead.
 *
 * The cap is shown while authoring rather than enforced afterwards. A refusal
 * after the writing is done tells you nothing useful; a live count lets the author
 * see the number move and retire something first.
 */
import { useCallback, useEffect, useMemo, useState, type CSSProperties } from 'react';
import { useStore } from '@/store/store';
import { PixelButton } from './PixelButton';

interface Rule {
  id: string;
  text: string;
  scope?: { kind: 'global' } | { kind: 'agents'; ids: string[] } | string;
  why?: string;
  status?: 'active' | 'retired';
  added_by?: string;
  added?: string;
  retired?: string;
  enforceable?: string;
}
interface CapEntry { count: number; tokens: number; max: number; maxTokens: number; over: boolean }
interface Overview {
  active: boolean;
  rev: number;
  rules: Rule[];
  targets: Record<string, string[]>;
  caps: { global: CapEntry; perAgent: Record<string, CapEntry>; over: string[] };
  deliveredRevs: Record<string, number | null>;
}

/** The preload bridge is `window.cth` — the name `contextBridge.exposeInMainWorld`
 *  actually registers (`src/preload/index.ts:1439`), typed as `CthApi` in
 *  `src/preload/index.d.ts`. Reaching for it through a hand-written
 *  `window as unknown as { api?: … }` cast is what shipped this panel with an
 *  eternal "Loading rules…": the cast invents a global that does not exist, so every
 *  call optional-chained away to `undefined` and no error was ever thrown. Go through
 *  the declared global so the compiler checks both the name and the methods; only the
 *  RESULT is cast, because the preload types these channels as `Promise<unknown>`. */
type UpsertResult = { ok: boolean; reason?: string; rev?: number; rendered?: string[]; detail?: unknown };
type RetireResult = { ok: boolean; reason?: string; rev?: number; rendered?: string[] };

const rulesApi = {
  overview: () => window.cth.rulesOverview() as Promise<Overview>,
  capPreview: (c: unknown) => window.cth.rulesCapPreview(c) as Promise<Overview['caps']>,
  upsert: (r: unknown, rev?: number) => window.cth.rulesUpsert(r, rev) as Promise<UpsertResult>,
  retire: (id: string, rev?: number) => window.cth.rulesRetire(id, rev) as Promise<RetireResult>,
  inEffect: (id: string) =>
    window.cth.rulesInEffect(id) as Promise<{ rev: number; rules: Rule[]; deliveredRev: number | null } | null>
};

const slug = (s: string): string =>
  s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);

const row: CSSProperties = { display: 'flex', gap: 8, alignItems: 'center' };
const label: CSSProperties = { fontSize: 11, opacity: 0.75, textTransform: 'uppercase', letterSpacing: 0.4 };
const box: CSSProperties = { border: '1px solid rgba(128,128,128,0.35)', borderRadius: 4, padding: 10 };
const input: CSSProperties = { width: '100%', padding: '6px 8px', fontFamily: 'inherit', fontSize: 12 };

export function RulesPanel() {
  const agents = useStore((s) => s.agents);
  const [ov, setOv] = useState<Overview | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  // draft
  const [editingId, setEditingId] = useState<string | null>(null);
  const [text, setText] = useState('');
  const [why, setWhy] = useState('');
  const [globalScope, setGlobalScope] = useState(true);
  const [picked, setPicked] = useState<string[]>([]);
  const [preview, setPreview] = useState<Overview['caps'] | null>(null);

  /** Every agent on the roster, god INCLUDED. Excluding the orchestrator here is
   *  the md-140 bug: the agent that most needs authority rules was the one with no
   *  surface to carry them. There is deliberately no `isGod` filter. */
  const targetable = useMemo(
    () => agents.filter((a) => !a.archived).map((a) => ({ id: a.id, name: a.name, isGod: !!a.isGod })),
    [agents]
  );

  /** A load that produces neither an overview nor an error would leave the panel on
   *  "Loading rules…" for ever, so treat an absent reply as a failure in its own
   *  right rather than as "still waiting". */
  const load = useCallback(async () => {
    try {
      const o = await rulesApi.overview();
      if (!o) { setOv(null); setErr('the main process returned no rules overview'); return; }
      setOv(o);
      setErr(null);
    } catch (e) { setOv(null); setErr(e instanceof Error ? e.message : String(e)); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const draftRule = useCallback((): Rule => ({
    id: editingId ?? (slug(text) || 'rule'),
    text: text.trim(),
    scope: globalScope ? { kind: 'global' } : { kind: 'agents', ids: picked },
    why: why.trim() || undefined,
    status: 'active'
  }), [editingId, text, why, globalScope, picked]);

  // Live cap preview as the draft changes — the point of authoring-time caps.
  useEffect(() => {
    let cancelled = false;
    if (!text.trim()) { setPreview(null); return; }
    void (async () => {
      try {
        const c = await rulesApi.capPreview(draftRule());
        if (!cancelled) setPreview(c ?? null);
      } catch { /* preview is advisory */ }
    })();
    return () => { cancelled = true; };
  }, [text, why, globalScope, picked, draftRule]);

  const reset = () => { setEditingId(null); setText(''); setWhy(''); setGlobalScope(true); setPicked([]); setPreview(null); };

  const save = async () => {
    if (!text.trim()) return;
    if (!globalScope && !picked.length) { setErr('Pick at least one agent, or make the rule global.'); return; }
    setBusy(true); setErr(null); setNote(null);
    try {
      const res = await rulesApi.upsert(draftRule(), ov?.rev);
      if (!res?.ok) {
        setErr(res?.reason === 'over-cap'
          ? 'Over the cap. Retire a rule before adding another — the cap is there to keep each rule salient.'
          : res?.reason === 'stale-rev'
            ? 'Someone else changed the rules while you were editing. Reloaded; re-check and save again.'
            : `Could not save: ${res?.reason ?? 'unknown'}`);
        if (res?.reason === 'stale-rev') await load();
        return;
      }
      setNote(`Saved as rev ${res.rev}. Rendered to ${res.rendered?.length ?? 0} agent(s); each is told what changed on its next turn.`);
      reset();
      await load();
    } finally { setBusy(false); }
  };

  const retire = async (id: string) => {
    setBusy(true); setErr(null); setNote(null);
    try {
      const res = await rulesApi.retire(id, ov?.rev);
      if (!res?.ok) { setErr(`Could not retire: ${res?.reason ?? 'unknown'}`); return; }
      setNote(`Retired at rev ${res.rev}. Kept in the store as a tombstone, dropped from every rendered block.`);
      await load();
    } finally { setBusy(false); }
  };

  const edit = (r: Rule) => {
    setEditingId(r.id);
    setText(r.text);
    setWhy(r.why ?? '');
    const s = r.scope;
    const isAgents = typeof s === 'object' && s !== null && (s as { kind?: string }).kind === 'agents';
    setGlobalScope(!isAgents);
    setPicked(isAgents ? [...((s as { ids?: string[] }).ids ?? [])] : []);
  };

  if (!ov) {
    return <div style={{ fontSize: 12, opacity: 0.8 }}>{err ? `Rules unavailable: ${err}` : 'Loading rules…'}</div>;
  }
  if (!ov.active) {
    return (
      <div style={{ ...box, fontSize: 12, lineHeight: 1.5 }}>
        <div style={{ fontWeight: 600, marginBottom: 6 }}>Rules are not set up for this hive.</div>
        Create <code>&lt;harnessHome&gt;/hive/policy/rules.json</code> with{' '}
        <code>{'{ "rev": 1, "rules": [] }'}</code> to switch this on. Until then nothing is
        rendered, logged or delivered — the feature is dormant.
      </div>
    );
  }

  const active = ov.rules.filter((r) => (r.status ?? 'active') === 'active');
  const retired = ov.rules.filter((r) => r.status === 'retired');
  const caps = preview ?? ov.caps;
  const overAgents = caps.over.filter((x) => x !== 'global');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ ...row, justifyContent: 'space-between' }}>
        <div style={{ fontSize: 12 }}>
          <strong>rev {ov.rev}</strong> · {active.length} active rule{active.length === 1 ? '' : 's'}
          {retired.length ? ` · ${retired.length} retired` : ''}
        </div>
        <div style={{ fontSize: 11, opacity: 0.75 }}>
          global {caps.global.count}/{caps.global.max} · ~{caps.global.tokens}/{caps.global.maxTokens} tok
        </div>
      </div>

      <div style={{ fontSize: 11, opacity: 0.8, lineHeight: 1.5 }}>
        Saving bumps the revision, writes the rule into each targeted agent's pinned
        memory block, and tells that agent what changed on its next turn. Nobody has to
        paste anything.
      </div>

      {/* — author — */}
      <div style={{ ...box, display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div style={label}>{editingId ? `Edit rule · ${editingId}` : 'New rule'}</div>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={3}
          placeholder="Write only inside your own agent folder. To reach another agent, write one message to your own outbox."
          style={{ ...input, resize: 'vertical' }}
        />
        <input
          value={why}
          onChange={(e) => setWhy(e.target.value)}
          placeholder="Why (optional) — the reason this exists, for whoever reads it in six months"
          style={input}
        />

        <div style={label}>Applies to</div>
        <div style={{ ...row, gap: 14 }}>
          <label style={row}>
            <input type="radio" checked={globalScope} onChange={() => setGlobalScope(true)} /> Every agent
          </label>
          <label style={row}>
            <input type="radio" checked={!globalScope} onChange={() => setGlobalScope(false)} /> Pick agents
          </label>
        </div>
        {!globalScope && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
            {targetable.map((a) => (
              <label key={a.id} style={row}>
                <input
                  type="checkbox"
                  checked={picked.includes(a.id)}
                  onChange={(e) => setPicked((p) => e.target.checked ? [...p, a.id] : p.filter((x) => x !== a.id))}
                />
                <span style={{ fontSize: 12 }}>{a.name}{a.isGod ? ' (orchestrator)' : ''}</span>
              </label>
            ))}
            {!targetable.length && <span style={{ fontSize: 11, opacity: 0.7 }}>No agents on the roster.</span>}
          </div>
        )}

        {/* per-agent budget, live */}
        <div style={{ fontSize: 11, opacity: 0.85, display: 'flex', flexWrap: 'wrap', gap: 10 }}>
          {targetable.map((a) => {
            const c = caps.perAgent[a.id];
            if (!c) return null;
            return (
              <span key={a.id} style={{ color: c.over ? '#c0392b' : undefined }}>
                {a.name} {c.count}/{c.max} · ~{c.tokens}/{c.maxTokens} tok
              </span>
            );
          })}
        </div>

        {(caps.global.over || overAgents.length > 0) && (
          <div style={{ fontSize: 11, color: '#c0392b', lineHeight: 1.5 }}>
            Over the cap{overAgents.length ? ` for ${overAgents.join(', ')}` : ' globally'}. Saving is
            blocked until something is retired. The cap is an alignment mechanism, not a
            budget: fewer rules means each one is actually held.
          </div>
        )}

        <div style={row}>
          <PixelButton
            size="sm"
            onClick={() => void save()}
            disabled={busy || !text.trim() || caps.global.over || overAgents.length > 0}
          >
            {editingId ? 'Save changes' : 'Add rule'}
          </PixelButton>
          {editingId && <PixelButton size="sm" variant="secondary" onClick={reset}>Cancel</PixelButton>}
        </div>
      </div>

      {err && <div style={{ fontSize: 11, color: '#c0392b' }}>{err}</div>}
      {note && <div style={{ fontSize: 11, opacity: 0.85 }}>{note}</div>}

      {/* — active rules — */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div style={label}>Active</div>
        {!active.length && <div style={{ fontSize: 12, opacity: 0.7 }}>No rules yet.</div>}
        {active.map((r) => {
          const hit = ov.targets[r.id] ?? [];
          const names = hit.map((id) => targetable.find((a) => a.id === id)?.name ?? id);
          return (
            <div key={r.id} style={{ ...box, display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ fontSize: 12, lineHeight: 1.5 }}>{r.text}</div>
              {r.why && <div style={{ fontSize: 11, opacity: 0.7 }}>Why: {r.why}</div>}
              <div style={{ fontSize: 11, opacity: 0.75 }}>
                {typeof r.scope === 'object' && r.scope && (r.scope as { kind?: string }).kind === 'agents'
                  ? `Applies to: ${names.join(', ') || '(nobody — check the agent ids)'}`
                  : `Applies to every agent (${hit.length})`}
                {r.added_by ? ` · added by ${r.added_by}` : ''}{r.added ? ` ${r.added}` : ''}
              </div>
              <div style={row}>
                <PixelButton size="sm" variant="secondary" onClick={() => edit(r)} disabled={busy}>Edit</PixelButton>
                <PixelButton size="sm" variant="secondary" onClick={() => void retire(r.id)} disabled={busy}>Retire</PixelButton>
              </div>
            </div>
          );
        })}
      </div>

      {/* — tombstones — */}
      {retired.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={label}>Retired</div>
          <div style={{ fontSize: 11, opacity: 0.7, lineHeight: 1.5 }}>
            Kept on purpose. A rule that simply vanishes leaves the next reader noticing a
            gap and re-opening the question it settled.
          </div>
          {retired.map((r) => (
            <div key={r.id} style={{ fontSize: 11, opacity: 0.65, textDecoration: 'line-through' }}>
              {r.text}{r.retired ? ` · retired ${r.retired}` : ''}
            </div>
          ))}
        </div>
      )}

      {/* — delivery audit — */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <div style={label}>Delivery</div>
        <div style={{ fontSize: 11, opacity: 0.75, lineHeight: 1.6 }}>
          {targetable.map((a) => {
            const d = ov.deliveredRevs[a.id];
            const current = d === ov.rev;
            return (
              <span key={a.id} style={{ marginRight: 12 }}>
                {a.name}: {d === null ? 'not yet told' : `told rev ${d}`}
                {current ? ' ✓' : ' · notice pending'}
              </span>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/**
 * The per-agent READ-ONLY view, for the agent modal. The goal editor should show
 * an agent's complete standing context, and half of that now comes from the rules
 * store — but authoring stays in one place so a rule cannot be edited from two
 * surfaces with different ideas of the cap.
 */
export function RulesInEffect({ agentId }: { agentId: string }) {
  const [data, setData] = useState<{ rev: number; rules: Rule[]; deliveredRev: number | null } | null>(null);
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const d = await rulesApi.inEffect(agentId);
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

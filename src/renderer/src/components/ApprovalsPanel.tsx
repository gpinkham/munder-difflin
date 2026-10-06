import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { PixelButton } from './PixelButton';
import { describeGrant, orderPending, type PendingGrantView } from './approvals';

/**
 * HAG-49 — pending approvals at the top of ASK ME. Renders NOTHING unless the policy
 * file makes a rule grantable: the check runs once on mount and the component stays
 * empty when main says approvals are off.
 *
 * Approve is the only way a grant is minted. The click goes to main over IPC; an
 * agent has no path to it.
 */
export function ApprovalsPanel({ onCount }: { onCount?: (n: number) => void }) {
  const { t: translate } = useTranslation();
  const [active, setActive] = useState(false);
  const [pending, setPending] = useState<PendingGrantView[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const list = await window.cth.policyPendingGrants();
      const ordered = orderPending(Array.isArray(list) ? list : []);
      setPending(ordered);
      onCount?.(ordered.length);
    } catch { /* keep what is shown */ }
  }, [onCount]);

  useEffect(() => {
    let off: (() => void) | undefined;
    let cancelled = false;
    void window.cth.policyGrantsActive().then((on) => {
      if (cancelled || !on) return;
      setActive(true);
      void refresh();
      off = window.cth.onPolicyGrantsChanged(() => { void refresh(); });
    }).catch(() => { /* off */ });
    return () => { cancelled = true; off?.(); };
  }, [refresh]);

  if (!active || pending.length === 0) return null;

  const decide = async (id: string, approve: boolean) => {
    setBusy(id);
    setError(null);
    try {
      const r = await window.cth.policyDecideGrant(id, approve);
      if (!r.ok) setError(r.error ?? 'failed');
    } finally {
      setBusy(null);
      void refresh();
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ fontSize: 12, color: 'var(--cth-ink-500)' }}>
        {translate('askMe.approvals.title', 'Approvals: one action each')}
      </div>
      {error && <div style={{ fontSize: 11, color: 'var(--cth-coral)' }}>{error}</div>}
      {pending.map((g) => {
        const d = describeGrant(g);
        return (
          <div key={g.id} style={{ background: 'var(--cth-paper-100)', boxShadow: 'inset 0 0 0 1px var(--cth-ink-100)', padding: '8px 9px', display: 'flex', flexDirection: 'column', gap: 6 }}>
            <div style={{ fontSize: 15, color: 'var(--cth-ink-900)' }}>{d.title}</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', columnGap: 8, rowGap: 2, fontSize: 12 }}>
              {d.facts.map(([k, v]) => (
                <div key={k} style={{ display: 'contents' }}>
                  <span style={{ color: 'var(--cth-ink-500)' }}>{k}</span>
                  <span style={{ color: k === 'Warning' ? 'var(--cth-coral, #c0392b)' : 'var(--cth-ink-900)', fontWeight: k === 'Warning' ? 600 : undefined, overflowWrap: 'anywhere' }}>{v}</span>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
              <PixelButton size="sm" disabled={busy === g.id} onClick={() => void decide(g.id, false)}>
                {translate('askMe.approvals.deny', 'Deny')}
              </PixelButton>
              <PixelButton variant="primary" size="sm" disabled={busy === g.id} onClick={() => void decide(g.id, true)}>
                {translate('askMe.approvals.approve', 'Approve this push')}
              </PixelButton>
            </div>
          </div>
        );
      })}
    </div>
  );
}

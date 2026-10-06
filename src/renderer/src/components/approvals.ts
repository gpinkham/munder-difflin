/**
 * HAG-49 approvals: how a pending request reads on the ASK ME tab. Pure, so it is
 * testable without a DOM.
 *
 * Everything shown comes from main's own copy of the request (policy:pendingGrants),
 * never from tasks.json, which agents can write. What the operator approves is the
 * canonical action main parsed, so it is shown first and in full: the branch, the
 * whole sha and the resolved remote URL. The agent's command and reason come after,
 * as context.
 */

export interface PendingGrantView {
  id: string;
  agent_id: string;
  command: string;
  cwd: string | null;
  reason: string;
  requested_at: string;
  action: { class: string; summary: string; target: { remote_url: string; ref: string; sha: string } };
  /** Set when the remote fetches from a different URL than this push goes to. */
  fetch_url?: string;
}

export interface ApprovalLines {
  title: string;
  facts: Array<[label: string, value: string]>;
}

export function describeGrant(g: PendingGrantView): ApprovalLines {
  const t = g.action.target;
  return {
    title: g.action.summary,
    facts: [
      ['Agent', g.agent_id],
      ['Branch', t.ref.replace(/^refs\/heads\//, '')],
      ['Commit', t.sha],
      ['Remote', t.remote_url],
      ...(g.fetch_url ? [['Warning', `this pushes to ${t.remote_url}, but the remote fetches from ${g.fetch_url}`] as [string, string]] : []),
      ['Valid', 'once, for 60 minutes after you approve'],
      ['Command', g.command],
      ...(g.reason ? [['Reason', g.reason] as [string, string]] : []),
    ],
  };
}

/** Oldest first: the one that has waited longest is the one to answer. */
export function orderPending(list: PendingGrantView[]): PendingGrantView[] {
  return [...list].sort((a, b) => a.requested_at.localeCompare(b.requested_at));
}

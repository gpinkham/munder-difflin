/**
 * Action-bound approval (HAG-49): consent as a capability for ONE proposed action.
 *
 * "Yes, push after the recheck" is prose an agent interprets. A grant is not: it
 * names one action class, one exact target, one agent and a short life, and the
 * policy engine checks the command against it before letting an `ask` rule pass.
 *
 * ENTIRELY OPT-IN. Nothing here runs unless a rule in the policy file lists
 * `"grantable": ["git-push"]`. Without that there is no desk, no grants file, no
 * request handling and no Approve UI.
 *
 * WHO MINTS. Only the operator, by clicking Approve in the app. The ASK ME answers
 * in tasks.json are agent-writable, so nothing is ever minted from text. The grants
 * file lives in the policy directory, which agents cannot write (self-protection),
 * and main is its only writer.
 *
 * v1 GRAMMAR, deliberately narrow. Exactly one form can be granted:
 *   git [-C <dir>] push [-u|--set-upstream] <remote> <40-hex sha>:refs/heads/<branch>
 * and only when it is the WHOLE Bash call and starts with git itself. The sha is in the
 * command, so the engine compares strings and never resolves what a branch points to.
 * The remote is judged by its PUSH url, resolved at evaluation, because a remote NAME
 * can be re-pointed (set-url, pushurl, pushInsteadOf). A repo that would push
 * submodules or tags along with the ref is refused.
 * Anything else — force, --all, --tags, --delete, more than one refspec, a compound
 * call, gh, curl, an alias — cannot be granted and keeps asking.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, isAbsolute, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { effectiveCommands } from './shell';

export const GRANT_CLASSES = ['git-push'] as const;
export type GrantClass = (typeof GRANT_CLASSES)[number];
export const GRANTS_FILE = 'grants.jsonl';
/** How long an approval stays usable after it is minted. */
export const GRANT_TTL_MS = 60 * 60 * 1000;
/** After first use, the identical action may run again for this long (a retried push). */
export const GRANT_RETRY_MS = 10 * 60 * 1000;

export interface GitPushTarget {
  remote_url: string;
  ref: string;
  sha: string;
}

export interface CanonicalAction {
  class: GrantClass;
  target: GitPushTarget;
  /** One line a human can approve without reading the command. */
  summary: string;
}

export interface Grant {
  id: string;
  class: GrantClass;
  agent_id: string;
  target: GitPushTarget;
  minted_at: string;
  expires_at: string;
  request_id: string;
}

export interface GrantRequest {
  id: string;
  agent_id: string;
  command: string;
  cwd: string | null;
  reason: string;
  action: CanonicalAction;
  requested_at: string;
  /** Set when the remote fetches from a different URL than this push goes to. */
  fetch_url?: string;
}

/** What the grant check needs to know about the repo a push runs in. */
export interface GitInspector {
  /** Where `git push <remote>` would actually send, or null when it cannot tell. */
  pushUrl(dir: string, remote: string): string | null;
  /** Why one approved push could publish more than its ref, or null when it cannot. */
  pushRisk(dir: string): string | null;
  /** Where the remote FETCHES from, to flag a push that goes elsewhere (item 6). */
  fetchUrl?(dir: string, remote: string): string | null;
}

const git = (dir: string, args: string[]) =>
  execFileSync('git', ['-C', dir, ...args], { timeout: 2000, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

export const gitInspector: GitInspector = {
  // --push: the PUSH url, after pushurl and pushInsteadOf, which is where git push goes.
  // Without it the fetch url was checked, and a pushurl in the repo's own config sent an
  // approved push somewhere else (Dwight, HAG-49 H1).
  pushUrl(dir, remote) {
    try { return git(dir, ['remote', 'get-url', '--push', remote]) || null; } catch { return null; }
  },
  fetchUrl(dir, remote) {
    try { return git(dir, ['remote', 'get-url', remote]) || null; } catch { return null; }
  },
  pushRisk(dir) {
    const get = (key: string): string | null => {
      try { return git(dir, ['config', '--get', key]); } catch (e) {
        // Exit 1 is "not set". Anything else means the config could not be read: refuse.
        if ((e as { status?: number }).status === 1) return null;
        throw e;
      }
    };
    try {
      const sub = (get('push.recurseSubmodules') ?? '').toLowerCase();
      if (sub && sub !== 'no' && sub !== 'check' && sub !== 'false') return `push.recurseSubmodules is ${sub}, so the push would also publish submodule commits`;
      const tags = (get('push.followTags') ?? '').toLowerCase();
      if (tags === 'true' || tags === 'yes' || tags === 'on' || tags === '1') return 'push.followTags is on, so the push would also publish tags';
      return null;
    } catch {
      return 'the repository config could not be read';
    }
  },
};

const SHA = /^[0-9a-f]{40}$/;
const BRANCH = /^(?!\/|.*\/\/|.*\.\.|.*\/$|.*\.lock$|.*@\{)[A-Za-z0-9._/-]+$/;
const ok = (a: CanonicalAction) => ({ ok: true as const, action: a });
const no = (why: string) => ({ ok: false as const, why });

/**
 * The canonical action a Bash command performs, or the reason it cannot be granted.
 * `cwd` is where the agent's shell is; a `-C <dir>` in the command overrides it.
 */
export function canonicalAction(command: string, cwd: string | null | undefined, inspect: GitInspector = gitInspector):
  { ok: true; action: CanonicalAction } | { ok: false; why: string } {
  // The RAW command must be git itself: the parser strips env assignments and
  // wrappers, and `GIT_CONFIG_COUNT=1 … git push` or `env GIT_DIR=… git push` changes
  // where the push goes without changing what the parser sees (Dwight, HAG-49 H1).
  if (!/^git\s/.test(command.trim())) return no('the command must start with git itself: no environment assignments, env, bash -c or other wrapper in front');
  let cmds;
  try { cmds = effectiveCommands(command, cwd ?? undefined); } catch { return no('the command could not be parsed'); }
  if (cmds.length !== 1) return no('only a single command can be approved; run the push on its own (use git -C <dir> instead of cd)');
  const c = cmds[0];
  if (c.unresolved.length) return no('the command has parts that cannot be read (a variable, a substitution or a pipe)');
  const argv = c.argv;
  if (argv[0] !== 'git') return no('only git push can be approved');
  let i = 1;
  let dir = cwd ?? null;
  while (argv[i] === '-C') {
    if (!argv[i + 1]) return no('-C needs a directory');
    dir = dir && !argv[i + 1].startsWith('/') ? join(dir, argv[i + 1]) : argv[i + 1];
    i += 2;
  }
  if (argv[i] !== 'push') return no('only git push can be approved, with no options before push other than -C <dir>');
  const rest = argv.slice(i + 1).filter((a) => a !== '-u' && a !== '--set-upstream');
  const flag = rest.find((a) => a.startsWith('-'));
  if (flag) return no(`${flag} cannot be approved; the approvable form is: git push <remote> <sha>:refs/heads/<branch>`);
  if (rest.length !== 2) return no('exactly one remote and one refspec are needed: git push <remote> <sha>:refs/heads/<branch>');
  const [remote, refspec] = rest;
  const m = /^([^:]+):(refs\/heads\/(.+))$/.exec(refspec);
  if (!m || !SHA.test(m[1])) return no('the refspec must be a full 40-character commit sha, a colon, and refs/heads/<branch>');
  if (!BRANCH.test(m[3])) return no('the branch name is not one that can be approved');
  if (!dir) return no('the working directory is unknown, so the remote cannot be resolved');
  const url = inspect.pushUrl(dir, remote);
  if (!url) return no(`the remote "${remote}" could not be resolved to a push URL in ${dir}`);
  const risk = inspect.pushRisk(dir);
  if (risk) return no(`one approved push would publish more than the approved ref: ${risk}`);
  const target = { remote_url: url, ref: m[2], sha: m[1] };
  return ok({ class: 'git-push', target, summary: `Push ${m[3]} at ${m[1].slice(0, 8)} to ${url}` });
}

export const sameTarget = (a: GitPushTarget, b: GitPushTarget) =>
  a.remote_url === b.remote_url && a.ref === b.ref && a.sha === b.sha;

const newId = (prefix: string) => `${prefix}_${randomBytes(6).toString('hex')}`;

/**
 * The grants file: append-only. A `mint` row per grant, a `use` row per use.
 * Read fresh on every lookup; it is small and a stale cache is how a used grant
 * would get used twice.
 */
export class GrantStore {
  constructor(private path: string) {}

  static in(policyDir: string): GrantStore {
    return new GrantStore(join(policyDir, GRANTS_FILE));
  }

  /** The folder the grants file lives in (the policy folder). */
  get dir(): string { return dirname(this.path); }

  private rows(): Array<Record<string, unknown>> {
    if (!existsSync(this.path)) return [];
    let text: string;
    try { text = readFileSync(this.path, 'utf8'); } catch { return []; }
    const out: Array<Record<string, unknown>> = [];
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try { out.push(JSON.parse(line)); } catch { /* a torn line grants nothing */ }
    }
    return out;
  }

  /** A grant this agent may use for this exact action now, or null. */
  findUsable(agentId: string, action: CanonicalAction, now = Date.now()): Grant | null {
    const rows = this.rows();
    const firstUse = new Map<string, number>();
    for (const r of rows) {
      if (r.op === 'use' && typeof r.id === 'string' && !firstUse.has(r.id)) firstUse.set(r.id, Date.parse(String(r.at)));
    }
    for (const r of rows) {
      if (r.op !== 'mint') continue;
      const g = r.grant as Grant | undefined;
      if (!g || g.agent_id !== agentId || g.class !== action.class || !g.target || !sameTarget(g.target, action.target)) continue;
      if (!(now < Date.parse(g.expires_at))) continue;
      const used = firstUse.get(g.id);
      if (used !== undefined && now - used > GRANT_RETRY_MS) continue;
      return g;
    }
    return null;
  }

  use(grant: Grant, now = Date.now()): void {
    this.append({ op: 'use', id: grant.id, at: new Date(now).toISOString() });
  }

  mint(request: GrantRequest, now = Date.now()): Grant {
    const grant: Grant = {
      id: newId('g'),
      class: request.action.class,
      agent_id: request.agent_id,
      target: request.action.target,
      minted_at: new Date(now).toISOString(),
      expires_at: new Date(now + GRANT_TTL_MS).toISOString(),
      request_id: request.id,
    };
    this.append({ op: 'mint', grant });
    return grant;
  }

  private append(row: Record<string, unknown>): void {
    mkdirSync(dirname(this.path), { recursive: true });
    appendFileSync(this.path, JSON.stringify(row) + '\n', 'utf8');
  }
}

/**
 * Main's side: agents' requests waiting for the operator, and the decision.
 * Pending requests live in memory only. The operator sees what THIS holds, never a
 * copy an agent could have edited.
 */
/** The desk's own state beside grants.jsonl: what waits on a card, what was approved. */
export const GRANT_DESK_FILE = 'grant-desk.json';

interface DeskState {
  pending: GrantRequest[];
  approved: Array<{ grant: Grant; command: string; cwd: string | null }>;
  /** Pushes the operator denied, held for GRANT_DENY_HOLD_MS (finish plan item 8). */
  denied: Array<{ agent_id: string; class: string; target: GitPushTarget; at: string }>;
}

/** After Deny, the same push by the same agent is refused at once, with no new card. */
export const GRANT_DENY_HOLD_MS = 10 * 60 * 1000;

export class GrantDesk {
  private pendingById = new Map<string, GrantRequest>();
  /** Approved commands, in order, so a retry in another form can be told the exact one. */
  private approved: DeskState['approved'] = [];
  private denied: DeskState['denied'] = [];
  private statePath: string;

  /** Loads what was waiting or approved before a restart (finish plan item 3). A torn
   *  file starts empty: nothing is approved by a file the desk cannot read. */
  constructor(private store: GrantStore, private inspect: GitInspector = gitInspector) {
    this.statePath = join(store.dir, GRANT_DESK_FILE);
    try {
      if (existsSync(this.statePath)) {
        const st = JSON.parse(readFileSync(this.statePath, 'utf8')) as Partial<DeskState>;
        for (const q of Array.isArray(st.pending) ? st.pending : []) if (q && typeof q.id === 'string') this.pendingById.set(q.id, q);
        this.approved = (Array.isArray(st.approved) ? st.approved : []).filter((a) => a && a.grant && typeof a.command === 'string');
        this.denied = (Array.isArray(st.denied) ? st.denied : []).filter((d) => d && d.target && typeof d.at === 'string');
      }
    } catch { this.pendingById.clear(); this.approved = []; this.denied = []; }
  }

  /** temp + rename, so a crash leaves the old state or the new, never half. */
  private persist(): void {
    try {
      mkdirSync(dirname(this.statePath), { recursive: true });
      const tmp = `${this.statePath}.tmp-${randomBytes(4).toString('hex')}`;
      writeFileSync(tmp, JSON.stringify({ pending: [...this.pendingById.values()], approved: this.approved, denied: this.denied }, null, 2) + '\n');
      renameSync(tmp, this.statePath);
    } catch { /* the in-memory desk still works; a restart then forgets */ }
  }

  /** Drop requests that waited longer than a grant would live. */
  private expire(now: number): void {
    let changed = false;
    const held = this.denied.filter((d) => now - Date.parse(d.at) < GRANT_DENY_HOLD_MS);
    if (held.length !== this.denied.length) { this.denied = held; changed = true; }
    for (const [id, q] of this.pendingById) {
      if (!(now - Date.parse(q.requested_at) < GRANT_TTL_MS)) { this.pendingById.delete(id); changed = true; }
    }
    if (changed) this.persist();
  }

  /** A new pending request, or the one already waiting for this agent's exact action
   *  (`fresh: false`): a retry before the operator decides raises no second card. */
  request(agentId: string, input: { command?: unknown; cwd?: unknown; reason?: unknown }, now = Date.now()):
    { ok: true; request: GrantRequest; fresh: boolean } | { ok: false; why: string; denied?: true } {
    if (typeof input.command !== 'string' || !input.command.trim()) return { ok: false, why: 'the request has no command' };
    const cwd = typeof input.cwd === 'string' && input.cwd ? input.cwd : null;
    const c = canonicalAction(input.command, cwd, this.inspect);
    if (!c.ok) return c;
    this.expire(now);
    const no = this.denied.find((d) => d.agent_id === agentId && d.class === c.action.class && sameTarget(d.target, c.action.target));
    if (no) {
      const until = new Date(Date.parse(no.at) + GRANT_DENY_HOLD_MS).toISOString();
      return { ok: false, denied: true, why: `the operator denied this push at ${no.at}; do not run it (it may be asked again after ${until})` };
    }
    for (const q of this.pendingById.values()) {
      if (q.agent_id === agentId && q.action.class === c.action.class && sameTarget(q.action.target, c.action.target)) {
        return { ok: true, request: q, fresh: false };
      }
    }
    // Item 6: a remote whose push URL is not its fetch URL (pushurl, pushInsteadOf)
    // sends this push somewhere the operator may not expect. Flag it on the card.
    const where = this.remoteOf(input.command, cwd);
    let fetchUrl: string | null = null;
    try { fetchUrl = where && this.inspect.fetchUrl ? this.inspect.fetchUrl(where.dir, where.remote) : null; } catch { fetchUrl = null; }
    const request: GrantRequest = {
      id: newId('r'), agent_id: agentId, command: input.command, cwd,
      reason: typeof input.reason === 'string' ? input.reason.slice(0, 500) : '',
      action: c.action, requested_at: new Date(now).toISOString(),
      ...(fetchUrl && fetchUrl !== c.action.target.remote_url ? { fetch_url: fetchUrl } : {}),
    };
    this.pendingById.set(request.id, request);
    this.persist();
    return { ok: true, request, fresh: true };
  }

  pending(now = Date.now()): GrantRequest[] {
    this.expire(now);
    return [...this.pendingById.values()];
  }

  /** The operator's decision. Returns the grant on Approve, null on Deny, an unknown id
   *  or a request that expired. */
  decide(requestId: string, approve: boolean, now = Date.now()): { request: GrantRequest; grant: Grant | null } | null {
    this.expire(now);
    const request = this.pendingById.get(requestId);
    if (!request) return null;
    this.pendingById.delete(requestId);
    const grant = approve ? this.store.mint(request, now) : null;
    if (grant) this.approved.push({ grant, command: request.command, cwd: request.cwd });
    else this.denied.push({ agent_id: request.agent_id, class: request.action.class, target: request.action.target, at: new Date(now).toISOString() });
    this.persist();
    return { request, grant };
  }

  /** openFor, limited to approvals for the remote this push command would send to.
   *  Null when the command's target cannot be worked out: then nothing is refused. */
  openForPush(agentId: string, command: string, cwd: string | null, now = Date.now()): ReturnType<GrantDesk['openFor']> {
    const url = this.pushTargetUrl(command, cwd);
    if (!url) return null;
    return this.openFor(agentId, now, url);
  }

  /** Where `git [-C dir] push [flags] [remote] …` sends: the remote's push URL in that
   *  repo (origin when no remote is named). Null for anything else, e.g. a compound
   *  command, whose directory cannot be known. */
  private pushTargetUrl(command: string, cwd: string | null): string | null {
    const where = this.remoteOf(command, cwd);
    if (!where) return null;
    try { return this.inspect.pushUrl(where.dir, where.remote); } catch { return null; }
  }

  /** The repo and remote of `git [-C dir] push [flags] [remote] …`, or null. */
  private remoteOf(command: string, cwd: string | null): { dir: string; remote: string } | null {
    const toks = command.trim().split(/\s+/);
    if (toks[0] !== 'git') return null;
    let dir = cwd;
    let i = 1;
    while (i < toks.length && toks[i] !== 'push') {
      if (toks[i] === '-C' && toks[i + 1]) { dir = isAbsolute(toks[i + 1]) ? toks[i + 1] : join(dir ?? '', toks[i + 1]); i += 2; continue; }
      if (toks[i].startsWith('-')) { i++; continue; }
      return null;
    }
    if (toks[i] !== 'push' || !dir) return null;
    if (toks.slice(i + 1).some((t) => /^(&&|\|\||;|\|)$/.test(t) || /[;&|]$/.test(t))) return null;
    return { dir, remote: toks.slice(i + 1).find((t) => !t.startsWith('-')) ?? 'origin' };
  }

  /** The push this agent may run now (approved, and its grant still usable) or is
   *  waiting on, newest first. Main's own copy of the command, never the agent's.
   *  Approvals whose grant can no longer be used are pruned. */
  openFor(agentId: string, now = Date.now(), remoteUrl?: string): { state: 'approved' | 'pending'; id: string; command: string; cwd: string | null } | null {
    this.expire(now);
    const live = this.approved.filter((a) => this.store.findUsable(a.grant.agent_id, { class: a.grant.class, target: a.grant.target, summary: '' }, now));
    if (live.length !== this.approved.length) { this.approved = live; this.persist(); }
    const a = [...live].reverse().find((x) => x.grant.agent_id === agentId && (!remoteUrl || x.grant.target.remote_url === remoteUrl));
    if (a) return { state: 'approved', id: a.grant.id, command: a.command, cwd: a.cwd };
    const q = [...this.pendingById.values()].reverse().find((r) => r.agent_id === agentId && (!remoteUrl || r.action.target.remote_url === remoteUrl));
    return q ? { state: 'pending', id: q.id, command: q.command, cwd: q.cwd } : null;
  }
}


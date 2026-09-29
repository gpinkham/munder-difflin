# Authority policy (opt-in)

A deterministic PreToolUse policy. It evaluates a few hand-written rules against a
hook payload and returns `allow` / `deny` / `ask` with a reason string the model
reads, so an agent self-corrects instead of retrying or working around a bare
refusal.

It exists for a specific failure: standing process rules ("an agent may only write
inside its own folder", "never run this destructive command") live as prose in
prompts and memory files, so they depend on salience. Under task pressure an agent
optimises for the immediate goal over a rule it is not actively holding. This moves
those rules from remembered to enforced.

**Nothing happens until you opt in.** With no `<hive>/policy/engine.json` (and no
`authority.json`), the engine loads nothing, evaluates nothing, logs nothing and
denies nothing.

**Two files, side by side.** `engine.json` is this engine's policy.
`authority.json` belongs to the older shell guardrail (`hive/bin/guardrail-hook.cjs`,
schema `match.kind`, `mode: "DRY_RUN"`) and is left exactly as it is. Before md-216
both readers shared `authority.json`, so the engine rejected every rule with
`unknown matcher "kind"` and enforced nothing. An `authority.json` in THIS schema is
still read when there is no `engine.json`. A hook-schema `authority.json` with no
`engine.json` now fails loudly: god gets a message at startup.

**Checking it loaded.** Every start logs `policy-status` with `rules_loaded` to
`log.jsonl` and prints `[policy] rules loaded: N` on stdout; `fleet.json` carries
the same thing under `policy` on every snapshot. `rules_loaded: 0` with an `error`
means nothing is enforced.

## What this is not

The hook transport is fail-open by construction. `hive/bin/cth-hook.cjs` exits 0 —
and no stdout means allow — when `HIVE_SOCK` is unset, on socket error, and on its
own 5-second timeout. **So this governs agents running under a live harness. It is a
salience aid for a cooperative agent, not a security boundary against a hostile
one.** No policy setting changes that, which is why it is written here rather than
papered over.

Making the shim fail-closed would wedge every agent whenever the harness restarts.
That trade is deliberately not taken.

## Install

```sh
mkdir -p <hive>/policy
cp examples/policy/engine.example.json <hive>/policy/engine.json
# then restart the harness — the policy is read once, at daemon start
```

The rules live in the hive directory, **outside this repo**, on purpose: they are
one operator's org-workflow rules, not a default anyone should inherit. The repo
ships an example and never an active policy.

## Reading the policy once, not watching it

The file is loaded at daemon start and **not** watched. A filesystem watcher would
turn "edit the file" into "disarm the guardrail" with no human in the loop. To
change a rule, edit the file and restart.

## dry_run → live

`mode` is per rule. Every rule should ship `dry_run`, where it is fully evaluated
and logged and the action **proceeds**.

Promote one rule at a time, and only after adjudicated evidence:

- the rule has fired, and
- every firing has been reviewed by a human, and
- none was a false positive, and
- roughly a week has passed.

A rule that has never fired is not evidence that it is well-targeted — it may
equally be dead. Label that case as weak and promote on firings you have actually
read.

## Measuring false positives

**A false positive cannot be computed automatically; it needs adjudication.** The
work is small because denies are rare.

Weekly, read the `policy-decision` rows in the harness log and mark each one
correct or not. Then report, per rule:

```
FP rate = false positives / total decisions for that rule
```

Secondary: decisions per 1,000 evaluated actions, as load. The `policy-stats` row
supplies that denominator.

**Never report block count as the headline.** "1,247 actions blocked" is the metric
of a feature about to be switched off. The number that decides whether a rule can
be trusted is its false-positive rate.

If agents begin working *around* denies, the load-bearing assumption — that these
rules are forgotten rather than resented — is falsified. The response is to remove
the rule, not to add more.

## The ledger

One row per deny or ask, including a dry-run would-deny. Never for an allow:
allows are the overwhelming majority and the log append is synchronous, so logging
them would put a disk write in front of every tool call of every agent.

```json
{ "kind": "policy-decision", "agent_id": "…", "rule_id": "cross-agent-write",
  "tool": "Write", "decision": "deny", "mode": "dry_run", "would_deny": true,
  "matched_on": "path_glob", "input_digest": "sha256:…" }
```

**Raw `tool_input` is never logged** — tool inputs carry file contents and
credentials. The row keeps a digest plus which matcher fired, which is enough to
correlate and to adjudicate.

`policy-loaded` is emitted at start with the rule list and the providers the engine
cannot enforce against, **named**. A generic "some providers may not be governed"
gets skimmed; a list does not.

## Self-protection

Three invariants live in `policy.ts`, ahead of user rules and not configurable —
an agent that can edit the policy file makes every rule advisory:

1. **Writes to the policy file and its directory are denied** whenever a policy
   file exists, even if it contains no rules. Reading it stays allowed, so an agent
   can look up the rule it just tripped.
2. **Loaded once, never watched** (above).
3. **A malformed policy loads nothing.** It logs `policy-load-failed` and runs with
   no policy rather than a half-parsed one — partial enforcement is worse than
   none, because it is believed. One invalid rule rejects the whole file for the
   same reason.

## Denying a pull-request merge (`bitbucket-merge`)

For a floor whose agents hold a token that can merge (the operator's own, say),
the forge cannot stop them, so the pack denies a Bitbucket merge by CLI (`bb`/`bkt
pr merge`), by REST (Cloud `…/pullrequests/<id>/merge`, Server/DC
`…/pull-requests/<id>/merge`) and by inline script. Two things to know:

- **It ships `dry_run`, which blocks nothing.** It logs `would_deny`. Where it is the
  only control, set its `mode` to `live`.
- **A merge can be disguised as a push.** `git push origin feature:main` puts the same
  commits on `main` and is only *asked* about by `remote-push`. Read that prompt as a
  possible merge. Branch permissions on the default branch remain the real control.
- **MCP tools** are seen by exact name only (the `tool` matcher). Add the server's
  merge tool names to a deny rule. A generic request tool (method + path) cannot be
  separated from a read by name.

Keep deny rules ahead of any `ask` rule: rules are first-match.

## Denying a push to a protected branch (`protected-branch-push`)

Not in the shipped pack, because the branch names are a floor's own: the rule is
[`protected-branch-push.rule.json`](protected-branch-push.rule.json), written for
`master` and `production-*`. Edit the two names for another floor, then paste the rule
into `engine.json` **ahead of `remote-push`**. It needs no engine change.

- **Denied:** a `git push`, `git subtree push` or `git send-pack` whose destination is
  protected: `origin master`, `HEAD:master`, `feat:refs/heads/production-x`, `+master`,
  `:master`, `--delete origin master`, and any of those forced. Also denied: `--all`,
  `--branches`, `--mirror` and wildcard refspecs, which reach every branch at once.
- **Allowed:** feature-branch pushes (forced or not), `--dry-run`/`-n`, a protected
  branch as the source only (`master:feat/x`), and `bb pr create` to a protected
  branch, which is how work should reach it.
- **Not covered:** a push that names no destination (`git push`, `git push origin`,
  `git push origin HEAD`) goes wherever the current branch says. From `master` it
  lands on `master` and is only asked about under `remote-push`. A destination set in
  git config, an alias and a script file are not seen either. Branch permissions on
  the server remain the real control where the agents' token allows them.

## Enforcement reach

A decision only takes effect if the harness bridge reads the response back. As
written:

| Bridge | Enforceable |
| --- | --- |
| Claude Code, Codex | yes — full payload, reads the response |
| Grok, agy, Gemini | `deny` yes; **`ask` is not translated and becomes allow** |
| pi, opencode | no — the bridge posts fire-and-forget |
| qwen (proxy) | no — it synthesizes PostToolUse after the fact, so there is no pre-action boundary |

Because of row two, an `ask` rule is **log-only** outside Claude Code and Codex. It
still records every attempt with rule, agent and timestamp, which is most of the
value; it does not stop anything there. Prefer `ask` for anything ambiguous anyway
— a false positive then costs one prompt instead of a blocked action.

## Report check (opt-in, off by default)

A rule sees one tool call before it runs. It cannot see an agent that reports
"done, suite green" after a red test run. The report check can: it records whether
each test run passed, and flags a delivered message that claims no failures when
the sender's last run failed.

It is **off unless the policy file turns it on**, with a top-level block beside
`rules`:

```json
{
  "version": 1,
  "rules": [ … ],
  "report_check": { "mode": "dry_run" }
}
```

- **Off** (no block, or no policy file): nothing of it runs. Agents' settings files
  gain no hook, nothing is recorded, no row is written, nobody is told.
- **`dry_run`**: writes `report-check-outcome` and `report-check-flag` rows to
  `log.jsonl`. Use it for a week and read every flag before going live.
- **`live`**: the same rows, and god gets a note on a contradiction, at most one per
  agent every 10 minutes (each flag row says whether it was `noted`). It **never
  blocks**: the message is always delivered.
- With no `mode`, it takes `defaults.mode`. A malformed block (`"LIVE"`, `true`)
  turns **only the check** off and logs `report-check-config-invalid`; the rules
  still load. An observer that fails to start must not take the guardrail with it.

What it keeps is deliberately thin:
- **Outcome row:** the runner (npm/yarn/pnpm/bun `test`, `node --test`, `pytest`
  including `uv run` / `poetry run`, `unittest`, `jest`, `vitest`, `playwright test`,
  `go test`, `cargo test`, `make test`, `mvn test`, `gradle test`), pass or fail, and
  one integer, the failure count from the runner's summary line (a log line such as
  "3 failed attempts" is not read as one). No output, no test names, and a digest of
  the command rather than the command itself.
- **Flag row:** the claim words that matched, not the message.

What counts as a claim: only a claim of **zero failures** ("suite green", "all tests
pass", "0 failures", "the suite passes"). "Done", "clean" and "no new failures" do
not count, so an honest report on a repo with known failing tests is not flagged.
Nor does a claim that is negated, conditional or required ("if all tests pass",
"once the suite is green", "we need tests passing"), a question, a quote, someone
else's words relayed ("Jim says all tests pass"), or talk of other failures ("no
fail-open rows", "no failed deliveries"). A claim with no recorded run is logged as
`unsupported` and never sent to god.

The window is the agent's last test run in its current session. A real start or
`/clear` resets it; a compaction or resume does not, since the red run before it is
still the state of things. The window is per agent, not per repo: a red run in one
repo followed by a green claim about another is flagged.

Changes take effect on restart, like the rules. Agents spawned before the restart
keep their old settings, so **respawn them** to pick up the failure hook: a failed
run arrives on `PostToolUseFailure`, which is registered only when this is on.

Known gaps: a run inside a subagent, a test script run from a file, and a runner not
in the list are not recorded. `|| true` hides a failure unless the summary line
shows a count.

## Approvals: one action at a time (opt-in, off by default)

An `ask` rule stops every push and keeps no memory of consent. In an agent's own
terminal that is a native prompt, and in an autonomous session nobody may be
watching it. Approvals turn "yes, push it" into a **grant for one exact action**:
this agent may push this commit to this branch of this remote, once, within the
hour.

It is **off unless a rule lists `grantable`**. It is valid only on an `ask` rule:

```json
{ "id": "remote-push", "decision": "ask", "grantable": ["git-push"], "match": { … }, "reason": "…" }
```

- **Off** (no rule with `grantable`): nothing of it runs. There is no prompt line
  for agents, no grants file, no Approvals section in ASK ME, and an
  `approval-request` message is routed like any other message.
- **On:**
  1. Agents are told to send `{"act":"approval-request","command":"git push <remote> <sha>:refs/heads/<branch>","cwd":"<dir>","reason":"…"}`
     before pushing.
  2. The app parses the request and shows it under **Approvals** in the ASK ME tab.
     It lists the branch, the full sha and the remote's resolved URL, then the
     agent's command and reason.
  3. **Approve** writes a grant to `policy/grants.jsonl`, and the agent is told to
     run exactly that command.
  4. The rule then allows that one push instead of asking.

What a grant covers, and nothing more:
- **Class:** `git-push`, and only `git [-C <dir>] push [-u] <remote> <40-char sha>:refs/heads/<branch>`
  as the whole Bash call, **starting with `git` itself**. Nothing may come in front:
  an environment assignment (`GIT_CONFIG_*=… git push`), `env`, `bash -c` or an
  absolute path can each change where the push goes without changing what the parser
  sees. Force, `--all`, `--tags`, `--delete`, several refspecs, `cd … && git push`,
  gh, curl and aliases can never be granted, and they keep asking.
- **Target:** the remote's **push** URL (`git remote get-url --push`, after `pushurl`
  and `pushInsteadOf`), resolved when the push runs, so re-pointing `origin` in any of
  those ways breaks the match. Also the ref, and the sha, which is written in the
  command, so a new commit needs a new approval. A repo whose config would publish
  more than that ref (`push.followTags`, `push.recurseSubmodules` other than `check`
  or `no`) cannot be granted at all.
- **Who:** the one agent that asked.
- **When:** 60 minutes from approval. After the first use, the identical push may be
  retried within 10 minutes (a network failure, say); after that the grant is spent.

Only the operator's **Approve** click mints a grant. An ASK ME text answer never
does, and neither can god or any agent: the answers live in `tasks.json`, which
agents can write. The grants file sits in this directory, which agents cannot
write.

In `dry_run` a matching grant is noted on the decision row (`grant_id`) but not
used, which measures how many real pushes would have had one. A live allow by a
grant writes a `policy-decision` row with `decision: "allow"` and the `grant_id`.

**Ship the engine before the pack.** An engine older than this feature rejects a rule
with `grantable`, and one rejected rule unloads the whole file.

**Keep deny rules ahead of a grantable ask.** Rules are first-match, so a grant on an
earlier ask rule returns allow before a later rule is looked at.

Known residuals: git configuration set outside the repo and the command (global
config, or a variable the agent's shell already exported) is not inspected, and
the push URL check runs `git remote get-url` from the app in a directory the agent
names (it runs no hooks or helpers).

## Why JSON and not YAML

JSON parses with no dependency. Adding a YAML parser would add a runtime dependency
to evaluate three rules, which works against the property that makes this feature
safe to merge: no new dependencies, and a complete no-op when unconfigured. If YAML
authoring is wanted later it belongs behind an optional dependency, or as an
offline `--draft` aid that emits JSON a human reviews and commits.

## Deliberately absent

No model call in the enforcement path, ever — it would add latency to every tool
call and make the decision nondeterministic. No English-to-rule compiler at
runtime. No expression language in the matchers: the moment rules need one, adopt
OPA/Rego instead of inventing a dialect here. No dashboard — the audit trail is a
byproduct, not a product.

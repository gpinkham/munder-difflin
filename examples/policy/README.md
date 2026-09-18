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

**Nothing happens until you opt in.** With no `<hive>/policy/authority.json`, the
engine loads nothing, evaluates nothing, logs nothing and denies nothing.

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
cp examples/policy/authority.example.json <hive>/policy/authority.json
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

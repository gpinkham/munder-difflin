# Guardrail

The guardrail keeps agents to the rules you set, even when they lose track of them.

## Rules: a principle, with an optional backstop

A **rule** is a guiding principle: a sentence every targeted agent is given in its
instructions ("Do not push without my approval"). Agents can forget a principle under
pressure, so a rule may also have a **backstop**: a check the hook runs before every
tool call, which stops the agent if it does the thing anyway.

| Backstop does | What happens |
|---|---|
| Block | The call is refused; the agent is told the rule's message. |
| Ask me | The call stops for you. With "approve on a card", an exact `git [-C <repo>] push <remote> <sha>:refs/heads/<branch>` instead goes to the Approvals card in ASK ME, and runs after you click Approve. |
| Log only | Nothing is stopped; the decision is recorded, to try a rule out. |

A rule applies to all agents or to named ones (its backstop too). A rule without a
backstop is shown as "Principle only, not enforced".

## Where rules live

One file, `<hive>/policy/guardrail.json`, edited in **Settings -> Rules**:
- add, edit, delete, turn a backstop on or off, and "Try it: would this stop a command?";
- each save is validated by the engine first, refused if the file changed on disk
  since the screen loaded it or if the file on disk is broken (repair it or restore a
  backup), refused if it adds principles over the cap (a save that does not make the
  cap worse, such as a delete, always goes through), written atomically with a timestamped backup
  (`guardrail.json.bak-<time>`, newest 20 kept), and takes effect at once;
- agents cannot write the policy folder (self-protection), and only the app window saves.

**Turn on guardrail** (Settings -> Rules) adds three starter rules: never merge a pull
request; never push to master or production-*; push only with approval. Running it
again adds only what is missing.

The status line at the top of Settings -> General and of the Rules screen says
"Guardrail active: N rules enforced", or in red why nothing is enforced.

## Approvals

- A push in the approvable form, with no approval, is refused at once and put on the
  Approvals card; the agent ends its turn and reruns the same command after Approve.
  The approved push is explicitly allowed (no prompt, whatever the permission mode).
- An agent's commands run in a sandbox whose network check is a prompt of its own, so
  the approved push runs outside the sandbox. What runs is rebuilt from the approval,
  `git -C <repo> push <approved url> <sha>:<ref>`, never the agent's text. Anything
  git runs for that push (the repo's pre-push hook, for one) runs outside it too.
  The push stays in the sandbox, and the network prompt can come back, when an
  insteadOf or pushInsteadOf rule matches the URL, a remote is named as the URL, or
  the repo cannot be placed.
- Pushed by URL, the push does not update the agent's remote-tracking ref (and drops
  `-u`): `git status` can look behind until the next `git fetch`.
- Every message names the push as one command with its repo, `git -C <repo> push …`,
  because an agent's shell is usually not in the repo. `cd <repo> && git push …`
  cannot be approved; when it is otherwise the approvable push it is refused with
  that `git -C` command, never asked (an ask is a terminal prompt, in
  bypassPermissions too). This comes first: an approval open for another repo
  never takes its place.
- Another form of the push to the same remote, while an approval is waiting or
  unused, is refused with the exact approved command. So is a push that cannot be
  placed at all (no repo where it runs, a compound command), for example an old
  `git push origin …` an agent copies from a resumed conversation into its inbox.
  A push placed at another remote asks as usual, and with no approval open nothing
  is refused.
- An agent without a valid hook token (not started by the running app) cannot use
  approvals, so its push under an approve-on-card rule is refused with "restart
  this agent" instead of asked.
- An approval works once (the identical retry within 10 minutes is allowed) and
  lasts 60 minutes. A request waiting longer expires. After Deny, the same push is
  refused for 10 minutes with no new card.
- Waiting requests and approvals survive an app restart (`policy/grant-desk.json`).
- The card warns when the push goes to a different URL than the remote fetches from.
- A temp waiting on a card is not shut down for being idle.
- If a waiting request expires, or approvals are turned off in the rules, the agent
  is told its request was dropped.
- After Deny, the hold covers that exact push (agent, remote, branch, commit); a
  different form of it asks in the terminal as usual.
- Known limit: a plain `git push` whose branch pushes to a remote other than
  `origin` (branch.<name>.pushRemote, remote.pushDefault) is matched against
  `origin`, so it can be refused with the exact command when it would have asked.

## Who may talk to the hook server

Each agent the app starts gets its own token (`HIVE_HOOK_TOKEN`, an HMAC of its id
under a secret made fresh each run). A hook payload that names an agent without its
token gets the policy decision only: rules still apply, but nothing happens in the
agent's name (no card, no approval used, no alert, no event, no decision row; the
refusal is logged as `hook-unauthenticated`). A subagent's hook call counts as its
hive agent's (the CLI's own id is kept as `subagent_id`). Limit: a same-user process
that reads an agent's environment can copy its token.

## Moving from engine.json / rules.json

The first start of this build moves `policy/engine.json` (backstops) and
`policy/rules.json` (principles) into `guardrail.json` and renames them
`*.migrated-<time>`. Descriptions and `_…_why` notes are carried. Nothing is dropped
silently: a rule the engine would refuse, a duplicate id, or a scope that is not all
agents or a list stops the move, the old files stay, and the error is shown. To go back to an older build, restore the renamed files to
their old names first: older builds read only `engine.json` and `rules.json`.
Changes made on the Rules screen after the move are not in the renamed files, and a
hive set up with "Turn on guardrail" has no old files at all: an older build then
enforces nothing.

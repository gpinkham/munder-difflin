/**
 * The starter rules "Turn on guardrail" installs (finish plan item 9): the three the
 * day job runs, as principles with backstops. Generated from the reviewed paste files
 * (for-gary/*-PASTE.json: bitbucket-merge, protected-branch-push, remote-push
 * LIVE-GRANTABLE); the patterns are copied, not rewritten. Blocks come first: the first
 * matching backstop wins, so a push to master is blocked, not asked.
 */
import type { GuardrailRule } from '../shared/guardrail';

export const STARTER_RULES: readonly GuardrailRule[] = [
  {
    "id": "bitbucket-merge",
    "principle": "Never merge a pull request. Leave it open, report its link, and say it is ready to merge.",
    "agents": "all",
    "backstop": {
      "on": true,
      "does": "block",
      "match": {
        "tool": "Bash",
        "command_matches": "^(?:(?:[Bb][Bb]|[Bb][Kk][Tt])(?:\\s+\\S+)*?\\s+pr\\s+(?:-\\S+(?:\\s+(?!pr(?:\\s|$))[^-\\s]\\S*)?\\s+)*merge(?:\\s|$)|(?=.*(?:pullrequests|pull-requests)/+[^/\\s'\"]+/+merge/?(?![\\w/-]))(?:curl\\b(?=.*(?:-X\\s*(?:[Pp][Oo][Ss][Tt])\\b|--request[\\s=]+(?:[Pp][Oo][Ss][Tt])\\b|\\s(?:-[A-Za-z]*[dF](?![A-Za-z])|--data\\S*|--json\\b|--form\\S*)))|(?:http|https|xh)\\b(?=.*(?:\\s(?:[Pp][Oo][Ss][Tt])\\s|\\s[\\w.-]+:?=))|wget\\b(?=.*(?:--method[\\s=]+(?:[Pp][Oo][Ss][Tt])\\b|--post-(?:data|file)\\b))|(?:python3?|node|ruby|perl)\\b(?=.*(?:(?:[Pp][Oo][Ss][Tt])|\\bdata\\s*=))))"
      },
      "message": "Merging a pull request is the operator's decision. Leave the PR open, report its link, and say it is ready to merge.",
      "on_error": "deny"
    }
  },
  {
    "id": "protected-branch-push",
    "principle": "Never push to master or production-*. Push a feature branch and open a PR instead.",
    "agents": "all",
    "backstop": {
      "on": true,
      "does": "block",
      "match": {
        "tool": "Bash",
        "command_matches": "^(?!(?!.*[ \\t](?:--no-dry-run(?:[ \\t]|$)|-[A-Za-z0-9]*o|--push-option))(?:.*[ \\t])?[^-\\s]\\S*[ \\t]+(?:--dry-run|-n)(?:[ \\t]|$))git(?:[ \\t]+-[Cc][ \\t]+\\S+|[ \\t]+--(?:git-dir|work-tree|namespace|exec-path|super-prefix|config-env)[ \\t]+\\S+|[ \\t]+-(?![Cc](?:\\s|$)|-(?:git-dir|work-tree|namespace|exec-path|super-prefix|config-env)(?:\\s|$))-?[^\\s-]\\S*)*[ \\t]+(?:push|subtree[ \\t]+push|send-pack)(?=\\s|$)(?:(?:[ \\t]+(?:[^\\s;&|<>()'\"`#]|'[^'\\n]*'|\"[^\"\\n]*\")+)*?[ \\t]+(?:--all|--branches|--mirror)|(?:[ \\t]+-(?:[^\\s;&|<>()'\"`#]|'[^'\\n]*'|\"[^\"\\n]*\")+?)*[ \\t]+(?![-])(?:(?:[^\\s;&|<>()'\"`#]|'[^'\\n]*'|\"[^\"\\n]*\")+)(?:[ \\t]+(?:[^\\s;&|<>()'\"`#]|'[^'\\n]*'|\"[^\"\\n]*\")+)*?[ \\t]+(?:\\+?(?:[^\\s:;&|<>()'\"`#]*:)?(?:refs/heads/|heads/)?(?:master|production-[^\\s:;&|<>()'\"`#]*|[^\\s:;&|<>()'\"`#]*\\*[^\\s:;&|<>()'\"`#]*)|\\+?[^\\s{]*\\{[^\\s}]*\\}[^\\s]*))(?=\\s|$)"
      },
      "message": "That push goes to a protected branch (master or production-*), which is the operator's call. Push a feature branch and open a PR with bb pr create instead, report the PR link, and say it is ready to merge.",
      "on_error": "deny"
    }
  },
  {
    "id": "remote-push",
    "principle": "Do not push, open a PR, publish, or write to GitHub without my approval.",
    "agents": "all",
    "backstop": {
      "on": true,
      "does": "ask",
      "approve_on_card": [
        "git-push"
      ],
      "match": {
        "tool": "Bash",
        "command_matches": "^(?!(?!.*\\s(?:--no-dry-run(?:\\s|$)|-[A-Za-z0-9]*o|--push-option))(?:.*\\s)?[^-\\s]\\S*\\s+--dry-run(?:\\s|$))(?:git(?:\\s+-[Cc]\\s+\\S+|\\s+--(?:git-dir|work-tree|namespace|exec-path|super-prefix|config-env)\\s+\\S+|\\s+-(?![Cc](?:\\s|$)|-(?:git-dir|work-tree|namespace|exec-path|super-prefix|config-env)(?:\\s|$))-?[^\\s-]\\S*)*\\s+(?:push|p|subtree\\s+push)\\b|git\\s+subtree\\s+push\\b|hub\\s+push\\b|gh\\s+(?:pr\\s+create|release\\s+create|repo\\s+sync)\\b|(?:npm|yarn|pnpm)\\s+publish\\b|curl\\b(?=.*-X\\s+(?:POST|PATCH|PUT|DELETE))(?=.*api\\.github\\.com)|gh\\s+(?:pr\\s+merge|repo\\s+create\\b(?=.*\\s--push\\b)|api\\b(?=.*(?:-X|--method)[\\s=]*(?:POST|PATCH|PUT|DELETE)\\b))\\b|git\\s+send-pack\\b|git(?:\\s+-[Cc]\\s+\\S+)*\\s+-c\\s+alias\\.\\S+=push\\b|curl\\b(?=.*--request\\s+(?:POST|PATCH|PUT|DELETE))(?=.*api\\.github\\.com)|gh\\s+api\\b(?=.*(?:-X|--method)[\\s=]*(?:[Pp][Oo][Ss][Tt]|[Pp][Aa][Tt][Cc][Hh]|[Pp][Uu][Tt]|[Dd][Ee][Ll][Ee][Tt][Ee])\\b)|gh\\s+api\\b(?!\\s+graphql\\b)(?=.*\\s(?:-[fF]|--field\\b|--raw-field\\b|--input\\b))(?!.*(?:-X|--method)[\\s=]*[Gg][Ee][Tt]\\b)|gh\\s+api\\s+graphql\\b(?=.*\\bmutation\\b)|curl\\b(?=.*(?:api|uploads)\\.github\\.com)(?=.*(?:-X\\s*(?:[Pp][Oo][Ss][Tt]|[Pp][Aa][Tt][Cc][Hh]|[Pp][Uu][Tt]|[Dd][Ee][Ll][Ee][Tt][Ee])\\b|--request[\\s=]+(?:[Pp][Oo][Ss][Tt]|[Pp][Aa][Tt][Cc][Hh]|[Pp][Uu][Tt]|[Dd][Ee][Ll][Ee][Tt][Ee])\\b|\\s(?:-[dFT]|--data\\S*|--json\\b|--form\\S*|--upload-file\\b))))"
      },
      "message": "Publishing work outside this machine - a push, a PR, a release, an npm publish, a write to the GitHub API - is the operator's decision. Commit to a branch, report the branch name, and ask first.",
      "on_error": "allow"
    }
  }
];

/**
 * Is an interactive menu open in this agent's terminal right now?
 *
 * Every automated write into an agent PTY (the inbox-wake nudge, the renderer's
 * queue, a seed prompt) ends in Enter. While Claude Code shows a menu — a permission
 * prompt, an AskUserQuestion, a plan approval, an MCP form — Enter chooses the
 * highlighted option, which is "Yes" or the first answer. So a nudge that arrives
 * while a menu is up answers a question nobody read: it ran a push a policy rule had
 * asked about, picked a database, approved a plan. Reproduced on Claude Code 2.1.287.
 *
 * This is the one place that knows. It is fed every hook event and holds an agent
 * from the moment a menu opens until that menu is answered, with no time limit:
 *
 *  - opens: PreToolUse of a tool that always waits for the user (AskUserQuestion,
 *    ExitPlanMode); PermissionRequest (fires the moment a permission prompt shows);
 *    a dialog Notification (permission_prompt, elicitation_*_dialog, which Claude
 *    Code only sends after ~6 s, so it is the fallback, not the signal); Elicitation.
 *  - closes: the answered call's own PostToolUse / PostToolUseFailure /
 *    PermissionDenied (by tool_use_id, so a PARALLEL tool finishing does not close
 *    another call's prompt); ElicitationResult; and anything that cannot happen
 *    while a menu blocks the turn — UserPromptSubmit, Stop, StopFailure, SessionStart.
 *  - Esc closes a menu with NO hook at all. `holdState` overrules the hook state
 *    when the screen shows the input box again and the terminal has gone quiet.
 *
 * The hive registers PreToolUse, PostToolUse, PermissionRequest, Elicitation,
 * ElicitationResult, Notification, UserPromptSubmit, Stop and SessionStart for
 * every agent; PostToolUseFailure only with the report check. PermissionDenied and
 * StopFailure are handled when a settings file sends them.
 *
 * `screenShowsMenu` is the backstop for a menu whose hook never arrived: it reads the
 * PTY's output tail and asks whether the last thing drawn was a menu footer or the
 * ordinary input box.
 */

/** Tools whose PreToolUse means a menu is about to wait for the user. */
const MENU_TOOLS = new Set(['AskUserQuestion', 'ExitPlanMode']);
/** Notification types that mean a dialog is waiting for the user. */
const DIALOG_NOTIFICATIONS = new Set(['permission_prompt', 'elicitation_dialog', 'elicitation_url_dialog', 'agent_needs_input']);
/** A call's own outcome: its prompt (if any) was answered. */
const CALL_SETTLED = new Set(['PostToolUse', 'PostToolUseFailure', 'PermissionDenied']);
/** Events that cannot happen while a menu blocks the turn, so every menu is gone. */
const ALL_SETTLED = new Set(['UserPromptSubmit', 'Stop', 'StopFailure', 'SessionStart']);
const ELICIT = 'elicitation';

export interface PromptHookPayload {
  hook_event_name?: string;
  tool_name?: string;
  tool_use_id?: string;
  notification_type?: string;
  message?: string;
}

interface AgentPrompts {
  /** Open menus. Key: the tool_use_id it belongs to, `tool:<name>` when the event
   *  carried no id, `dialog:<id>` for a notification-only prompt, or ELICIT. */
  open: Set<string>;
  /** tool name → its most recent PreToolUse id, to pin a PermissionRequest (which
   *  carries no tool_use_id) to the call it is about. */
  lastCall: Map<string, string>;
  /** The most recent PreToolUse id of any tool. */
  lastId?: string;
}

export class PromptGate {
  private agents = new Map<string, AgentPrompts>();

  private state(agentId: string): AgentPrompts {
    let s = this.agents.get(agentId);
    if (!s) { s = { open: new Set(), lastCall: new Map() }; this.agents.set(agentId, s); }
    return s;
  }

  /** Feed one hook event. Never throws: a malformed payload changes nothing. */
  noteHook(agentId: string | undefined | null, p: PromptHookPayload | undefined | null): void {
    if (!agentId || !p) return;
    const event = p.hook_event_name;
    const tool = typeof p.tool_name === 'string' ? p.tool_name : '';
    const id = typeof p.tool_use_id === 'string' && p.tool_use_id ? p.tool_use_id : '';
    if (!event) return;
    if (ALL_SETTLED.has(event)) { this.agents.delete(agentId); return; }
    const s = this.state(agentId);
    switch (event) {
      case 'PreToolUse':
        if (id) { s.lastCall.set(tool, id); s.lastId = id; }
        if (MENU_TOOLS.has(tool)) s.open.add(id || `tool:${tool}`);
        break;
      case 'PermissionRequest':
        s.open.add(s.lastCall.get(tool) ?? `tool:${tool}`);
        break;
      case 'Notification':
        if (p.notification_type === 'elicitation_complete' || p.notification_type === 'elicitation_response') {
          s.open.delete(ELICIT);
        } else if (p.notification_type && DIALOG_NOTIFICATIONS.has(p.notification_type) && s.open.size === 0) {
          // Only when no hook already pinned the menu: this is the fallback for a
          // prompt whose PermissionRequest was not delivered (an older settings file).
          s.open.add(p.notification_type.startsWith('elicitation') ? ELICIT : `dialog:${s.lastId ?? ''}`);
        }
        break;
      case 'Elicitation':
        s.open.add(ELICIT);
        break;
      case 'ElicitationResult':
        s.open.delete(ELICIT);
        break;
      default:
        if (CALL_SETTLED.has(event)) {
          if (id) { s.open.delete(id); s.open.delete(`dialog:${id}`); }
          s.open.delete(`tool:${tool}`);
          if (id && s.lastCall.get(tool) === id) s.lastCall.delete(tool);
        }
    }
  }

  /** True while any menu is open in this agent's terminal. */
  isOpen(agentId: string | undefined | null): boolean {
    return !!agentId && (this.agents.get(agentId)?.open.size ?? 0) > 0;
  }

  /** Forget an agent (its PTY exited or was replaced). */
  forget(agentId: string): void {
    this.agents.delete(agentId);
  }
}

/** Footers Claude Code draws under a menu, whitespace removed (the TUI positions
 *  words with cursor moves, so spaces do not survive in the byte stream). */
const MENU_FOOTERS = ['Entertoselect', 'Entertoconfirm', 'Esctocancel', 'Tabtoamend', 'Doyouwanttoproceed', 'Wouldyouliketoproceed'];
/** What it draws for the ordinary input box (or while working), in every mode. */
const INPUT_FOOTERS = ['shift+tabtocycle', '?forshortcuts', 'esctointerrupt'];

/**
 * Does this PTY output tail end on a menu? True when it is a Claude Code screen (an
 * input-box footer appears in it) and a menu footer was drawn after the last one. A false positive only delays a nudge; a false negative
 * is what the hook state above is for.
 */
export function screenShowsMenu(tail: string | undefined | null): boolean {
  const { menu, input } = footers(tail);
  // No input-box footer at all: not a Claude Code screen (or not yet drawn), and
  // another CLI's idle screen would never clear the menu again. Leave it to hooks.
  return input >= 0 && menu > input;
}

/** Positions of the last menu footer and the last input-box footer in a tail. */
function footers(tail: string | undefined | null): { menu: number; input: number } {
  if (!tail) return { menu: -1, input: -1 };
  const text = tail
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '')
    .replace(/\x1b\[[0-9;?<>=]*[ -/]*[@-~]/g, '')
    .replace(/\x1b[@-_]/g, '')
    .replace(/\s+/g, '');
  const last = (marks: string[]) => Math.max(...marks.map((m) => text.lastIndexOf(m)));
  return { menu: last(MENU_FOOTERS), input: last(INPUT_FOOTERS) };
}

/** How long the terminal must be silent, on the input box, before hook state that
 *  still says "menu open" is overruled. Claude Code redraws while it works (the
 *  spinner), so ten quiet seconds on the input box means the turn has ended. */
export const DISMISS_QUIET_MS = 10_000;

/**
 * Hold, release, or overrule. Esc at a permission prompt or at an AskUserQuestion
 * fires NO hook and no Stop (live, 2.1.287), so hook state alone would hold the
 * agent forever: no nudge, no queued message, ever. The screen settles it.
 *
 *  - hooks say open: 'held', unless the screen ends on the input box and the
 *    terminal has been quiet for DISMISS_QUIET_MS: then 'dismissed' (the menu went
 *    away without an answer the hooks could see; the caller forgets it).
 *  - hooks say nothing: 'held' if the screen ends on a menu, else 'free'.
 */
export function holdState(hooksOpen: boolean, tail: string | undefined | null, idleMs: number): 'held' | 'dismissed' | 'free' {
  if (hooksOpen) {
    const { menu, input } = footers(tail);
    return input >= 0 && input > menu && idleMs >= DISMISS_QUIET_MS ? 'dismissed' : 'held';
  }
  return screenShowsMenu(tail) ? 'held' : 'free';
}

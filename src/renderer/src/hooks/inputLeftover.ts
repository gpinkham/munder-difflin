import { PendingSubmit } from '../../../shared/pendingSubmit';

/**
 * Text automation typed into an agent's input box whose Enter main withheld at a
 * menu (see submitToPty). One record for the whole renderer, because the events
 * that make it stale happen elsewhere: the user submitting the box (a
 * UserPromptSubmit hook), typing or clearing in the terminal, or the terminal
 * exiting. A stale record would make a retry send only Enter into an empty box
 * and acknowledge a message that was never delivered.
 */
export const inputLeftover = new PendingSubmit();

/** Replies the terminal sends on its own, not keys the user pressed: status and
 *  cursor reports and device attributes (CSI … n / R / c), focus in/out (CSI I /
 *  CSI O), OSC replies (colours) and DCS replies (version). Everything else,
 *  ESC-led editing keys included (Option+Backspace, forward Delete, arrows), is
 *  the user touching the input box. */
const TERMINAL_REPLY = /^(?:\x1b\[[?>=]?[\d;]*[nRc]|\x1b\[[IO]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1bP[^\x1b]*\x1b\\)$/;

export function isTerminalReply(data: string): boolean {
  return TERMINAL_REPLY.test(data);
}

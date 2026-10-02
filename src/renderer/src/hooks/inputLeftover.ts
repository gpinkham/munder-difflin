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

/**
 * Text typed into a terminal whose Enter was withheld.
 *
 * Automation types a line, then presses Enter 140 ms later. If a menu opens in
 * between, the Enter is withheld (it would answer the menu), and the text stays in
 * the input box. Typing it again on the retry would submit two copies. This
 * remembers what was left, per terminal, so the retry sends only the Enter.
 */
export class PendingSubmit {
  private left = new Map<string, string>();

  /** Should `text` be typed before the Enter? Not when it is already in the box.
   *  `interchangeable`: any leftover serves (two inbox nudges say the same thing). */
  typeText(ptyId: string, text: string, interchangeable = false): boolean {
    const left = this.left.get(ptyId);
    if (left === undefined) return true;
    return !(left === text || interchangeable);
  }

  /** The text went in but its Enter was withheld. */
  withheld(ptyId: string, text: string): void {
    this.left.set(ptyId, text);
  }

  /** Enter went in (by automation or by the user): the box is empty. */
  submitted(ptyId: string): void {
    this.left.delete(ptyId);
  }

  /** The terminal went away. */
  forget(ptyId: string): void {
    this.left.delete(ptyId);
  }
}

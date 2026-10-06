/**
 * Who may talk to the hook server as an agent (finish plan item 5).
 *
 * Each agent the app starts gets HIVE_HOOK_TOKEN = HMAC-SHA256(secret, agent id),
 * and every hook shim sends it back. The secret is made fresh for each app run and
 * never written anywhere, so a token from an earlier run, or one guessed for another
 * agent, does not verify. A payload that names an agent without its token gets the
 * policy decision and nothing else (HookServer.handle).
 *
 * Limit: a same-user process that can read an agent's environment (ps eww) can copy
 * that agent's token. This stops blind forgery, not a process with that access.
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export class HookAuth {
  private secret = randomBytes(32);

  token(agentId: string): string {
    return createHmac('sha256', this.secret).update(agentId).digest('hex');
  }

  verify(agentId: string, token: unknown): boolean {
    if (typeof token !== 'string' || !token) return false;
    const want = Buffer.from(this.token(agentId));
    const got = Buffer.from(token);
    return got.length === want.length && timingSafeEqual(got, want);
  }
}

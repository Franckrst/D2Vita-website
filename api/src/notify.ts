// Optional Telegram notifications (spec section 5.7): only when both
// TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are set. Failures are swallowed:
// a notification must never affect the request that triggered it.

import type { Env } from "./env";

export async function notify(
  env: Pick<Env, "TELEGRAM_BOT_TOKEN" | "TELEGRAM_CHAT_ID">,
  text: string,
): Promise<boolean> {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return false;
  try {
    const res = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text, disable_web_page_preview: true }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

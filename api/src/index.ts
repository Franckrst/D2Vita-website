import { runCron } from "./cron";
import type { Env } from "./env";
import { handle } from "./router";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handle(request, env, ctx, Math.floor(Date.now() / 1000));
  },

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      runCron(env, Math.floor(controller.scheduledTime / 1000)).then((summary) => {
        console.log("retention:", JSON.stringify(summary));
      }),
    );
  },
} satisfies ExportedHandler<Env>;
